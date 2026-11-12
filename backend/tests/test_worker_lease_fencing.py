import time
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.delivery import Delivery, DeliveryStatus
from app.models.delivery_attempt import DeliveryAttempt, AttemptStatus
from app.models.endpoint import Endpoint
from app.models.event import Event
from app.models.outbox import OutboxEvent, OutboxStatus
from app.services.delivery_service import DeliveryService, DeliveryRetryError
from app.services.webhook_client import WebhookExecutionResult, HTTPOutcome

TEST_POSTGRES_URL = "postgresql+psycopg://postgres:postgres@postgres:5432/eventflow_test"


@pytest.fixture(scope="module")
def pg_engine():
    try:
        engine = create_engine(TEST_POSTGRES_URL, pool_pre_ping=True)
        with engine.connect() as conn:
            pass
        return engine
    except Exception as e:
        pytest.skip(f"PostgreSQL test database not available: {e}")


@pytest.fixture
def pg_session(pg_engine):
    Session = sessionmaker(bind=pg_engine, autocommit=False, autoflush=False)
    session = Session()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def create_test_delivery(session, max_attempts=5, status=DeliveryStatus.PENDING):
    ep = Endpoint(
        url="https://consumer.example.com/webhook",
        secret="whsec_pg_test_secret_12345",
        is_active=True,
        event_types=["*"],
    )
    ev = Event(
        event_type="order.created",
        payload={"order_id": str(uuid.uuid4())},
    )
    session.add_all([ep, ev])
    session.commit()

    deliv = Delivery(
        event_id=ev.id,
        endpoint_id=ep.id,
        status=status,
        max_attempts=max_attempts,
    )
    session.add(deliv)
    session.commit()
    return deliv


def test_preflight_attempt_commit(pg_engine):
    """Verify that DeliveryAttempt(status=STARTED) is committed to DB before HTTP completes."""
    Session = sessionmaker(bind=pg_engine)
    session1 = Session()
    session2 = Session()

    try:
        deliv = create_test_delivery(session1)
        deliv_id = deliv.id
        session1.close()

        inspected_started_attempt = None

        def mock_http_side_effect(*args, **kwargs):
            nonlocal inspected_started_attempt
            # Inspect the DB using a completely separate session while HTTP request is in-flight
            check_session = Session()
            try:
                d = check_session.query(Delivery).filter(Delivery.id == deliv_id).first()
                assert d.status == DeliveryStatus.PROCESSING
                assert d.lease_token is not None

                attempts = (
                    check_session.query(DeliveryAttempt)
                    .filter(DeliveryAttempt.delivery_id == deliv_id)
                    .all()
                )
                assert len(attempts) == 1
                assert attempts[0].status == AttemptStatus.STARTED
                assert attempts[0].attempt_number == 1
                inspected_started_attempt = attempts[0].status
            finally:
                check_session.close()

            return WebhookExecutionResult(
                success=True,
                http_status=200,
                response_time_ms=50,
                request_headers={"x-eventflow-signature": "sig"},
                response_headers={},
                response_body="OK",
                outcome=HTTPOutcome.SUCCESS,
            )

        with patch("app.services.delivery_service.execute_webhook_request", side_effect=mock_http_side_effect):
            worker_session = Session()
            final_deliv = DeliveryService.execute_delivery(worker_session, deliv_id)
            worker_session.close()

        assert inspected_started_attempt == AttemptStatus.STARTED
        assert final_deliv.status == DeliveryStatus.SUCCESS
        assert final_deliv.lease_token is None

    finally:
        session1.close()
        session2.close()


def test_premature_retry_prevention(pg_session):
    """Verify worker refuses to execute delivery if next_retry_at is in the future."""
    deliv = create_test_delivery(pg_session, status=DeliveryStatus.RETRYING)
    now = datetime.now(timezone.utc)
    deliv.next_retry_at = now + timedelta(seconds=60)
    pg_session.commit()

    # Attempt to execute
    result = DeliveryService.execute_delivery(pg_session, deliv.id)
    assert result.status == DeliveryStatus.RETRYING

    # Verify no attempts were created
    attempts = pg_session.query(DeliveryAttempt).filter(DeliveryAttempt.delivery_id == deliv.id).all()
    assert len(attempts) == 0


def test_crash_recovery_reaper_reconciles_started_to_unknown(pg_session):
    """Verify crash reaper recovers stuck deliveries and transitions STARTED attempts to UNKNOWN."""
    deliv = create_test_delivery(pg_session, status=DeliveryStatus.PROCESSING)
    now = datetime.now(timezone.utc)

    # Simulate expired lease from a crashed worker
    deliv.lease_token = str(uuid.uuid4())
    deliv.lease_expires_at = now - timedelta(seconds=10)
    deliv.attempt_count = 1

    # Orphaned in-flight attempt left by crashed worker
    attempt = DeliveryAttempt(
        delivery_id=deliv.id,
        attempt_number=1,
        status=AttemptStatus.STARTED,
        executed_at=now - timedelta(seconds=30),
    )
    pg_session.add(attempt)
    pg_session.commit()

    # Run Crash Recovery Reaper
    reaped = DeliveryService.reap_stuck_deliveries(pg_session)
    assert reaped >= 1

    pg_session.refresh(deliv)
    pg_session.refresh(attempt)

    # 1. Attempt reconciled to UNKNOWN with audit note
    assert attempt.status == AttemptStatus.UNKNOWN
    assert "[CRASH REAPER]" in attempt.error_message

    # 2. Delivery transitioned to RETRYING and lease cleared
    assert deliv.status == DeliveryStatus.RETRYING
    assert deliv.lease_token is None
    assert deliv.lease_expires_at is None
    assert deliv.next_retry_at is not None

    # 3. Scheduled outbox event created
    outbox = (
        pg_session.query(OutboxEvent)
        .filter(OutboxEvent.delivery_id == deliv.id, OutboxEvent.status == OutboxStatus.PENDING)
        .first()
    )
    assert outbox is not None
    assert outbox.scheduled_for == deliv.next_retry_at


def test_crash_recovery_reaper_exhausted_to_dead_letter(pg_session):
    """Verify crash reaper moves stuck delivery to DEAD_LETTER when max attempts reached."""
    deliv = create_test_delivery(pg_session, max_attempts=3, status=DeliveryStatus.PROCESSING)
    now = datetime.now(timezone.utc)

    # Delivery was on its 3rd and final attempt
    deliv.lease_token = str(uuid.uuid4())
    deliv.lease_expires_at = now - timedelta(seconds=5)
    deliv.attempt_count = 3

    attempt = DeliveryAttempt(
        delivery_id=deliv.id,
        attempt_number=3,
        status=AttemptStatus.STARTED,
        executed_at=now - timedelta(seconds=20),
    )
    pg_session.add(attempt)
    pg_session.commit()

    reaped = DeliveryService.reap_stuck_deliveries(pg_session)
    assert reaped >= 1

    pg_session.refresh(deliv)
    pg_session.refresh(attempt)

    assert attempt.status == AttemptStatus.UNKNOWN
    assert deliv.status == DeliveryStatus.DEAD_LETTER
    assert deliv.next_retry_at is None
    assert deliv.lease_token is None


def test_stale_worker_late_completion_fencing(pg_engine):
    """
    Test stale worker late completion:
    - Worker A's lease expires while waiting for slow HTTP response.
    - Reaper runs and transitions attempt #1 to UNKNOWN.
    - Worker B claims delivery and executes attempt #2.
    - Worker A eventually gets HTTP 200 OK.
    - Worker A fencing check fails: deliveries table is NOT modified!
    - Worker A's own attempt #1 transitions UNKNOWN -> SUCCESS with stale worker audit note.
    - Worker B finishes normally.
    """
    Session = sessionmaker(bind=pg_engine)
    session_setup = Session()
    deliv = create_test_delivery(session_setup)
    deliv_id = deliv.id
    session_setup.close()

    now = datetime.now(timezone.utc)

    # 1. Simulate Worker A claiming the delivery
    session_a = Session()
    d_a = session_a.query(Delivery).filter(Delivery.id == deliv_id).first()
    token_a = "token-worker-a-111"
    d_a.status = DeliveryStatus.PROCESSING
    d_a.lease_token = token_a
    d_a.lease_expires_at = now - timedelta(seconds=5)  # Lease expired!
    d_a.attempt_count = 1

    attempt_a = DeliveryAttempt(
        delivery_id=deliv_id,
        attempt_number=1,
        status=AttemptStatus.STARTED,
        executed_at=now - timedelta(seconds=35),
    )
    session_a.add(attempt_a)
    session_a.commit()
    attempt_a_id = attempt_a.id
    session_a.close()

    # 2. Crash Reaper runs
    session_reaper = Session()
    reaped = DeliveryService.reap_stuck_deliveries(session_reaper)
    assert reaped >= 1
    session_reaper.close()

    # Verify attempt #1 is now UNKNOWN and delivery is RETRYING
    session_check = Session()
    d_reaped = session_check.query(Delivery).filter(Delivery.id == deliv_id).first()
    assert d_reaped.status == DeliveryStatus.RETRYING
    att_1 = session_check.query(DeliveryAttempt).filter(DeliveryAttempt.id == attempt_a_id).first()
    assert att_1.status == AttemptStatus.UNKNOWN
    session_check.close()

    # 3. Worker B claims delivery
    session_b = Session()
    d_b = session_b.query(Delivery).filter(Delivery.id == deliv_id).first()
    d_b.next_retry_at = None  # due for execution
    token_b = "token-worker-b-222"
    d_b.status = DeliveryStatus.PROCESSING
    d_b.lease_token = token_b
    d_b.lease_expires_at = now + timedelta(seconds=30)
    d_b.attempt_count = 2

    attempt_b = DeliveryAttempt(
        delivery_id=deliv_id,
        attempt_number=2,
        status=AttemptStatus.STARTED,
        executed_at=now,
    )
    session_b.add(attempt_b)
    session_b.commit()
    session_b.close()

    # 4. Worker A finally gets HTTP 200 OK response!
    # Simulate Worker A running Step 4 finalization with token_a
    session_late_a = Session()
    mock_result_a = WebhookExecutionResult(
        success=True,
        http_status=200,
        response_time_ms=12000,
        request_headers={"x-eventflow-signature": "sig-a"},
        response_headers={},
        response_body="Late 200 OK",
        outcome=HTTPOutcome.SUCCESS,
    )

    # Execute finalization logic directly as Worker A
    now_post = datetime.now(timezone.utc)
    cas_query = (
        session_late_a.query(Delivery)
        .filter(
            Delivery.id == deliv_id,
            Delivery.lease_token == token_a,
            Delivery.lease_expires_at > now_post,
        )
    )
    current_delivery = cas_query.first()

    # CAS MUST FAIL!
    assert current_delivery is None

    # Stale Worker reconciliation
    my_attempt = (
        session_late_a.query(DeliveryAttempt)
        .filter(
            DeliveryAttempt.id == attempt_a_id,
            DeliveryAttempt.status.in_([AttemptStatus.STARTED, AttemptStatus.UNKNOWN]),
        )
        .first()
    )
    assert my_attempt is not None
    my_attempt.status = AttemptStatus.SUCCESS
    my_attempt.http_status = 200
    my_attempt.error_message = (
        f"[STALE WORKER RECONCILIATION] Completed with HTTP 200 after lease expired. "
        f"Delivery state was not modified. Worker token was {token_a}."
    )
    session_late_a.commit()
    session_late_a.close()

    # 5. Verify Invariants:
    session_verify = Session()
    final_d = session_verify.query(Delivery).filter(Delivery.id == deliv_id).first()

    # Invariant 1: deliveries table was NOT modified by Worker A (still owned by Worker B)
    assert final_d.status == DeliveryStatus.PROCESSING
    assert final_d.lease_token == token_b
    assert final_d.attempt_count == 2

    # Invariant 2: Worker A's attempt #1 was reconciled UNKNOWN -> SUCCESS with audit note
    reconciled_att = session_verify.query(DeliveryAttempt).filter(DeliveryAttempt.id == attempt_a_id).first()
    assert reconciled_att.status == AttemptStatus.SUCCESS
    assert reconciled_att.http_status == 200
    assert "[STALE WORKER RECONCILIATION]" in reconciled_att.error_message

    # Invariant 3: Worker B's attempt #2 is still in progress
    att_2 = (
        session_verify.query(DeliveryAttempt)
        .filter(DeliveryAttempt.delivery_id == deliv_id, DeliveryAttempt.attempt_number == 2)
        .first()
    )
    assert att_2.status == AttemptStatus.STARTED

    session_verify.close()


def test_lease_renewal_heartbeat(pg_session):
    """Verify lease renewal extends lease while active, fails if expired or mismatched."""
    deliv = create_test_delivery(pg_session, status=DeliveryStatus.PROCESSING)
    now = datetime.now(timezone.utc)
    token = "lease-token-heartbeat"

    deliv.lease_token = token
    deliv.lease_expires_at = now + timedelta(seconds=30)
    pg_session.commit()

    # 1. Successful renewal
    renewed = DeliveryService.renew_lease(pg_session, deliv.id, token, extension_seconds=60)
    assert renewed is True
    pg_session.refresh(deliv)
    assert deliv.lease_expires_at > now + timedelta(seconds=45)

    # 2. Failed renewal with wrong token
    bad_renew = DeliveryService.renew_lease(pg_session, deliv.id, "wrong-token", extension_seconds=60)
    assert bad_renew is False

    # 3. Failed renewal if already expired
    deliv.lease_expires_at = now - timedelta(seconds=1)
    pg_session.commit()
    expired_renew = DeliveryService.renew_lease(pg_session, deliv.id, token, extension_seconds=60)
    assert expired_renew is False


def test_manual_retry_resets_cycle_and_preserves_history(pg_session):
    """Verify manual retry resets attempt_count=0, creates OutboxEvent, and generates next attempt_number."""
    deliv = create_test_delivery(pg_session, max_attempts=3, status=DeliveryStatus.DEAD_LETTER)
    deliv.attempt_count = 3
    now = datetime.now(timezone.utc)

    # 3 historical failed attempts in cycle 1
    for i in range(1, 4):
        att = DeliveryAttempt(
            delivery_id=deliv.id,
            attempt_number=i,
            status=AttemptStatus.FAILED,
            http_status=500,
            executed_at=now - timedelta(minutes=10 - i),
        )
        pg_session.add(att)
    pg_session.commit()

    # Trigger manual retry
    retried_deliv = DeliveryService.retry_manually(pg_session, deliv.id)

    # 1. Active cycle attempt_count is reset to 0
    assert retried_deliv.status == DeliveryStatus.PENDING
    assert retried_deliv.attempt_count == 0
    assert retried_deliv.next_retry_at is None
    assert retried_deliv.last_error is None

    # 2. OutboxEvent created in same transaction
    outbox = (
        pg_session.query(OutboxEvent)
        .filter(OutboxEvent.delivery_id == deliv.id, OutboxEvent.status == OutboxStatus.PENDING)
        .first()
    )
    assert outbox is not None
    assert outbox.scheduled_for is None

    # 3. All 3 historical attempts preserved
    attempts = (
        pg_session.query(DeliveryAttempt)
        .filter(DeliveryAttempt.delivery_id == deliv.id)
        .order_by(DeliveryAttempt.attempt_number.asc())
        .all()
    )
    assert len(attempts) == 3
    assert [a.attempt_number for a in attempts] == [1, 2, 3]

    # 4. Subsequent execution receives attempt_number = 4 and attempt_count = 1
    mock_success = WebhookExecutionResult(
        success=True,
        http_status=200,
        response_time_ms=40,
        request_headers={"x-eventflow-signature": "sig"},
        response_headers={},
        response_body="Success",
        outcome=HTTPOutcome.SUCCESS,
    )
    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_success):
        executed_deliv = DeliveryService.execute_delivery(pg_session, deliv.id)

    assert executed_deliv.status == DeliveryStatus.SUCCESS
    assert executed_deliv.attempt_count == 1  # 1st attempt in cycle 2

    # Verify attempt_number was globally sequential (4)
    all_attempts = (
        pg_session.query(DeliveryAttempt)
        .filter(DeliveryAttempt.delivery_id == deliv.id)
        .order_by(DeliveryAttempt.attempt_number.asc())
        .all()
    )
    assert len(all_attempts) == 4
    assert [a.attempt_number for a in all_attempts] == [1, 2, 3, 4]
    assert all_attempts[-1].status == AttemptStatus.SUCCESS
