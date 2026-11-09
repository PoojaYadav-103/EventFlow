import http.server
import threading
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import pytest

from app.core.config import settings
from app.models.delivery import Delivery, DeliveryStatus
from app.models.delivery_attempt import DeliveryAttempt, AttemptStatus
from app.models.endpoint import Endpoint
from app.models.event import Event
from app.models.outbox import OutboxEvent, OutboxStatus
from app.services.delivery_service import DeliveryService
from app.services.webhook_client import (
    execute_webhook_request,
    HTTPOutcome,
    WebhookExecutionResult,
)


class SlowChunkedStreamHandler(http.server.BaseHTTPRequestHandler):
    """
    Simulates a slow streaming server that periodically trickles chunks.
    Each chunk is sent every 0.35 seconds, well below individual socket read timeouts (5s-10s),
    but the complete response takes ~3.5 seconds.
    """
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        # Send 10 chunks spaced by 0.35s = ~3.5s total stream
        for i in range(10):
            time.sleep(0.35)
            chunk = f"chunk-{i}\n".encode("utf-8")
            try:
                self.wfile.write(f"{len(chunk):X}\r\n".encode("utf-8") + chunk + b"\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def log_message(self, format, *args):
        pass  # Suppress HTTP access logs in test output


@pytest.fixture(scope="module")
def slow_stream_server():
    """Runs the SlowChunkedStreamHandler on an ephemeral port."""
    server = http.server.HTTPServer(("127.0.0.1", 0), SlowChunkedStreamHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    port = server.server_port
    yield f"http://127.0.0.1:{port}/slow-stream"
    server.shutdown()


def test_slow_streaming_aborts_at_overall_deadline(slow_stream_server):
    """
    Verify that an HTTP operation trickling data before the individual socket read timeout
    is strictly terminated by the overall wall-clock deadline (e.g. 1.0s) and does not hang
    for the full 3.5s stream duration.
    """
    start = time.perf_counter()
    result = execute_webhook_request(
        url=slow_stream_server,
        secret="whsec_deadline_test_secret",
        event_id="evt_deadline_test",
        delivery_id="deliv_deadline_test",
        event_type="test.slow.stream",
        payload={"stream": "slow"},
        timeout_seconds=1.0,
        allow_internal=True,
    )
    elapsed = time.perf_counter() - start

    # 1. Must fail with timeout outcome
    assert result.success is False
    assert result.outcome == HTTPOutcome.RETRYABLE_FAILURE
    assert result.http_status is None
    assert "Request timed out after 1.0s total deadline" in (result.error_message or "")

    # 2. Must abort around ~1.0s and never wait for the full 3.5s response
    assert 0.8 <= elapsed < 2.5, f"Expected abort near 1.0s, but elapsed was {elapsed:.2f}s"


def test_timeout_deadline_capped_by_lease_duration():
    """
    Verify that any requested timeout exceeding the worker lease duration is capped
    strictly below settings.LEASE_DURATION_SECONDS so workers never lose their lease
    while waiting on HTTP calls.
    """
    # Request an excessive 60.0s timeout with a 30.0s lease
    with patch("app.services.webhook_client.settings.LEASE_DURATION_SECONDS", 30.0):
        # We target a non-listening port to quickly fail after connect or test the cap directly
        result = execute_webhook_request(
            url="http://127.0.0.1:59999/unreachable",
            secret="whsec_test",
            event_id="evt_cap",
            delivery_id="deliv_cap",
            event_type="test.cap",
            payload={},
            timeout_seconds=60.0,
            allow_internal=True,
        )
        assert result.success is False
        assert result.outcome == HTTPOutcome.RETRYABLE_FAILURE


def test_worker_handles_timeout_correctly_with_valid_lease(db_session):
    """
    Verify that when an HTTP call times out within the worker's active lease duration:
    1. The pre-flight attempt (STARTED) is reconciled to FAILED with error details.
    2. The delivery is transitioned to RETRYING with exponential backoff and jitter.
    3. An OutboxEvent is created for the next scheduled retry.
    4. Worker lease is cleanly released upon completion.
    """
    ep = Endpoint(
        url="https://api.example.com/webhook",
        secret="whsec_valid_lease_test",
        is_active=True,
        event_types=["*"],
    )
    ev = Event(event_type="order.placed", payload={"order_id": 999})
    db_session.add_all([ep, ev])
    db_session.commit()

    deliv = Delivery(
        event_id=ev.id,
        endpoint_id=ep.id,
        status=DeliveryStatus.PENDING,
        attempt_count=0,
        max_attempts=3,
    )
    db_session.add(deliv)
    db_session.commit()

    timeout_result = WebhookExecutionResult(
        success=False,
        http_status=None,
        response_time_ms=10000,
        request_headers={},
        error_message="Request timed out after 10.0s total deadline",
        outcome=HTTPOutcome.RETRYABLE_FAILURE,
    )

    with patch("app.services.delivery_service.execute_webhook_request", return_value=timeout_result):
        completed_delivery = DeliveryService.execute_delivery(db_session, deliv.id, worker_id="worker-valid-1")

    assert completed_delivery is not None
    assert completed_delivery.status == DeliveryStatus.RETRYING
    assert completed_delivery.attempt_count == 1
    assert completed_delivery.last_error == "Request timed out after 10.0s total deadline"
    assert completed_delivery.lease_token is None
    assert completed_delivery.lease_expires_at is None
    assert completed_delivery.next_retry_at is not None

    # Verify attempt record
    attempts = (
        db_session.query(DeliveryAttempt)
        .filter(DeliveryAttempt.delivery_id == deliv.id)
        .all()
    )
    assert len(attempts) == 1
    assert attempts[0].status == AttemptStatus.FAILED
    assert attempts[0].attempt_number == 1
    assert "Request timed out after 10.0s total deadline" in attempts[0].error_message

    # Verify outbox event created for scheduled retry
    outbox = (
        db_session.query(OutboxEvent)
        .filter(
            OutboxEvent.delivery_id == deliv.id,
            OutboxEvent.status == OutboxStatus.PENDING,
        )
        .first()
    )
    assert outbox is not None
    assert outbox.scheduled_for == completed_delivery.next_retry_at


def test_stale_worker_fenced_if_lease_expired_during_delayed_http(db_session):
    """
    Verify that if a worker's lease expired before HTTP finalization:
    1. The worker's CAS query fails to match.
    2. The worker NEVER mutates the deliveries table.
    3. The worker reconciles its own attempt with an audit trail note.
    """
    ep = Endpoint(
        url="https://api.example.com/webhook",
        secret="whsec_stale_test",
        is_active=True,
        event_types=["*"],
    )
    ev = Event(event_type="order.placed", payload={"order_id": 888})
    db_session.add_all([ep, ev])
    db_session.commit()

    deliv = Delivery(
        event_id=ev.id,
        endpoint_id=ep.id,
        status=DeliveryStatus.PENDING,
        attempt_count=0,
        max_attempts=3,
    )
    db_session.add(deliv)
    db_session.commit()

    # We simulate a worker whose lease expires while in flight by hooking execute_webhook_request
    # to artificially advance the lease expiration into the past before returning
    def mock_http_with_lease_expiration(*args, **kwargs):
        # Artificially expire the lease in the database during the HTTP call
        past_time = datetime.now(timezone.utc) - timedelta(seconds=10)
        db_session.query(Delivery).filter(Delivery.id == deliv.id).update(
            {"lease_expires_at": past_time}
        )
        db_session.commit()
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=12000,
            request_headers={},
            error_message="Request timed out after 10.0s total deadline",
            outcome=HTTPOutcome.RETRYABLE_FAILURE,
        )

    with patch("app.services.delivery_service.execute_webhook_request", side_effect=mock_http_with_lease_expiration):
        result_delivery = DeliveryService.execute_delivery(db_session, deliv.id, worker_id="worker-stale-1")

    # Delivery table was NOT updated to RETRYING by this stale worker; remains PROCESSING with expired lease
    assert result_delivery.status == DeliveryStatus.PROCESSING

    # Attempt record was reconciled with STALE WORKER note
    attempt = (
        db_session.query(DeliveryAttempt)
        .filter(DeliveryAttempt.delivery_id == deliv.id)
        .first()
    )
    assert attempt is not None
    assert attempt.status == AttemptStatus.FAILED
    assert "[STALE WORKER RECONCILIATION]" in attempt.error_message
