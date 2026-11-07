from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import pytest

from app.models.delivery import Delivery, DeliveryStatus
from app.models.outbox import OutboxEvent, OutboxStatus
from app.models.endpoint import Endpoint
from app.models.event import Event
from app.services.delivery_service import DeliveryService
from app.services.webhook_client import WebhookExecutionResult
from app.workers.tasks import sweep_outbox_task, sweep_retries_task


def test_sweep_outbox_redis_failure_preserves_pending_records(client, db_session):
    """
    Verifies that when publishing a delivery task to Redis/broker raises an exception:
    - The Outbox record is NOT marked PUBLISHED.
    - The Outbox record remains PENDING and retryable.
    - Processed count is not incremented for failed dispatches.
    - Once the broker recovers, the next sweep cycle successfully publishes the task.
    """
    # 1. Setup endpoint, event, delivery, and pending outbox record
    endpoint = Endpoint(
        url="https://consumer.example.com/webhook",
        secret="whsec_test_outbox_reliability",
        is_active=True,
        event_types=["order.placed"],
    )
    event = Event(event_type="order.placed", payload={"order_id": "ord_999"})
    db_session.add(endpoint)
    db_session.add(event)
    db_session.flush()

    delivery = Delivery(event_id=event.id, endpoint_id=endpoint.id, status=DeliveryStatus.PENDING)
    db_session.add(delivery)
    db_session.flush()

    outbox = OutboxEvent(delivery_id=delivery.id, status=OutboxStatus.PENDING)
    db_session.add(outbox)
    db_session.commit()
    outbox_id = outbox.id

    # 2. Simulate Redis broker network failure
    with patch("app.workers.tasks.deliver_webhook_task.delay", side_effect=ConnectionError("Redis connection refused")):
        processed_count = sweep_outbox_task()
        assert processed_count == 0, "Processed count must not increment when broker publishing fails"

    # 3. Assert outbox record was NOT marked PUBLISHED and remains PENDING
    refreshed_outbox = db_session.query(OutboxEvent).filter(OutboxEvent.id == outbox_id).first()
    assert refreshed_outbox.status == OutboxStatus.PENDING, "Outbox event must remain PENDING on broker failure"
    assert refreshed_outbox.processed_at is None

    # 4. Broker recovers: next sweep cycle publishes successfully
    mock_ok_result = WebhookExecutionResult(
        success=True,
        http_status=200,
        response_time_ms=30,
        request_headers={},
        response_body="OK",
    )
    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_ok_result):
        processed_count = sweep_outbox_task()
        assert processed_count == 1, "Should successfully process the outbox record once broker is available"

    db_session.expire_all()
    refreshed_outbox_after = db_session.query(OutboxEvent).filter(OutboxEvent.id == outbox_id).first()
    assert refreshed_outbox_after.status == OutboxStatus.PUBLISHED
    assert refreshed_outbox_after.processed_at is not None


def test_automatic_retry_creates_scheduled_outbox_record(client, db_session):
    """
    Verifies that when a delivery attempt fails, an OutboxEvent is created
    in the same database transaction with scheduled_for set to next_retry_at,
    and no direct Celery enqueueing is performed.
    """
    endpoint = Endpoint(
        url="https://consumer.example.com/webhook",
        secret="whsec_test_retry_outbox",
        is_active=True,
        event_types=["order.placed"],
    )
    event = Event(event_type="order.placed", payload={"order_id": "ord_100"})
    db_session.add(endpoint)
    db_session.add(event)
    db_session.flush()

    delivery = Delivery(event_id=event.id, endpoint_id=endpoint.id, status=DeliveryStatus.PENDING)
    db_session.add(delivery)
    db_session.commit()

    mock_fail_result = WebhookExecutionResult(
        success=False,
        http_status=500,
        response_time_ms=50,
        request_headers={},
        error_message="HTTP 500 Internal Server Error",
    )

    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_fail_result):
        updated_delivery = DeliveryService.execute_delivery(db_session, delivery.id)

    assert updated_delivery.status == DeliveryStatus.RETRYING
    assert updated_delivery.next_retry_at is not None

    # Check that a scheduled OutboxEvent exists with scheduled_for == delivery.next_retry_at
    retry_outbox = (
        db_session.query(OutboxEvent)
        .filter(
            OutboxEvent.delivery_id == delivery.id,
            OutboxEvent.status == OutboxStatus.PENDING,
        )
        .first()
    )
    assert retry_outbox is not None, "Automatic retry must create a pending OutboxEvent"
    assert retry_outbox.scheduled_for is not None
    # scheduled_for should match the delivery's next_retry_at within a 1-second margin
    diff = abs((retry_outbox.scheduled_for - updated_delivery.next_retry_at).total_seconds())
    assert diff < 2.0


def test_sweep_retries_task_creates_outbox_without_direct_celery_publish(client, db_session):
    """
    Verifies that sweep_retries_task creates an OutboxEvent record for overdue retries
    and does NOT directly publish tasks to Redis/Celery.
    """
    endpoint = Endpoint(
        url="https://consumer.example.com/webhook",
        secret="whsec_test_sweep_retries",
        is_active=True,
        event_types=["*"],
    )
    event = Event(event_type="test.event", payload={})
    db_session.add(endpoint)
    db_session.add(event)
    db_session.flush()

    # Delivery in RETRYING state with next_retry_at in the past
    past_time = datetime.now(timezone.utc) - timedelta(minutes=2)
    delivery = Delivery(
        event_id=event.id,
        endpoint_id=endpoint.id,
        status=DeliveryStatus.RETRYING,
        next_retry_at=past_time,
    )
    db_session.add(delivery)
    db_session.commit()

    with patch("app.workers.tasks.deliver_webhook_task.delay") as mock_delay:
        enqueued = sweep_retries_task()
        # Direct publishing must NOT happen from sweep_retries_task
        mock_delay.assert_not_called()

    assert enqueued == 1
    # Verify OutboxEvent was created
    outbox = (
        db_session.query(OutboxEvent)
        .filter(
            OutboxEvent.delivery_id == delivery.id,
            OutboxEvent.status == OutboxStatus.PENDING,
        )
        .first()
    )
    assert outbox is not None
    assert outbox.status == OutboxStatus.PENDING
