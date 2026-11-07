from unittest.mock import patch
import pytest

from app.models.delivery import Delivery, DeliveryStatus
from app.services.delivery_service import DeliveryService
from app.services.webhook_client import WebhookExecutionResult


def test_dead_letter_on_exhausted_retries(client, db_session):
    """Scenario 6: Mark exhausted deliveries as dead-lettered when max attempts reached."""
    reg = client.post(
        "/api/v1/endpoints",
        json={"url": "https://flaky.example.com/webhook", "event_types": ["*"]},
    )
    endpoint_id = reg.json()["id"]

    mock_fail_result = WebhookExecutionResult(
        success=False,
        http_status=503,
        response_time_ms=25,
        request_headers={"x-eventflow-signature": "t=1,v1=test_sig"},
        response_headers={},
        response_body="Service Unavailable",
        error_message="HTTP Error 503: Service Unavailable",
    )

    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_fail_result):
        event_resp = client.post(
            "/api/v1/events",
            json={"event_type": "order.placed", "payload": {"item": "Test"}},
        )
        event_id = event_resp.json()["id"]

        from app.workers.tasks import sweep_outbox_task
        sweep_outbox_task()

    deliv_resp = client.get(f"/api/v1/deliveries?event_id={event_id}")
    delivery_id = deliv_resp.json()[0]["id"]

    # Now simulate repeated failures until max_attempts (5) is reached
    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_fail_result):
        # Already 1 attempt made. Run 4 more attempts:
        for _ in range(4):
            # Advance scheduled time for retry
            d = db_session.query(Delivery).filter(Delivery.id == delivery_id).first()
            d.next_retry_at = None
            db_session.commit()
            DeliveryService.execute_delivery(db_session, delivery_id)

    # Fetch updated delivery
    final_resp = client.get(f"/api/v1/deliveries/{delivery_id}")
    final_data = final_resp.json()

    assert final_data["attempt_count"] == 5
    assert final_data["status"] == "DEAD_LETTER"
    assert final_data["next_retry_at"] is None
    assert "HTTP Error 503" in final_data["last_error"]


def test_retry_failed_delivery_and_succeed(client, db_session):
    """Scenario 5: Retry a failed delivery and succeed on subsequent attempt."""
    reg = client.post(
        "/api/v1/endpoints",
        json={"url": "https://recovery.example.com/webhook", "event_types": ["*"]},
    )

    # First attempt fails
    mock_fail_result = WebhookExecutionResult(
        success=False,
        http_status=500,
        response_time_ms=30,
        request_headers={"x-eventflow-signature": "t=1,v1=test_sig"},
        response_headers={},
        response_body="Server error",
        error_message="HTTP Error 500: Server error",
    )
    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_fail_result):
        event_resp = client.post(
            "/api/v1/events",
            json={"event_type": "order.shipped", "payload": {"tracking": "TRK123"}},
        )
        from app.workers.tasks import sweep_outbox_task
        sweep_outbox_task()
        delivery_id = client.get(f"/api/v1/deliveries?event_id={event_resp.json()['id']}").json()[0]["id"]

    # Verify initially in RETRYING
    deliv = client.get(f"/api/v1/deliveries/{delivery_id}").json()
    assert deliv["status"] == "RETRYING"
    assert deliv["attempt_count"] == 1

    # Second attempt succeeds!
    d = db_session.query(Delivery).filter(Delivery.id == delivery_id).first()
    d.next_retry_at = None
    db_session.commit()

    mock_success_result = WebhookExecutionResult(
        success=True,
        http_status=200,
        response_time_ms=40,
        request_headers={"x-eventflow-signature": "t=1,v1=test_sig"},
        response_headers={"content-type": "application/json"},
        response_body='{"status": "ok"}',
        error_message=None,
    )
    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_success_result):
        DeliveryService.execute_delivery(db_session, delivery_id)

    # Verify now SUCCESS
    updated = client.get(f"/api/v1/deliveries/{delivery_id}").json()
    assert updated["status"] == "SUCCESS"
    assert updated["attempt_count"] == 2
    assert updated["last_http_status"] == 200
    assert updated["last_error"] is None


def test_manual_retry_action(client, db_session):
    """
    Test manual retry API endpoint POST /deliveries/{id}/retry:
    - Rejects retrying active in-flight or non-failed states (RETRYING, SUCCESS) with 409
    - Rejects duplicate concurrent retry requests when outbox event is already pending
    - Permits retry for DEAD_LETTER deliveries, resetting state and creating outbox atomically
    - Preserves previous attempt history
    """
    reg = client.post(
        "/api/v1/endpoints",
        json={"url": "https://manual.example.com/webhook", "event_types": ["*"]},
    )
    mock_fail_result = WebhookExecutionResult(
        success=False,
        http_status=500,
        response_time_ms=20,
        request_headers={"x-eventflow-signature": "t=1,v1=test_sig"},
        response_headers={},
        response_body="Error",
        error_message="HTTP Error 500: Internal Server Error",
    )
    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_fail_result):
        event_resp = client.post(
            "/api/v1/events",
            json={"event_type": "order.shipped", "payload": {"item": "Shoes"}},
        )
        from app.workers.tasks import sweep_outbox_task
        sweep_outbox_task()
        delivery_id = client.get(f"/api/v1/deliveries?event_id={event_resp.json()['id']}").json()[0]["id"]

    # 1. Delivery is currently in RETRYING state: manual retry must be rejected with 409
    deliv_state = client.get(f"/api/v1/deliveries/{delivery_id}").json()
    assert deliv_state["status"] == "RETRYING"
    rejected_resp = client.post(f"/api/v1/deliveries/{delivery_id}/retry")
    assert rejected_resp.status_code == 409
    assert "Cannot manually retry delivery with status 'RETRYING'" in rejected_resp.json()["detail"]

    # 2. Drive delivery to DEAD_LETTER state by exhausting max_attempts
    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_fail_result):
        for _ in range(4):
            d = db_session.query(Delivery).filter(Delivery.id == delivery_id).first()
            d.next_retry_at = None
            db_session.commit()
            DeliveryService.execute_delivery(db_session, delivery_id)

    deliv_dead = client.get(f"/api/v1/deliveries/{delivery_id}").json()
    assert deliv_dead["status"] == "DEAD_LETTER"
    assert deliv_dead["attempt_count"] == 5

    # 3. Eligible DEAD_LETTER delivery: manual retry must succeed
    retry_resp = client.post(f"/api/v1/deliveries/{delivery_id}/retry")
    assert retry_resp.status_code == 200
    assert retry_resp.json()["status"] == "PENDING"

    # 4. Duplicate retry while delivery is in PENDING state must be rejected with 409
    dup_retry_resp = client.post(f"/api/v1/deliveries/{delivery_id}/retry")
    assert dup_retry_resp.status_code == 409
    assert "PENDING" in dup_retry_resp.json()["detail"]

    # 5. Outbox relay sweeps the pending retry and executes it
    mock_ok_result = WebhookExecutionResult(
        success=True,
        http_status=200,
        response_time_ms=35,
        request_headers={"x-eventflow-signature": "t=1,v1=test_sig"},
        response_headers={},
        response_body='{"ok": true}',
        error_message=None,
    )
    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_ok_result):
        processed = sweep_outbox_task()
        assert processed == 1

    # 6. Verify delivery reached SUCCESS and attempts history is preserved:
    # In Module 2: attempt_count tracks active cycle (reset to 0 on manual retry -> 1 on success)
    # Total historical attempts = 5 (cycle 1) + 1 (cycle 2) = 6
    db_session.expire_all()
    detail_resp = client.get(f"/api/v1/deliveries/{delivery_id}").json()
    assert detail_resp["status"] == "SUCCESS"
    assert detail_resp["attempt_count"] == 1
    assert len(detail_resp["attempts"]) == 6
    assert detail_resp["attempts"][-1]["attempt_number"] == 6

    # 7. SUCCESS delivery must also reject manual retry with 409
    success_retry_resp = client.post(f"/api/v1/deliveries/{delivery_id}/retry")
    assert success_retry_resp.status_code == 409
