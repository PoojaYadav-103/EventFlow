from unittest.mock import patch
import pytest

from app.services.webhook_client import WebhookExecutionResult


def test_successful_webhook_delivery(client, db_session):
    """Scenario 3: Successfully deliver an event."""
    # 1. Register endpoint
    reg = client.post(
        "/api/v1/endpoints",
        json={"url": "https://consumer.example.com/webhook", "event_types": ["order.placed"]},
    )
    assert reg.status_code == 201

    mock_result = WebhookExecutionResult(
        success=True,
        http_status=200,
        response_time_ms=45,
        request_headers={"x-eventflow-signature": "t=1,v1=test_sig"},
        response_headers={"x-server-id": "srv-prod-1"},
        response_body='{"received": true, "status": "ok"}',
        error_message=None,
    )

    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_result):
        event_resp = client.post(
            "/api/v1/events",
            json={"event_type": "order.placed", "payload": {"item": "Laptop", "qty": 1}},
        )
        assert event_resp.status_code == 201
        event_id = event_resp.json()["id"]

        # Transactional outbox relay dispatches the pending delivery
        from app.workers.tasks import sweep_outbox_task
        processed = sweep_outbox_task()
        assert processed == 1

    # Verify delivery record state
    deliv_resp = client.get(f"/api/v1/deliveries?event_id={event_id}")
    assert deliv_resp.status_code == 200
    deliveries = deliv_resp.json()
    assert len(deliveries) == 1

    delivery = deliveries[0]
    assert delivery["status"] == "SUCCESS"
    assert delivery["last_http_status"] == 200
    assert delivery["attempt_count"] == 1
    assert delivery["last_error"] is None

    # Inspect delivery detail and attempts
    detail_resp = client.get(f"/api/v1/deliveries/{delivery['id']}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert len(detail["attempts"]) == 1
    att = detail["attempts"][0]
    assert att["status"] == "SUCCESS"
    assert att["http_status"] == 200
    assert "x-eventflow-signature" in att["request_headers"]
    assert att["response_headers"].get("x-server-id") == "srv-prod-1"


def test_failed_webhook_response(client, db_session):
    """Scenario 4: Handle a failed webhook response (HTTP 500)."""
    client.post(
        "/api/v1/endpoints",
        json={"url": "https://failing.example.com/webhook", "event_types": ["*"]},
    )

    mock_fail_result = WebhookExecutionResult(
        success=False,
        http_status=500,
        response_time_ms=30,
        request_headers={"x-eventflow-signature": "t=1,v1=test_sig"},
        response_headers={},
        response_body="Internal Server Error: Database down",
        error_message="HTTP Error 500: Internal Server Error",
    )

    with patch("app.services.delivery_service.execute_webhook_request", return_value=mock_fail_result):
        event_resp = client.post(
            "/api/v1/events",
            json={"event_type": "order.placed", "payload": {"amount": 50}},
        )
        assert event_resp.status_code == 201
        event_id = event_resp.json()["id"]

        # Transactional outbox relay dispatches the pending delivery
        from app.workers.tasks import sweep_outbox_task
        processed = sweep_outbox_task()
        assert processed == 1

    # Verify delivery record transitioned to RETRYING
    deliv_resp = client.get(f"/api/v1/deliveries?event_id={event_id}")
    delivery = deliv_resp.json()[0]

    assert delivery["status"] == "RETRYING"
    assert delivery["last_http_status"] == 500
    assert "HTTP Error 500" in delivery["last_error"]
    assert delivery["attempt_count"] == 1
    assert delivery["next_retry_at"] is not None
