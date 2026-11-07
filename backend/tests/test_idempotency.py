import pytest
from app.models.delivery import Delivery, DeliveryStatus
from app.services.delivery_service import DeliveryService


def test_client_idempotency_key_prevents_duplicate_events(client):
    """Scenario 7: Prevent duplicate delivery records and duplicate events."""
    client.post(
        "/api/v1/endpoints",
        json={"url": "https://consumer.example.com/orders", "event_types": ["*"]},
    )

    event_payload = {
        "event_type": "order.placed",
        "payload": {"order_id": "ord_9999", "total": 99.00},
        "idempotency_key": "idemp_client_req_001",
    }

    # First request -> 201 Created
    resp1 = client.post("/api/v1/events", json=event_payload)
    assert resp1.status_code == 201
    event_id_1 = resp1.json()["id"]

    # Second request with identical idempotency key -> 200 OK with same event_id
    resp2 = client.post("/api/v1/events", json=event_payload)
    assert resp2.status_code == 200
    assert resp2.json()["id"] == event_id_1

    # Check total deliveries in DB for this event - must remain exactly 1!
    deliv_resp = client.get(f"/api/v1/deliveries?event_id={event_id_1}")
    assert len(deliv_resp.json()) == 1


def test_delivery_execution_idempotency(db_session):
    """Ensure delivery execution is safe against repeated task execution."""
    delivery = Delivery(
        event_id="dummy-event-id",
        endpoint_id="dummy-endpoint-id",
        status=DeliveryStatus.SUCCESS,
        attempt_count=1,
    )
    db_session.add(delivery)
    db_session.commit()

    # Re-running execution on an already successful delivery returns immediately without changing attempt count
    result = DeliveryService.execute_delivery(db_session, delivery.id)
    assert result.status == DeliveryStatus.SUCCESS
    assert result.attempt_count == 1
