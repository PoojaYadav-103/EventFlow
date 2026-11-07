import pytest


def test_publish_event_success(client):
    """Scenario 2: Publish an event and generate delivery records."""
    # 1. Register two endpoints
    client.post(
        "/api/v1/endpoints",
        json={"url": "https://service-a.com/hook", "event_types": ["order.placed"]},
    )
    client.post(
        "/api/v1/endpoints",
        json={"url": "https://service-b.com/hook", "event_types": ["*"]},
    )

    # 2. Publish order.placed event
    event_payload = {
        "event_type": "order.placed",
        "payload": {
            "order_id": "ord_12345",
            "customer_id": "cust_999",
            "amount": 149.99,
            "currency": "USD",
        },
    }
    response = client.post("/api/v1/events", json=event_payload)
    assert response.status_code == 201
    data = response.json()
    assert data["event_type"] == "order.placed"
    assert data["payload"]["order_id"] == "ord_12345"
    assert data["deliveries_count"] == 2


def test_inactive_endpoint_does_not_receive_events(client):
    """Scenario 10: Ensure inactive endpoints do not receive events."""
    # 1. Register active endpoint
    active_resp = client.post(
        "/api/v1/endpoints",
        json={"url": "https://active.com/hook", "event_types": ["*"]},
    )
    # 2. Register inactive endpoint
    inactive_resp = client.post(
        "/api/v1/endpoints",
        json={"url": "https://inactive.com/hook", "event_types": ["*"]},
    )
    inactive_id = inactive_resp.json()["id"]
    client.patch(f"/api/v1/endpoints/{inactive_id}", json={"is_active": False})

    # 3. Publish event
    event_resp = client.post(
        "/api/v1/events",
        json={"event_type": "order.confirmed", "payload": {"id": 1}},
    )
    assert event_resp.status_code == 201
    event_id = event_resp.json()["id"]

    # Check delivery records for this event
    deliv_resp = client.get(f"/api/v1/deliveries?event_id={event_id}")
    assert deliv_resp.status_code == 200
    deliveries = deliv_resp.json()
    assert len(deliveries) == 1
    assert deliveries[0]["endpoint_id"] == active_resp.json()["id"]


def test_event_type_filtering(client):
    """Ensure events are only routed to endpoints subscribed to matching types."""
    # Subscribed only to order.cancelled
    ep_cancel = client.post(
        "/api/v1/endpoints",
        json={"url": "https://cancellations.com/hook", "event_types": ["order.cancelled"]},
    )
    # Subscribed only to order.delivered
    ep_delivered = client.post(
        "/api/v1/endpoints",
        json={"url": "https://logistics.com/hook", "event_types": ["order.delivered"]},
    )

    # Publish order.cancelled
    resp = client.post(
        "/api/v1/events",
        json={"event_type": "order.cancelled", "payload": {"reason": "Customer request"}},
    )
    assert resp.status_code == 201
    assert resp.json()["deliveries_count"] == 1
    event_id = resp.json()["id"]

    deliv_resp = client.get(f"/api/v1/deliveries?event_id={event_id}")
    assert deliv_resp.json()[0]["endpoint_id"] == ep_cancel.json()["id"]
