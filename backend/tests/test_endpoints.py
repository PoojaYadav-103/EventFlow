import pytest


def test_register_webhook_success(client):
    """Scenario 1: Successfully register a webhook."""
    payload = {
        "url": "https://api.example.com/webhooks/orders",
        "description": "Inventory Notification Service",
        "event_types": ["order.placed", "order.shipped"],
    }
    response = client.post("/api/v1/endpoints", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["url"] == payload["url"]
    assert data["description"] == payload["description"]
    assert data["is_active"] is True
    assert "order.placed" in data["event_types"]
    # Secret must be returned unmasked on creation
    assert "signing_secret" in data
    assert data["signing_secret"].startswith("whsec_")
    # Masked secret must also be formatted correctly
    assert "••••" in data["signing_secret_masked"]


def test_list_endpoints_masks_secrets(client):
    """Test that listing endpoints never exposes the unmasked signing secret."""
    # Register an endpoint first
    reg = client.post(
        "/api/v1/endpoints",
        json={"url": "https://example.com/hook1", "event_types": ["*"]},
    )
    assert reg.status_code == 201
    full_secret = reg.json()["signing_secret"]

    # List endpoints
    list_resp = client.get("/api/v1/endpoints")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert len(items) >= 1
    found = next(item for item in items if item["id"] == reg.json()["id"])
    assert "signing_secret" not in found
    assert found["signing_secret_masked"].startswith("whsec_")
    assert full_secret not in found["signing_secret_masked"]


def test_register_invalid_input(client):
    """Scenario 9: Handle invalid input."""
    # 1. Invalid URL scheme
    bad_url_resp = client.post(
        "/api/v1/endpoints",
        json={"url": "ftp://example.com/hook"},
    )
    assert bad_url_resp.status_code in (400, 422)

    # 2. Missing url field
    missing_url_resp = client.post(
        "/api/v1/endpoints",
        json={"description": "No url provided"},
    )
    assert missing_url_resp.status_code == 422


def test_toggle_endpoint_active_status(client):
    """Test enabling and disabling an endpoint."""
    reg = client.post(
        "/api/v1/endpoints",
        json={"url": "https://example.com/hook-toggle", "event_types": ["*"]},
    )
    ep_id = reg.json()["id"]

    # Deactivate
    patch_resp = client.patch(f"/api/v1/endpoints/{ep_id}", json={"is_active": False})
    assert patch_resp.status_code == 200
    assert patch_resp.json()["is_active"] is False

    # Reactivate
    patch_resp2 = client.patch(f"/api/v1/endpoints/{ep_id}", json={"is_active": True})
    assert patch_resp2.status_code == 200
    assert patch_resp2.json()["is_active"] is True


def test_roll_signing_secret(client):
    """Test rotating an endpoint's signing secret."""
    reg = client.post(
        "/api/v1/endpoints",
        json={"url": "https://example.com/hook-roll"},
    )
    ep_id = reg.json()["id"]
    old_secret = reg.json()["signing_secret"]

    roll_resp = client.post(f"/api/v1/endpoints/{ep_id}/roll-secret")
    assert roll_resp.status_code == 200
    data = roll_resp.json()
    assert data["signing_secret"] != old_secret
    assert data["signing_secret"].startswith("whsec_")


def test_soft_delete_preserves_history(client, db_session):
    """Test that deleting an endpoint performs soft deletion and preserves historical records."""
    # 1. Register endpoint and publish event
    reg = client.post(
        "/api/v1/endpoints",
        json={"url": "https://example.com/soft-delete-hook", "event_types": ["*"]},
    )
    ep_id = reg.json()["id"]

    ev_resp = client.post(
        "/api/v1/events",
        json={"event_type": "order.placed", "payload": {"item": "Book"}},
    )
    ev_id = ev_resp.json()["id"]

    # Verify delivery exists
    delivs_before = client.get(f"/api/v1/deliveries?event_id={ev_id}").json()
    assert len(delivs_before) == 1
    assert delivs_before[0]["endpoint_id"] == ep_id

    # 2. Delete endpoint
    del_resp = client.delete(f"/api/v1/endpoints/{ep_id}")
    assert del_resp.status_code == 204

    # Endpoint is no longer returned in active endpoint queries
    get_ep = client.get(f"/api/v1/endpoints/{ep_id}")
    assert get_ep.status_code == 404

    # Historical delivery record is STILL preserved in the database!
    delivs_after = client.get(f"/api/v1/deliveries?event_id={ev_id}").json()
    assert len(delivs_after) == 1
    assert delivs_after[0]["endpoint_id"] == ep_id
