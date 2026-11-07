import json
from app.core.security import sign_payload


def test_mock_receiver_flow(client):
    """Test built-in mock webhook receiver logging, configuration, and cryptographic HMAC verification."""
    # 1. Clear any existing logs
    client.delete("/api/v1/mock-receiver/logs")

    test_secret = "whsec_test_secret_for_mock_receiver_12345"

    # 2. Configure mock receiver with secret and 200 OK
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "delay_seconds": 0.0, "signing_secret": test_secret},
    )

    # 3. Create genuine HMAC signature for payload
    payload_data = {"order_id": "ord_100"}
    raw_payload_str = json.dumps(payload_data)
    valid_sig_header, timestamp = sign_payload(test_secret, raw_payload_str)

    # Send mock webhook with genuine HMAC signature
    post_resp = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={
            "Content-Type": "application/json",
            "X-EventFlow-Delivery-Id": "del_test_1",
            "X-EventFlow-Event-Id": "ev_test_1",
            "X-EventFlow-Event-Type": "order.placed",
            "X-EventFlow-Signature": valid_sig_header,
        },
        content=raw_payload_str.encode("utf-8"),
    )
    assert post_resp.status_code == 200

    # 4. Inspect logs and assert genuine cryptographic validation succeeded
    logs_resp = client.get("/api/v1/mock-receiver/logs")
    assert logs_resp.status_code == 200
    logs = logs_resp.json()
    assert len(logs) == 1
    assert logs[0]["delivery_id"] == "del_test_1"
    assert logs[0]["payload"]["order_id"] == "ord_100"
    assert logs[0]["signature_valid"] is True

    # 5. Send fabricated / invalid signature and verify rejection
    client.post(
        "/api/v1/mock-receiver/webhook",
        headers={
            "Content-Type": "application/json",
            "X-EventFlow-Delivery-Id": "del_test_2",
            "X-EventFlow-Event-Id": "ev_test_2",
            "X-EventFlow-Event-Type": "order.placed",
            "X-EventFlow-Signature": "t=12345,v1=fabricated_digest_1234567890",
        },
        content=raw_payload_str.encode("utf-8"),
    )
    logs = client.get("/api/v1/mock-receiver/logs").json()
    assert logs[0]["delivery_id"] == "del_test_2"
    assert logs[0]["signature_valid"] is False, "Fabricated signature must be rejected"

    # 6. Send modified / tampered payload with original signature and verify rejection
    tampered_payload_str = json.dumps({"order_id": "ord_tampered"})
    client.post(
        "/api/v1/mock-receiver/webhook",
        headers={
            "Content-Type": "application/json",
            "X-EventFlow-Delivery-Id": "del_test_3",
            "X-EventFlow-Event-Id": "ev_test_3",
            "X-EventFlow-Event-Type": "order.placed",
            "X-EventFlow-Signature": valid_sig_header,
        },
        content=tampered_payload_str.encode("utf-8"),
    )
    logs = client.get("/api/v1/mock-receiver/logs").json()
    assert logs[0]["delivery_id"] == "del_test_3"
    assert logs[0]["signature_valid"] is False, "Tampered payload must be rejected"


def test_mock_receiver_error_simulation(client):
    """Test simulated failure responses in mock receiver."""
    # Configure mock receiver to respond with 502 Bad Gateway
    client.post("/api/v1/mock-receiver/config", json={"status_code": 502})

    resp = client.post(
        "/api/v1/mock-receiver/webhook",
        json={"test": "error_simulation"},
    )
    assert resp.status_code == 502
