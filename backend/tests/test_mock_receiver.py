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


def test_mock_receiver_bidirectional_transitions_500_to_200_and_200_to_500(client):
    """
    Verify bidirectional configuration transitions:
    HTTP 500 -> HTTP 200 and HTTP 200 -> HTTP 500.
    Ensures GET and webhook POST responses consistently reflect the current state.
    """
    # Phase 1: Set to 500
    res1 = client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 500, "delay_seconds": 0.5, "reject_all": False},
    )
    assert res1.status_code == 200
    assert res1.json()["status_code"] == 500
    assert client.get("/api/v1/mock-receiver/config").json()["status_code"] == 500
    assert client.post("/api/v1/mock-receiver/webhook", json={"step": 1}).status_code == 500

    # Phase 2: Transition 500 -> 200
    res2 = client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "delay_seconds": 0.0, "reject_all": False},
    )
    assert res2.status_code == 200
    assert res2.json()["status_code"] == 200
    assert client.get("/api/v1/mock-receiver/config").json()["status_code"] == 200
    assert client.post("/api/v1/mock-receiver/webhook", json={"step": 2}).status_code == 200

    # Phase 3: Transition 200 -> 500
    res3 = client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 500, "delay_seconds": 0.0, "reject_all": False},
    )
    assert res3.status_code == 200
    assert res3.json()["status_code"] == 500
    assert client.get("/api/v1/mock-receiver/config").json()["status_code"] == 500
    assert client.post("/api/v1/mock-receiver/webhook", json={"step": 3}).status_code == 500

    # Phase 4: Transition back to 200
    res4 = client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "delay_seconds": 0.0, "reject_all": False},
    )
    assert res4.status_code == 200
    assert res4.json()["status_code"] == 200
    assert client.get("/api/v1/mock-receiver/config").json()["status_code"] == 200
    assert client.post("/api/v1/mock-receiver/webhook", json={"step": 4}).status_code == 200


def test_mock_receiver_get_post_consistency_and_secret_clearing(client):
    """
    Verify GET/POST configuration consistency, secret masking, and explicit secret clearing.
    Never exposes raw secrets in API responses.
    """
    raw_custom_secret = "whsec_custom_secret_for_mock_receiver_9999"

    # 1. POST config with secret
    post_res = client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "delay_seconds": 1.0, "signing_secret": raw_custom_secret},
    )
    assert post_res.status_code == 200
    post_data = post_res.json()
    assert post_data["status_code"] == 200
    assert post_data["delay_seconds"] == 1.0
    # Secret must be masked, NEVER exposed raw
    assert post_data["signing_secret"] is not None
    assert "••••" in post_data["signing_secret"]
    assert raw_custom_secret not in post_data["signing_secret"]

    # 2. GET config matches POST response exactly
    get_res = client.get("/api/v1/mock-receiver/config")
    assert get_res.status_code == 200
    assert get_res.json() == post_data

    # 3. Explicit secret clearing via None / null
    clear_res = client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": None},
    )
    assert clear_res.status_code == 200
    assert clear_res.json()["signing_secret"] is None
    assert client.get("/api/v1/mock-receiver/config").json()["signing_secret"] is None

    # 4. Explicit secret clearing via empty string
    client.post("/api/v1/mock-receiver/config", json={"signing_secret": raw_custom_secret})
    assert client.get("/api/v1/mock-receiver/config").json()["signing_secret"] is not None
    clear_empty = client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": ""},
    )
    assert clear_empty.status_code == 200
    assert clear_empty.json()["signing_secret"] is None
    assert client.get("/api/v1/mock-receiver/config").json()["signing_secret"] is None


def test_mock_receiver_database_endpoint_secret_precedence_and_no_fallback(client, db_session):
    """
    Verify regression requirement:
    1. When a delivery ID identifies an existing delivery, its endpoint's database secret
       is authoritative, overriding any stale or conflicting global mock secret.
    2. If the delivery exists in DB but has no secret, do NOT silently fall back to global mock secret.
    3. Standalone deliveries not in DB fall back to global mock secret.
    """
    from app.models.endpoint import Endpoint
    from app.models.event import Event
    from app.models.delivery import Delivery

    client.delete("/api/v1/mock-receiver/logs")

    # Set a conflicting/stale global mock secret
    global_mismatch_secret = "whsec_conflicting_global_secret_1111"
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": global_mismatch_secret},
    )

    # Subtest 1: Existing delivery in DB with valid secret -> authoritative DB secret
    real_secret = "whsec_real_endpoint_signing_secret_998877"
    ep1 = Endpoint(
        url="http://backend:8000/api/v1/mock-receiver/webhook",
        secret=real_secret,
        is_active=True,
        event_types=["*"],
    )
    ev1 = Event(event_type="order.placed", payload={"item": "book", "qty": 1})
    db_session.add_all([ep1, ev1])
    db_session.commit()

    deliv1 = Delivery(event_id=ev1.id, endpoint_id=ep1.id)
    db_session.add(deliv1)
    db_session.commit()

    payload1_str = json.dumps({"item": "book", "qty": 1}, separators=(",", ":"))
    sig1, _ = sign_payload(real_secret, payload1_str)

    resp1 = client.post(
        "/api/v1/mock-receiver/webhook",
        content=payload1_str.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-EventFlow-Delivery-Id": deliv1.id,
            "X-EventFlow-Event-Id": ev1.id,
            "X-EventFlow-Signature": sig1,
        },
    )
    assert resp1.status_code == 200
    logs = client.get("/api/v1/mock-receiver/logs").json()
    log1 = next((l for l in logs if l.get("delivery_id") == deliv1.id), None)
    assert log1 is not None
    assert log1["signature_valid"] is True, "Must verify against DB endpoint secret"

    # Subtest 2: Existing delivery in DB where endpoint is missing/None (e.g. deleted endpoint)
    # Must NOT silently fall back to global_mismatch_secret
    ev2 = Event(event_type="order.placed", payload={"item": "pencil"})
    db_session.add(ev2)
    db_session.commit()

    deliv2 = Delivery(event_id=ev2.id, endpoint_id=None)
    db_session.add(deliv2)
    db_session.commit()

    payload2_str = json.dumps({"item": "pencil"}, separators=(",", ":"))
    # Sign with the global secret to see if it mistakenly falls back
    sig2_with_global, _ = sign_payload(global_mismatch_secret, payload2_str)

    client.post(
        "/api/v1/mock-receiver/webhook",
        content=payload2_str.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-EventFlow-Delivery-Id": deliv2.id,
            "X-EventFlow-Event-Id": ev2.id,
            "X-EventFlow-Signature": sig2_with_global,
        },
    )
    logs = client.get("/api/v1/mock-receiver/logs").json()
    log2 = next((l for l in logs if l.get("delivery_id") == deliv2.id), None)
    assert log2 is not None
    assert log2["signature_valid"] is False, "Must NOT fall back to global mock secret for existing delivery"

    # Subtest 3: Synthetic delivery NOT in DB falls back to global mock secret
    synthetic_id = "del_synthetic_not_in_db_999"
    payload3_str = json.dumps({"synthetic": True}, separators=(",", ":"))
    sig3, _ = sign_payload(global_mismatch_secret, payload3_str)

    client.post(
        "/api/v1/mock-receiver/webhook",
        content=payload3_str.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-EventFlow-Delivery-Id": synthetic_id,
            "X-EventFlow-Signature": sig3,
        },
    )
    logs = client.get("/api/v1/mock-receiver/logs").json()
    log3 = next((l for l in logs if l.get("delivery_id") == synthetic_id), None)
    assert log3 is not None
    assert log3["signature_valid"] is True, "Standalone unknown delivery falls back to configured global mock secret"


def test_mock_receiver_does_not_modify_existing_endpoint_secret(client, db_session):
    """
    Verify that updating mock receiver configuration (including mock secrets, delays, and statuses)
    never modifies or resets existing endpoint signing secrets in the database.
    """
    from app.models.endpoint import Endpoint

    original_secret = "whsec_persistent_endpoint_secret_abcdef123456"
    ep = Endpoint(
        url="http://backend:8000/api/v1/mock-receiver/webhook",
        secret=original_secret,
        is_active=True,
        event_types=["*"],
    )
    db_session.add(ep)
    db_session.commit()
    ep_id = ep.id

    # Perform various mock receiver operations
    client.post("/api/v1/mock-receiver/config", json={"status_code": 500, "delay_seconds": 2.0})
    client.post("/api/v1/mock-receiver/config", json={"signing_secret": "whsec_different_mock_secret"})
    client.post("/api/v1/mock-receiver/config", json={"status_code": 200, "signing_secret": None})

    # Query endpoint from database and verify secret is untouched
    db_session.expire_all()
    queried_ep = db_session.query(Endpoint).filter(Endpoint.id == ep_id).first()
    assert queried_ep is not None
    assert queried_ep.secret == original_secret, "Endpoint secret must remain strictly unchanged"
