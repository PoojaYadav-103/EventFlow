import json
import time
import pytest
from app.core.security import sign_payload
from app.api.v1.mock_receiver import reset_replay_store_for_testing


@pytest.fixture(autouse=True)
def clean_mock_receiver(client):
    """Ensure complete mock receiver and replay store isolation between tests."""
    reset_replay_store_for_testing()
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "delay_seconds": 0.0, "reject_all": False, "signing_secret": None},
    )
    client.delete("/api/v1/mock-receiver/logs")
    yield
    reset_replay_store_for_testing()
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "delay_seconds": 0.0, "reject_all": False, "signing_secret": None},
    )
    client.delete("/api/v1/mock-receiver/logs")


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


def test_mock_receiver_replay_protection_lifecycle(client):
    """
    Verify replay attack protection in the mock receiver:
    1. Valid request #1 is accepted and recorded.
    2. Identical replayed request #2 (same timestamp, nonce, signature) is detected as a replay.
    3. Legitimate Module 2 retry with identical event/delivery ID but fresh timestamp and nonce is accepted!
    """
    from app.api.v1.mock_receiver import _replay_store
    _replay_store.clear()
    client.delete("/api/v1/mock-receiver/logs")

    test_secret = "whsec_replay_protection_test_secret_777"
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": test_secret},
    )

    payload_data = {"order_id": "ord_replay_test", "amount": 99.95}
    payload_bytes = json.dumps(payload_data, separators=(",", ":")).encode("utf-8")

    # Attempt 1: Initial delivery
    sig1, ts1 = sign_payload(test_secret, payload_bytes)
    resp1 = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={
            "Content-Type": "application/json",
            "X-EventFlow-Delivery-Id": "del_replay_1",
            "X-EventFlow-Event-Id": "ev_replay_1",
            "X-EventFlow-Signature": sig1,
            "X-EventFlow-Timestamp": str(ts1),
        },
        content=payload_bytes,
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["signature_valid"] is True
    assert data1.get("replay_detected") is False

    # Attempt 2: Replay of exact identical request (intercepted replay attack)
    resp2 = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={
            "Content-Type": "application/json",
            "X-EventFlow-Delivery-Id": "del_replay_1",
            "X-EventFlow-Event-Id": "ev_replay_1",
            "X-EventFlow-Signature": sig1,
            "X-EventFlow-Timestamp": str(ts1),
        },
        content=payload_bytes,
    )
    # Explicit HTTP 409 Conflict rejection for detected replays
    assert resp2.status_code == 409
    data2 = resp2.json()
    assert data2["signature_valid"] is False, "Replayed signature must be rejected"
    assert data2.get("replay_detected") is True, "Replay must be flagged"

    # Attempt 3: Legitimate Module 2 retry (same event_id & delivery_id, but fresh nonce & timestamp)
    sig3, ts3 = sign_payload(test_secret, payload_bytes)
    assert sig3 != sig1, "Fresh attempt must produce a distinct signature"

    resp3 = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={
            "Content-Type": "application/json",
            "X-EventFlow-Delivery-Id": "del_replay_1",
            "X-EventFlow-Event-Id": "ev_replay_1",
            "X-EventFlow-Signature": sig3,
            "X-EventFlow-Timestamp": str(ts3),
        },
        content=payload_bytes,
    )
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert data3["signature_valid"] is True, "Legitimate retry with fresh nonce must be accepted"
    assert data3.get("replay_detected") is False


def test_in_memory_replay_store_unit():
    """Unit tests for InMemoryReplayStore parameter validation, fail-closed capacity, and TTL purge."""
    from app.api.v1.mock_receiver import InMemoryReplayStore, ReplayRecordResult
    import pytest

    # 1. Parameter validation: reject booleans, zero, negative, or invalid types
    with pytest.raises(ValueError):
        InMemoryReplayStore(max_entries=0)

    with pytest.raises(ValueError):
        InMemoryReplayStore(max_entries=-10)

    with pytest.raises(ValueError):
        InMemoryReplayStore(max_entries=True)

    with pytest.raises(ValueError):
        InMemoryReplayStore(default_ttl_seconds=0)

    with pytest.raises(ValueError):
        InMemoryReplayStore(default_ttl_seconds=True)

    with pytest.raises(ValueError):
        InMemoryReplayStore(default_ttl_seconds=100000)

    # 2. Fail-closed policy: never evict unexpired entries when capacity is reached
    store = InMemoryReplayStore(max_entries=3, default_ttl_seconds=300)
    assert store.check_and_record("sig_1") == ReplayRecordResult.ACCEPTED
    assert store.check_and_record("sig_2") == ReplayRecordResult.ACCEPTED
    assert store.check_and_record("sig_3") == ReplayRecordResult.ACCEPTED

    # Replay of existing keys
    assert store.check_and_record("sig_1") == ReplayRecordResult.REPLAY_DETECTED
    assert store.check_and_record("sig_2") == ReplayRecordResult.REPLAY_DETECTED

    # Adding a 4th key when capacity is full fails closed: CAPACITY_EXHAUSTED
    assert store.check_and_record("sig_4") == ReplayRecordResult.CAPACITY_EXHAUSTED

    # Existing entries are strictly preserved and still detected as replays
    assert store.check_and_record("sig_1") == ReplayRecordResult.REPLAY_DETECTED
    assert store.check_and_record("sig_3") == ReplayRecordResult.REPLAY_DETECTED

    # 3. Active purge of expired entries restores capacity
    short_store = InMemoryReplayStore(max_entries=2, default_ttl_seconds=0.01)
    assert short_store.check_and_record("quick_1", ttl=0.001) == ReplayRecordResult.ACCEPTED
    assert short_store.check_and_record("quick_2", ttl=300) == ReplayRecordResult.ACCEPTED
    # Full
    assert short_store.check_and_record("quick_3", ttl=300) == ReplayRecordResult.CAPACITY_EXHAUSTED

    # Wait for quick_1 to expire
    time.sleep(0.01)

    # Expired entry is purged, restoring a capacity slot
    assert short_store.check_and_record("quick_3", ttl=300) == ReplayRecordResult.ACCEPTED


def test_invalid_hmac_requests_never_enter_replay_cache(client):
    """Verify that unauthenticated or invalid HMAC requests never consume replay store capacity."""
    from app.api.v1.mock_receiver import _replay_store, reset_replay_store_for_testing
    reset_replay_store_for_testing()

    test_secret = "whsec_invalid_hmac_cache_test_123"
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": test_secret},
    )

    bad_sig = "t=1731300000,n=0123456789abcdef0123456789abcdef,v1=" + "a" * 64
    resp = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={"X-EventFlow-Signature": bad_sig},
        content=b'{"order":1}',
    )
    # Explicit 401 Unauthorized
    assert resp.status_code == 401

    # Verify nothing was added to replay store
    assert len(_replay_store._entries) == 0


def test_clearing_mock_logs_does_not_clear_replay_state(client):
    """Verify that deleting mock logs does NOT clear or weaken the replay store."""
    from app.api.v1.mock_receiver import reset_replay_store_for_testing
    reset_replay_store_for_testing()
    client.delete("/api/v1/mock-receiver/logs")

    test_secret = "whsec_log_clearing_isolation_secret"
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": test_secret},
    )

    payload_bytes = b'{"msg":"hello"}'
    sig, ts = sign_payload(test_secret, payload_bytes)

    # First request succeeds
    resp1 = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={"X-EventFlow-Signature": sig, "X-EventFlow-Timestamp": str(ts)},
        content=payload_bytes,
    )
    assert resp1.status_code == 200

    # User clears mock logs via DELETE /api/v1/mock-receiver/logs
    del_resp = client.delete("/api/v1/mock-receiver/logs")
    assert del_resp.status_code == 204
    assert len(client.get("/api/v1/mock-receiver/logs").json()) == 0

    # Re-sending the exact same signature must STILL be rejected as a replay!
    resp2 = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={"X-EventFlow-Signature": sig, "X-EventFlow-Timestamp": str(ts)},
        content=payload_bytes,
    )
    assert resp2.status_code == 409, "Clearing logs must not weaken replay detection"


def test_mock_receiver_cache_capacity_exhaustion_fails_closed(client, monkeypatch):
    """Verify that when replay cache capacity is exhausted, new requests fail closed with HTTP 503."""
    from app.api.v1.mock_receiver import InMemoryReplayStore, reset_replay_store_for_testing
    import app.api.v1.mock_receiver as mock_module

    # Inject small capacity store
    tiny_store = InMemoryReplayStore(max_entries=2, default_ttl_seconds=300)
    monkeypatch.setattr(mock_module, "_replay_store", tiny_store)

    test_secret = "whsec_capacity_fail_closed_test"
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": test_secret},
    )

    # Request 1: succeeds
    p1 = b'{"r":1}'
    s1, _ = sign_payload(test_secret, p1)
    assert client.post("/api/v1/mock-receiver/webhook", headers={"X-EventFlow-Signature": s1}, content=p1).status_code == 200

    # Request 2: succeeds
    p2 = b'{"r":2}'
    s2, _ = sign_payload(test_secret, p2)
    assert client.post("/api/v1/mock-receiver/webhook", headers={"X-EventFlow-Signature": s2}, content=p2).status_code == 200

    # Request 3: capacity exhausted -> fails closed with HTTP 503 Service Unavailable
    p3 = b'{"r":3}'
    s3, _ = sign_payload(test_secret, p3)
    resp3 = client.post("/api/v1/mock-receiver/webhook", headers={"X-EventFlow-Signature": s3}, content=p3)
    assert resp3.status_code == 503
    assert resp3.json()["error"] == "Replay cache capacity exhausted"


def test_concurrent_identical_requests_only_one_accepted(client):
    """Verify that when concurrent identical requests arrive, thread-safe locking accepts exactly one."""
    import concurrent.futures
    from app.api.v1.mock_receiver import reset_replay_store_for_testing
    reset_replay_store_for_testing()

    test_secret = "whsec_concurrency_test_secret"
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": test_secret},
    )

    payload_bytes = b'{"concurrent":true}'
    sig, ts = sign_payload(test_secret, payload_bytes)
    headers = {"X-EventFlow-Signature": sig, "X-EventFlow-Timestamp": str(ts)}

    def send_request():
        return client.post("/api/v1/mock-receiver/webhook", headers=headers, content=payload_bytes).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(send_request) for _ in range(5)]
        status_codes = [f.result() for f in futures]

    # Exactly ONE must succeed (200 OK); all other 4 must be rejected with 409 Conflict
    assert status_codes.count(200) == 1
    assert status_codes.count(409) == 4


def test_replay_store_ttl_argument_validation():
    """Verify check_and_record rejects boolean, non-numeric, NaN, inf, zero, and negative TTLs before float conversion."""
    from app.api.v1.mock_receiver import InMemoryReplayStore
    store = InMemoryReplayStore(max_entries=10, default_ttl_seconds=300)

    invalid_ttls = [
        True,
        False,
        "10",
        "10.5",
        object(),
        float("nan"),
        float("inf"),
        float("-inf"),
        0,
        0.0,
        -1,
        -0.01,
    ]
    for bad_ttl in invalid_ttls:
        with pytest.raises(ValueError):
            store.check_and_record("test_key", ttl=bad_ttl)

    assert len(store._entries) == 0


def test_mock_receiver_rejects_empty_auxiliary_timestamp_header(client):
    """Verify that supplying an empty or whitespace-only X-EventFlow-Timestamp header is rejected with 401."""
    from app.api.v1.mock_receiver import _replay_store

    test_secret = "whsec_empty_aux_ts_secret"
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": test_secret},
    )

    payload_bytes = b'{"event":"aux_test"}'
    sig, _ = sign_payload(test_secret, payload_bytes)

    for bad_aux in ("", "   ", "\t"):
        resp = client.post(
            "/api/v1/mock-receiver/webhook",
            headers={
                "X-EventFlow-Signature": sig,
                "X-EventFlow-Timestamp": bad_aux,
            },
            content=payload_bytes,
        )
        assert resp.status_code == 401
        assert resp.json()["signature_valid"] is False

    assert len(_replay_store._entries) == 0


def test_mock_receiver_non_positive_remaining_validity_rejected_and_subsecond_ttl_exact(client, monkeypatch):
    """
    Verify that:
    1. When remaining signature validity is <= 0 (e.g. sub-second boundary past tolerance),
       recording is rejected (401) and nothing enters the replay cache.
    2. When remaining signature validity is positive and < 1.0s, exact remaining validity is used
       without artificially extending to max(1.0, ...).
    """
    from types import SimpleNamespace
    import app.api.v1.mock_receiver as mock_module
    import app.core.security as security_module

    test_secret = "whsec_remaining_validity_test"
    client.post(
        "/api/v1/mock-receiver/config",
        json={"status_code": 200, "signing_secret": test_secret},
    )

    base_ts = 1700000000
    payload_bytes = b'{"boundary":true}'
    sig, _ = sign_payload(test_secret, payload_bytes, timestamp=base_ts)

    # Case 1: time = 1700000300.5 -> int(time) - base_ts == 300 (passes integer tolerance check),
    # remaining_validity = (1700000000 + 300) - 1700000300.5 = -0.5 <= 0 -> must reject recording!
    fake_clock = SimpleNamespace(time=lambda: float(base_ts + 300) + 0.5)
    monkeypatch.setattr(security_module, "time", fake_clock)
    monkeypatch.setattr(mock_module, "time", fake_clock)

    resp_neg = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={"X-EventFlow-Signature": sig},
        content=payload_bytes,
    )
    assert resp_neg.status_code == 401
    assert resp_neg.json()["signature_valid"] is False
    assert len(mock_module._replay_store._entries) == 0

    # Case 2: time = 1700000300.0 -> remaining_validity = 0.0 <= 0 -> must reject recording!
    fake_clock_zero = SimpleNamespace(time=lambda: float(base_ts + 300))
    monkeypatch.setattr(security_module, "time", fake_clock_zero)
    monkeypatch.setattr(mock_module, "time", fake_clock_zero)

    resp_zero = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={"X-EventFlow-Signature": sig},
        content=payload_bytes,
    )
    assert resp_zero.status_code == 401
    assert len(mock_module._replay_store._entries) == 0

    # Case 3: time = 1700000299.75 -> remaining_validity = 0.25s > 0 -> accepted with exact 0.25s expiration (not 1.0s)
    current_t = float(base_ts + 299) + 0.75
    fake_clock_sub = SimpleNamespace(time=lambda: current_t)
    monkeypatch.setattr(security_module, "time", fake_clock_sub)
    monkeypatch.setattr(mock_module, "time", fake_clock_sub)

    resp_ok = client.post(
        "/api/v1/mock-receiver/webhook",
        headers={"X-EventFlow-Signature": sig},
        content=payload_bytes,
    )
    assert resp_ok.status_code == 200
    assert len(mock_module._replay_store._entries) == 1
    stored_exp = next(iter(mock_module._replay_store._entries.values()))
    assert abs(stored_exp - float(base_ts + 300)) < 1e-6
