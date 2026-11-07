import urllib.request
import json
import time

def verify_live():
    base = "http://localhost:8000/api/v1"

    # 1. Clear any prior mock receiver logs
    req = urllib.request.Request(f"{base}/mock-receiver/logs", method="DELETE")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 204

    # 2. Register endpoint with Docker container destination
    ep_payload = json.dumps({
        "url": "http://backend:8000/api/v1/mock-receiver/webhook",
        "description": "Live Docker Verification Endpoint",
        "event_types": ["order.created"]
    }).encode("utf-8")
    req = urllib.request.Request(f"{base}/endpoints", data=ep_payload, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        ep_data = json.loads(resp.read().decode("utf-8"))
    print(f"[1] Endpoint registered: ID={ep_data['id']}, URL={ep_data['url']}")

    # 3. Publish domain event
    ev_payload = json.dumps({
        "event_type": "order.created",
        "payload": {"order_id": "docker_live_001", "amount": 99.99},
        "idempotency_key": f"live_idemp_{int(time.time())}"
    }).encode("utf-8")
    req = urllib.request.Request(f"{base}/events", data=ev_payload, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        ev_data = json.loads(resp.read().decode("utf-8"))
    print(f"[2] Event published to Transactional Outbox: ID={ev_data['id']}, Deliveries created={ev_data['deliveries_count']}")

    # 4. Wait for scheduled outbox sweeper (Celery Beat) and background worker
    print("[3] Waiting 4 seconds for independent Celery Beat outbox sweep + Celery worker execution...")
    time.sleep(4.0)

    # 5. Check delivery record status
    with urllib.request.urlopen(f"{base}/deliveries?event_id={ev_data['id']}") as resp:
        deliveries = json.loads(resp.read().decode("utf-8"))
    assert len(deliveries) > 0, "Delivery record must exist"
    deliv = deliveries[0]
    print(f"[4] Delivery status: {deliv['status']}, Attempt count: {deliv['attempt_count']}, HTTP status: {deliv['last_http_status']}")

    # 6. Check mock receiver received logs and genuine HMAC verification
    with urllib.request.urlopen(f"{base}/mock-receiver/logs") as resp:
        logs = json.loads(resp.read().decode("utf-8"))
    assert len(logs) > 0, "Mock receiver must have received the webhook"
    latest = logs[0]
    print(f"[5] Mock receiver received event: {latest['event_id']}")
    print(f" -> Delivery ID match: {latest['delivery_id'] == deliv['id']}")
    print(f" -> Cryptographic HMAC Signature Valid: {latest['signature_valid']}")
    print(f" -> Signature header: {latest['signature_header']}")

    # 7. Check Dashboard statistics
    with urllib.request.urlopen(f"{base}/dashboard/stats") as resp:
        stats = json.loads(resp.read().decode("utf-8"))
    print(f"[6] Dashboard metrics: Success Rate={stats['success_rate']}%, Successful={stats['successful_deliveries']}, Pending={stats['pending_deliveries']}")

    assert deliv['status'] == "SUCCESS", f"Expected SUCCESS, got {deliv['status']}"
    assert latest['signature_valid'] is True, "Cryptographic HMAC signature must be valid"
    print("\n>>> LIVE DOCKER STACK VERIFICATION PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    verify_live()

