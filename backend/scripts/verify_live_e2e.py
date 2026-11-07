import json
import time
import urllib.request
import urllib.error

BASE_URL = "http://localhost:8000"


def http_post(endpoint, data):
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def http_get(endpoint):
    req = urllib.request.Request(f"{BASE_URL}{endpoint}")
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def main():
    print("=== LIVE END-TO-END VERIFICATION (MODULE 2) ===")

    # 1. Configure Mock Receiver for HTTP 429 simulation with delay
    status, conf_resp = http_post("/api/v1/mock-receiver/config", {
        "status_code": 429,
        "delay_seconds": 0,
        "reject_all": False
    })
    print(f"1. Mock receiver configured: status={status}, config={conf_resp}")

    # 2. Register endpoint pointing to mock receiver
    status, ep_resp = http_post("/api/v1/endpoints", {
        "url": "http://backend:8000/api/v1/mock-receiver/webhook",
        "description": "Module 2 E2E Verification Receiver",
        "event_types": ["reliability.test"]
    })
    ep_id = ep_resp["id"]
    print(f"2. Registered endpoint: {ep_id}")

    # 3. Publish test event
    status, ev_resp = http_post("/api/v1/events", {
        "event_type": "reliability.test",
        "payload": {"check": "module_2_reliability", "timestamp": time.time()}
    })
    ev_id = ev_resp["id"]
    print(f"3. Published event: {ev_id}")

    # 4. Wait for Outbox Relay and Celery worker (2-4 seconds)
    print("4. Waiting for Outbox Relay and Worker execution...")
    time.sleep(4)

    # 5. Check delivery status
    status, delivs = http_get(f"/api/v1/deliveries?event_id={ev_id}")
    assert len(delivs) > 0, "No delivery record created!"
    delivery = delivs[0]
    deliv_id = delivery["id"]
    print(f"5. Delivery record created: id={deliv_id}, status={delivery['status']}, attempt_count={delivery['attempt_count']}")

    # 6. Inspect delivery details and attempt execution
    status, detail = http_get(f"/api/v1/deliveries/{deliv_id}")
    print(f"6. Delivery status={detail['status']}, next_retry_at={detail['next_retry_at']}")
    print(f"   Attempts recorded: {len(detail['attempts'])}")
    for att in detail["attempts"]:
        print(f"   - Attempt #{att['attempt_number']}: status={att['status']}, http_status={att['http_status']}")

    assert detail["status"] == "RETRYING", f"Expected RETRYING, got {detail['status']}"
    assert detail["attempt_count"] == 1
    assert len(detail["attempts"]) == 1
    assert detail["attempts"][0]["attempt_number"] == 1
    assert detail["attempts"][0]["http_status"] == 429

    # 7. Test manual retry rejection (409 Conflict while in RETRYING)
    print("7. Testing manual retry rejection while in RETRYING...")
    req_retry = urllib.request.Request(
        f"{BASE_URL}/api/v1/deliveries/{deliv_id}/retry",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req_retry)
        raise AssertionError("Manual retry should have been rejected with 409!")
    except urllib.error.HTTPError as e:
        assert e.code == 409, f"Expected HTTP 409, got {e.code}"
        err_body = json.loads(e.read().decode())
        print(f"   Received expected 409 Conflict: {err_body['detail']}")

    # 8. Reset mock receiver to 200 OK
    http_post("/api/v1/mock-receiver/config", {
        "status_code": 200,
        "delay_seconds": 0,
        "reject_all": False
    })
    print("8. Reset mock receiver to 200 OK.")

    print("\n>>> ALL LIVE VERIFICATION CHECKS PASSED SUCCESSFULLY! <<<")


if __name__ == "__main__":
    main()
