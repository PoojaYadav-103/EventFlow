import time
import pytest
from app.core.security import generate_signing_secret, sign_payload, verify_signature


def test_hmac_signature_generation_and_verification():
    """Scenario 8: Verify webhook signatures using HMAC-SHA256."""
    secret = generate_signing_secret()
    payload = '{"order_id":"123","status":"confirmed"}'
    
    # Sign payload
    sig_header, ts = sign_payload(secret, payload)
    assert sig_header.startswith(f"t={ts},v1=")
    
    # 1. Verification succeeds with authentic secret and payload
    assert verify_signature(secret, payload, sig_header) is True

    # 2. Verification fails when payload is tampered
    tampered_payload = '{"order_id":"123","status":"cancelled"}'
    assert verify_signature(secret, tampered_payload, sig_header) is False

    # 3. Verification fails when wrong secret is used
    wrong_secret = generate_signing_secret()
    assert verify_signature(wrong_secret, payload, sig_header) is False

    # 4. Verification fails when timestamp is outside tolerance (replay protection)
    old_timestamp = int(time.time()) - 1000
    old_sig_header, _ = sign_payload(secret, payload, timestamp=old_timestamp)
    assert verify_signature(secret, payload, old_sig_header, tolerance_seconds=300) is False
