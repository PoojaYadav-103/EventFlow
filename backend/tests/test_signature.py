import secrets
import time
import pytest
from app.core.security import (
    generate_signing_secret,
    sign_payload,
    verify_signature,
    verify_signature_detailed,
)


def test_hmac_signature_generation_and_verification():
    """Verify webhook signatures using timestamped HMAC-SHA256 and cryptographic nonces."""
    secret = generate_signing_secret()
    payload = '{"order_id":"123","status":"confirmed"}'

    # Sign payload
    sig_header, ts = sign_payload(secret, payload)
    assert f"t={ts}," in sig_header
    assert ",n=" in sig_header
    assert ",v1=" in sig_header

    # 1. Verification succeeds with authentic secret, payload, and headers
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


def test_distinct_nonces_same_timestamp_produce_distinct_digests():
    """Verify that multiple signings in the exact same second produce unique signatures due to nonces."""
    secret = generate_signing_secret()
    payload = '{"event":"user.login"}'
    fixed_ts = 1731300000

    sig1, _ = sign_payload(secret, payload, timestamp=fixed_ts)
    sig2, _ = sign_payload(secret, payload, timestamp=fixed_ts)

    assert sig1 != sig2, "Two attempts in the same second must have distinct nonces and digests"
    assert verify_signature(secret, payload, sig1, current_time=fixed_ts) is True
    assert verify_signature(secret, payload, sig2, current_time=fixed_ts) is True


def test_tampered_nonce_rejected():
    """Verify that tampering with the nonce parameter in the header invalidates the signature."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    sig_header, ts = sign_payload(secret, payload)

    # Tamper with the nonce value
    tampered_header = sig_header.replace("n=", "n=00000000000000000000000000000000")
    if tampered_header != sig_header:
        assert verify_signature(secret, payload, tampered_header) is False


def test_tampered_timestamp_rejected():
    """Verify that tampering with the timestamp parameter in the header invalidates the signature."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    sig_header, ts = sign_payload(secret, payload)

    tampered_header = sig_header.replace(f"t={ts}", f"t={ts + 1}")
    assert verify_signature(secret, payload, tampered_header) is False


def test_missing_nonce_rejected():
    """Verify that legacy or malformed headers missing 'n=' are strictly rejected."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    now = int(time.time())
    header_without_nonce = f"t={now},v1={'a' * 64}"
    assert verify_signature(secret, payload, header_without_nonce) is False


def test_duplicate_nonce_parameter_rejected():
    """Verify that duplicate or conflicting 'n=' parameters in the header are rejected."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    now = int(time.time())
    nonce = secrets.token_hex(16)
    digest = "a" * 64
    duplicate_nonce_header = f"t={now},n={nonce},n={nonce},v1={digest}"
    assert verify_signature(secret, payload, duplicate_nonce_header) is False


def test_duplicate_timestamp_parameter_rejected():
    """Verify that duplicate or conflicting 't=' parameters in the header are rejected."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    now = int(time.time())
    nonce = secrets.token_hex(16)
    digest = "a" * 64
    duplicate_ts_header = f"t={now},t={now + 1},n={nonce},v1={digest}"
    assert verify_signature(secret, payload, duplicate_ts_header) is False


def test_malformed_timestamp_rejected():
    """Verify that non-ASCII decimal digits (negatives, decimals, scientific notation, Unicode digits) fail safely."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    nonce = secrets.token_hex(16)
    digest = "a" * 64

    malformed_timestamps = [
        "-1000",
        "123.45",
        "1e10",
        "abc",
        "\u0660\u0661\u0662",  # Arabic-Indic digits (Unicode isdigit() would be True, but ASCII is False)
        "",
    ]
    for bad_ts in malformed_timestamps:
        header = f"t={bad_ts},n={nonce},v1={digest}"
        assert verify_signature(secret, payload, header) is False


def test_expired_timestamp_rejected():
    """Verify that signatures older than tolerance_seconds are rejected."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    now = 1000000
    expired_ts = now - 301  # > 300s old
    sig_header, _ = sign_payload(secret, payload, timestamp=expired_ts)

    assert verify_signature(secret, payload, sig_header, tolerance_seconds=300, current_time=now) is False


def test_future_timestamp_rejected():
    """Verify that signatures too far in the future (> future_tolerance_seconds) are rejected."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    now = 1000000
    future_ts = now + 65  # > 60s future
    sig_header, _ = sign_payload(secret, payload, timestamp=future_ts)

    assert verify_signature(secret, payload, sig_header, future_tolerance_seconds=60, current_time=now) is False


def test_future_timestamp_within_drift_accepted():
    """Verify that small clock drift (e.g. +30s) within future_tolerance_seconds is accepted."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    now = 1000000
    future_ts = now + 30  # within 60s future drift
    sig_header, _ = sign_payload(secret, payload, timestamp=future_ts)

    assert verify_signature(secret, payload, sig_header, future_tolerance_seconds=60, current_time=now) is True


def test_auxiliary_timestamp_header_consistency():
    """Verify that X-EventFlow-Timestamp (if present) must be non-empty and match t in X-EventFlow-Signature."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    now = 1000000
    sig_header, ts = sign_payload(secret, payload, timestamp=now)

    # 1. Omitted auxiliary timestamp header (None) succeeds
    assert verify_signature(
        secret, payload, sig_header, current_time=now, auxiliary_timestamp_header=None
    ) is True

    # 2. Matching auxiliary timestamp header succeeds
    assert verify_signature(
        secret, payload, sig_header, current_time=now, auxiliary_timestamp_header=str(ts)
    ) is True

    # 3. Mismatched auxiliary timestamp header fails
    assert verify_signature(
        secret, payload, sig_header, current_time=now, auxiliary_timestamp_header=str(ts + 10)
    ) is False

    # 4. Empty or whitespace-only auxiliary timestamp header must be rejected
    for empty_val in ("", "   ", "\t\n"):
        res = verify_signature_detailed(
            secret, payload, sig_header, current_time=now, auxiliary_timestamp_header=empty_val
        )
        assert res.is_valid is False, f"Empty/whitespace auxiliary timestamp {empty_val!r} must be rejected"


def test_strict_32_hex_nonce_required():
    """Verify that nonces must be exactly 32 hexadecimal ASCII characters."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    now = 1000000
    digest = "a" * 64

    bad_nonces = [
        "short",                                # too short
        "a" * 31,                               # 31 chars
        "a" * 33,                               # 33 chars
        "g" * 32,                               # non-hex char 'g'
        "1234567890123456789012345678901!",    # special char
    ]
    for bad_nonce in bad_nonces:
        header = f"t={now},n={bad_nonce},v1={digest}"
        assert verify_signature(secret, payload, header, current_time=now) is False


def test_strict_64_hex_digest_required():
    """Verify that v1 digests must be exactly 64 hexadecimal ASCII characters."""
    secret = generate_signing_secret()
    payload = '{"item":"widget"}'
    now = 1000000
    nonce = secrets.token_hex(16)

    bad_digests = [
        "a" * 63,  # too short
        "a" * 65,  # too long
        "z" * 64,  # non-hex char
    ]
    for bad_digest in bad_digests:
        header = f"t={now},n={nonce},v1={bad_digest}"
        assert verify_signature(secret, payload, header, current_time=now) is False


def test_multi_signature_secret_rotation():
    """Verify zero-downtime secret rotation where the header contains multiple v1 digests."""
    old_secret = generate_signing_secret()
    new_secret = generate_signing_secret()
    payload = '{"event":"order.updated"}'
    now = 1000000
    nonce = secrets.token_hex(16)

    # Sign with old secret and new secret using same t and n
    sig_old, _ = sign_payload(old_secret, payload, timestamp=now, nonce=nonce)
    sig_new, _ = sign_payload(new_secret, payload, timestamp=now, nonce=nonce)

    digest_old = sig_old.split("v1=")[1]
    digest_new = sig_new.split("v1=")[1]

    # Combine both signatures into one header
    multi_header = f"t={now},n={nonce},v1={digest_old},v1={digest_new}"

    # Verifying with old secret succeeds and identifies matched_digest
    res_old = verify_signature_detailed(old_secret, payload, multi_header, current_time=now)
    assert res_old.is_valid is True
    assert res_old.matched_digest == digest_old

    # Verifying with new secret succeeds and identifies matched_digest
    res_new = verify_signature_detailed(new_secret, payload, multi_header, current_time=now)
    assert res_new.is_valid is True
    assert res_new.matched_digest == digest_new

    # Verifying with unrelated secret fails
    other_secret = generate_signing_secret()
    res_other = verify_signature_detailed(other_secret, payload, multi_header, current_time=now)
    assert res_other.is_valid is False


def test_negative_tolerance_raises_value_error():
    """Verify tolerance_seconds requires > 0 and future_tolerance_seconds requires >= 0."""
    secret = generate_signing_secret()
    payload = "payload"
    now = 1000000
    sig, _ = sign_payload(secret, payload, timestamp=now)

    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, tolerance_seconds=0, current_time=now)

    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, tolerance_seconds=-1, current_time=now)

    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, future_tolerance_seconds=-5, current_time=now)

    # future_tolerance_seconds == 0 must remain valid
    assert verify_signature(secret, payload, sig, future_tolerance_seconds=0, current_time=now) is True


def test_raw_bytes_and_string_consistency():
    """Verify that signing raw bytes and verifying raw bytes match perfectly."""
    secret = generate_signing_secret()
    raw_payload_bytes = '{"unicode":"🔒_webhook_🚀"}'.encode("utf-8")

    sig_header, ts = sign_payload(secret, raw_payload_bytes)
    assert verify_signature(secret, raw_payload_bytes, sig_header) is True


def test_supplied_invalid_nonce_rejection():
    """Verify that sign_payload strictly validates caller-supplied nonces and rejects invalid values."""
    secret = generate_signing_secret()
    payload = "payload"

    # Non-string
    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce=12345)

    # Boolean
    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce=True)

    # Wrong length
    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce="abc")

    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce="a" * 31)

    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce="a" * 33)

    # Non-hex characters
    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce="g" * 32)

    # Whitespace padding must not be stripped; must be rejected strictly
    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce=" " + ("a" * 32))

    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce=("a" * 32) + " ")

    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce=" " + ("a" * 31))

    with pytest.raises(ValueError):
        sign_payload(secret, payload, nonce="\t" + ("a" * 32) + "\n")


def test_boolean_and_non_integer_tolerance_rejection():
    """Verify that verify_signature strictly rejects boolean, float, or string tolerance values."""
    secret = generate_signing_secret()
    payload = "payload"
    sig, _ = sign_payload(secret, payload)

    # Boolean tolerance (in Python, isinstance(True, int) is True, must be rejected!)
    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, tolerance_seconds=True)

    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, tolerance_seconds=False)

    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, tolerance_seconds=1.5)

    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, future_tolerance_seconds=True)

    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, future_tolerance_seconds=2.5)

    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, current_time=True)

    with pytest.raises(ValueError):
        verify_signature(secret, payload, sig, current_time=-1)

    with pytest.raises(ValueError):
        sign_payload(secret, payload, timestamp=True)

    with pytest.raises(ValueError):
        sign_payload(secret, payload, timestamp=-1)


def test_empty_signature_header_elements_and_trailing_commas():
    """Verify that headers with trailing commas, leading commas, or empty elements fail safely."""
    secret = generate_signing_secret()
    payload = "payload"
    sig, _ = sign_payload(secret, payload)

    # Trailing comma
    assert verify_signature(secret, payload, f"{sig},") is False

    # Leading comma
    assert verify_signature(secret, payload, f",{sig}") is False

    # Empty comma-separated element
    parts = sig.split(",")
    empty_elem_header = f"{parts[0]},,{parts[1]},{parts[2]}"
    assert verify_signature(secret, payload, empty_elem_header) is False

    # Empty key or value
    assert verify_signature(secret, payload, f"t=,n={'a'*32},v1={'b'*64}") is False
    assert verify_signature(secret, payload, f"=12345,n={'a'*32},v1={'b'*64}") is False


def test_excessively_long_timestamps():
    """Verify that excessively long timestamp strings are rejected before integer conversion."""
    secret = generate_signing_secret()
    payload = "payload"
    nonce = secrets.token_hex(16)
    digest = "a" * 64

    # 17 digits (> 16 digits limit)
    long_ts_header = f"t=12345678901234567,n={nonce},v1={digest}"
    assert verify_signature(secret, payload, long_ts_header) is False

    # 100 digits (large integer DoS attempt)
    huge_ts_header = f"t={'9' * 100},n={nonce},v1={digest}"
    assert verify_signature(secret, payload, huge_ts_header) is False


def test_config_validation_rejects_invalid_types_and_booleans():
    """Verify that Settings validation rejects booleans and invalid values for signature tolerances."""
    from pydantic import ValidationError
    from app.core.config import Settings

    # Booleans rejected
    with pytest.raises(ValidationError):
        Settings(SIGNATURE_TOLERANCE_SECONDS=True)

    with pytest.raises(ValidationError):
        Settings(SIGNATURE_FUTURE_TOLERANCE_SECONDS=False)

    # Negative / zero values rejected
    with pytest.raises(ValidationError):
        Settings(SIGNATURE_TOLERANCE_SECONDS=0)

    with pytest.raises(ValidationError):
        Settings(SIGNATURE_TOLERANCE_SECONDS=-300)

    with pytest.raises(ValidationError):
        Settings(SIGNATURE_FUTURE_TOLERANCE_SECONDS=-60)
