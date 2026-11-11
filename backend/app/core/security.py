import hmac
import hashlib
import secrets
import time
from typing import Tuple, Optional, Union, List
from app.core.config import settings

ASCII_DIGITS = set("0123456789")
HEX_CHARS = set("0123456789abcdefABCDEF")


def generate_signing_secret() -> str:
    """Generate a cryptographically secure webhook signing secret."""
    raw = secrets.token_urlsafe(32)
    return f"{settings.SIGNING_SECRET_PREFIX}{raw}"


def mask_secret(secret: str) -> str:
    """Mask a secret for safe display in listings."""
    if not secret:
        return ""
    if len(secret) <= 10:
        return "whsec_••••"
    return f"{secret[:9]}••••••••{secret[-4:]}"


def sign_payload(
    secret: str,
    payload: Optional[Union[str, bytes]] = None,
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
    payload_str: Optional[Union[str, bytes]] = None,
) -> Tuple[str, int]:
    """
    Sign a raw payload (bytes or str) using HMAC-SHA256 with Unix timestamp and per-attempt nonce.
    Supports either 'payload' or legacy 'payload_str' keyword arguments.
    Returns (signature_header, timestamp).
    Format of header: t={timestamp},n={nonce},v1={hex_digest}
    Canonical message: {timestamp}.{nonce}.{payload_bytes}
    """
    if timestamp is not None:
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
            raise ValueError("timestamp must be a non-negative integer.")
    else:
        timestamp = int(time.time())

    if nonce is not None:
        if isinstance(nonce, bool) or not isinstance(nonce, str):
            raise ValueError("Caller-supplied nonce must be a string of exactly 32 hexadecimal ASCII characters.")
        if len(nonce) != 32 or not all(c in HEX_CHARS for c in nonce):
            raise ValueError(f"Caller-supplied nonce must be exactly 32 hexadecimal ASCII characters (got {len(nonce)} chars).")
        nonce = nonce.lower()
    else:
        nonce = secrets.token_hex(16)  # Exactly 32 hexadecimal ASCII characters

    raw_val = payload if payload is not None else payload_str
    if raw_val is None:
        raw_val = ""
    payload_bytes = raw_val if isinstance(raw_val, bytes) else str(raw_val).encode("utf-8")

    canonical_message = f"{timestamp}.{nonce}.".encode("ascii") + payload_bytes
    key = secret.encode("utf-8")
    digest = hmac.new(key, canonical_message, hashlib.sha256).hexdigest().lower()

    signature_header = f"t={timestamp},n={nonce},v1={digest}"
    return signature_header, timestamp


class SignatureVerificationResult:
    """
    Structured outcome of signature verification, exposing validity, the exact matched v1 digest,
    the parsed timestamp, and the nonce for precise replay-store recording.
    """
    def __init__(
        self,
        is_valid: bool,
        matched_digest: Optional[str] = None,
        timestamp: Optional[int] = None,
        nonce: Optional[str] = None,
        error_message: Optional[str] = None,
    ):
        self.is_valid = is_valid
        self.matched_digest = matched_digest
        self.timestamp = timestamp
        self.nonce = nonce
        self.error_message = error_message

    def __bool__(self) -> bool:
        return self.is_valid


def verify_signature_detailed(
    secret: str,
    payload: Optional[Union[str, bytes]] = None,
    header_value: str = "",
    tolerance_seconds: int = 300,
    future_tolerance_seconds: int = 60,
    current_time: Optional[int] = None,
    auxiliary_timestamp_header: Optional[str] = None,
    payload_str: Optional[Union[str, bytes]] = None,
) -> SignatureVerificationResult:
    """
    Strict cryptographic verification of X-EventFlow-Signature header.
    Returns SignatureVerificationResult with is_valid, matched_digest, timestamp, and nonce.
    Supports either 'payload' or legacy 'payload_str' keyword arguments.
    """
    if isinstance(tolerance_seconds, bool) or not isinstance(tolerance_seconds, int) or tolerance_seconds <= 0:
        raise ValueError("tolerance_seconds must be a positive integer > 0.")

    if isinstance(future_tolerance_seconds, bool) or not isinstance(future_tolerance_seconds, int) or future_tolerance_seconds < 0:
        raise ValueError("future_tolerance_seconds must be a non-negative integer >= 0.")

    if current_time is not None and (isinstance(current_time, bool) or not isinstance(current_time, int) or current_time < 0):
        raise ValueError("current_time must be a non-negative integer.")

    if not header_value or not secret:
        return SignatureVerificationResult(False, error_message="Missing secret or signature header")

    raw_val = payload if payload is not None else payload_str
    if raw_val is None:
        raw_val = ""
    payload_bytes = raw_val if isinstance(raw_val, bytes) else str(raw_val).encode("utf-8")

    # Reject malformed header strings with leading or trailing commas
    raw_header_str = header_value.strip()
    if raw_header_str.startswith(",") or raw_header_str.endswith(","):
        return SignatureVerificationResult(False, error_message="Malformed signature header: contains leading or trailing comma")

    # Strict element parsing
    timestamps: List[str] = []
    nonces: List[str] = []
    v1_digests: List[str] = []

    parts = header_value.split(",")
    for item in parts:
        trimmed = item.strip()
        # Reject empty comma-separated elements (e.g. "t=1,,n=2")
        if not trimmed:
            return SignatureVerificationResult(False, error_message="Malformed signature header: contains empty comma-separated element")
        if "=" not in trimmed:
            return SignatureVerificationResult(False, error_message="Malformed item: missing '=' delimiter")
        k, v = trimmed.split("=", 1)
        k, v = k.strip(), v.strip()

        if not k or not v:
            return SignatureVerificationResult(False, error_message="Malformed item: empty key or value")

        if k == "t":
            timestamps.append(v)
        elif k == "n":
            nonces.append(v)
        elif k == "v1":
            v1_digests.append(v)
        else:
            # Reject unsupported or malformed parameter keys
            return SignatureVerificationResult(False, error_message=f"Unsupported signature parameter: {k}")

    # Exactly ONE timestamp and ONE nonce must be present
    if len(timestamps) != 1:
        return SignatureVerificationResult(False, error_message=f"Expected exactly 1 timestamp parameter, found {len(timestamps)}")
    if len(nonces) != 1:
        return SignatureVerificationResult(False, error_message=f"Expected exactly 1 nonce parameter, found {len(nonces)}")
    if not v1_digests:
        return SignatureVerificationResult(False, error_message="Missing v1 digest parameter")

    # Strict ASCII decimal digit validation for timestamp (and length limit to prevent DoS)
    t_str = timestamps[0]
    if not t_str or len(t_str) > 16 or not all(c in ASCII_DIGITS for c in t_str):
        return SignatureVerificationResult(False, error_message="Malformed timestamp: must be non-empty ASCII decimal digits under 16 digits")
    timestamp = int(t_str)

    # Cross-check auxiliary X-EventFlow-Timestamp header if present
    if auxiliary_timestamp_header is not None:
        aux_trimmed = str(auxiliary_timestamp_header).strip()
        if not aux_trimmed or aux_trimmed != t_str:
            return SignatureVerificationResult(
                False,
                error_message="Auxiliary timestamp header is empty or does not match signature timestamp",
            )

    # Strict ASCII hex validation for nonce (exactly 32 hex chars)
    nonce_val = nonces[0]
    if len(nonce_val) != 32 or not all(c in HEX_CHARS for c in nonce_val):
        return SignatureVerificationResult(False, error_message="Malformed nonce: must be exactly 32 hexadecimal ASCII characters")
    nonce_val = nonce_val.lower()

    # Strict ASCII hex validation for v1 digests (exactly 64 hex chars)
    valid_candidates = []
    for d in v1_digests:
        if len(d) != 64 or not all(c in HEX_CHARS for c in d):
            return SignatureVerificationResult(False, error_message="Malformed v1 digest: must be exactly 64 hexadecimal characters")
        valid_candidates.append(d.lower())

    # Timestamp freshness and clock skew validation
    now = int(time.time()) if current_time is None else current_time
    if (now - timestamp) > tolerance_seconds:
        return SignatureVerificationResult(False, error_message="Signature timestamp expired")
    if (timestamp - now) > future_tolerance_seconds:
        return SignatureVerificationResult(False, error_message="Signature timestamp too far in the future")

    # Constant-time HMAC comparison
    canonical_message = f"{timestamp}.{nonce_val}.".encode("ascii") + payload_bytes
    key = secret.encode("utf-8")
    expected_digest = hmac.new(key, canonical_message, hashlib.sha256).hexdigest().lower()

    for candidate in valid_candidates:
        if hmac.compare_digest(expected_digest, candidate):
            return SignatureVerificationResult(
                is_valid=True,
                matched_digest=candidate,
                timestamp=timestamp,
                nonce=nonce_val,
            )

    return SignatureVerificationResult(False, error_message="HMAC signature mismatch")


def verify_signature(
    secret: str,
    payload: Optional[Union[str, bytes]] = None,
    header_value: str = "",
    tolerance_seconds: int = 300,
    future_tolerance_seconds: int = 60,
    current_time: Optional[int] = None,
    auxiliary_timestamp_header: Optional[str] = None,
    payload_str: Optional[Union[str, bytes]] = None,
) -> bool:
    """
    Verify an incoming signature header (t={ts},n={nonce},v1={digest}).
    Returns boolean True if valid, False otherwise.
    Supports either 'payload' or legacy 'payload_str' keyword arguments.
    """
    try:
        res = verify_signature_detailed(
            secret=secret,
            payload=payload,
            header_value=header_value,
            tolerance_seconds=tolerance_seconds,
            future_tolerance_seconds=future_tolerance_seconds,
            current_time=current_time,
            auxiliary_timestamp_header=auxiliary_timestamp_header,
            payload_str=payload_str,
        )
        return res.is_valid
    except ValueError:
        raise
    except Exception:
        return False
