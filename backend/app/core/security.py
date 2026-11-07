import hmac
import hashlib
import secrets
import time
from typing import Tuple
from app.core.config import settings


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


def sign_payload(secret: str, payload_str: str, timestamp: int = None) -> Tuple[str, int]:
    """
    Sign a raw payload string using HMAC-SHA256.
    Returns (header_value, timestamp).
    Format of header: t={timestamp},v1={hex_digest}
    """
    if timestamp is None:
        timestamp = int(time.time())
    
    # Message format: {timestamp}.{payload}
    signed_payload = f"{timestamp}.{payload_str}".encode("utf-8")
    key = secret.encode("utf-8")
    digest = hmac.new(key, signed_payload, hashlib.sha256).hexdigest()
    
    signature_header = f"t={timestamp},v1={digest}"
    return signature_header, timestamp


def verify_signature(secret: str, payload_str: str, header_value: str, tolerance_seconds: int = 300) -> bool:
    """
    Verify an incoming signature header (t={ts},v1={digest}).
    Includes optional timestamp tolerance to prevent replay attacks.
    """
    try:
        parts = dict(item.split("=", 1) for item in header_value.split(","))
        timestamp_str = parts.get("t")
        expected_digest = parts.get("v1")
        
        if not timestamp_str or not expected_digest:
            return False
        
        timestamp = int(timestamp_str)
        now = int(time.time())
        if tolerance_seconds and abs(now - timestamp) > tolerance_seconds:
            return False
            
        signed_payload = f"{timestamp}.{payload_str}".encode("utf-8")
        actual_digest = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
        
        return hmac.compare_digest(actual_digest, expected_digest)
    except Exception:
        return False
