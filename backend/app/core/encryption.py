import os
import base64
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


class EncryptionError(Exception):
    """Base exception for cryptographic operations in EventFlow."""
    pass


class MissingEncryptionKeyError(EncryptionError):
    """Raised when the ENCRYPTION_KEY environment configuration is missing or empty."""
    pass


class InvalidEncryptionKeyError(EncryptionError):
    """Raised when the provided ENCRYPTION_KEY is malformed or invalid for Fernet."""
    pass


class DecryptionError(EncryptionError):
    """Raised when decrypting ciphertext fails due to corrupted tokens or key mismatch."""
    pass


def get_encryption_key() -> str:
    """
    Retrieves the raw ENCRYPTION_KEY from settings or OS environment.
    Never logs the key.
    """
    key = settings.ENCRYPTION_KEY or os.environ.get("ENCRYPTION_KEY")
    if not key or not str(key).strip():
        raise MissingEncryptionKeyError(
            "ENCRYPTION_KEY environment configuration is missing or empty. "
            "A valid 32-byte URL-safe base64 Fernet key is required for secret encryption at rest."
        )
    return str(key).strip()


def validate_encryption_key(key: Optional[str] = None) -> bool:
    """
    Validates that the provided key (or configured ENCRYPTION_KEY) is a valid Fernet key.
    Ensures length, URL-safe base64 encoding, and encrypt/decrypt capability.
    Raises MissingEncryptionKeyError or InvalidEncryptionKeyError on failure.
    Never exposes or logs the key value.
    """
    if key is None:
        key = get_encryption_key()

    if not key or not str(key).strip():
        raise MissingEncryptionKeyError(
            "ENCRYPTION_KEY is missing. A valid Fernet encryption key must be provided."
        )

    clean_key = str(key).strip()

    # Fernet keys must be 44 URL-safe base64-encoded characters (32 raw bytes)
    if len(clean_key) != 44:
        raise InvalidEncryptionKeyError(
            f"Invalid ENCRYPTION_KEY length ({len(clean_key)} chars). "
            "A Fernet key must be exactly 44 URL-safe base64-encoded characters."
        )

    try:
        raw_bytes = base64.urlsafe_b64decode(clean_key)
        if len(raw_bytes) != 32:
            raise InvalidEncryptionKeyError(
                f"Invalid decoded key length ({len(raw_bytes)} bytes). "
                "Decoded Fernet key must be exactly 32 bytes."
            )
        f = Fernet(clean_key.encode("utf-8"))
        # Verify encryption and decryption roundtrip
        probe = b"eventflow_integrity_probe"
        token = f.encrypt(probe)
        if f.decrypt(token) != probe:
            raise InvalidEncryptionKeyError("Fernet key roundtrip integrity check failed.")
        return True
    except (MissingEncryptionKeyError, InvalidEncryptionKeyError):
        raise
    except Exception as exc:
        raise InvalidEncryptionKeyError(
            f"Malformed Fernet ENCRYPTION_KEY: {type(exc).__name__}."
        ) from exc


def get_fernet(key: Optional[str] = None) -> Fernet:
    """
    Instantiates and returns a Fernet cipher instance using the validated key.
    """
    if key is None:
        key = get_encryption_key()
    validate_encryption_key(key)
    return Fernet(str(key).strip().encode("utf-8"))


def is_encrypted(value: Optional[str], key: Optional[str] = None) -> bool:
    """
    Checks if a string represents authentic Fernet ciphertext decryptable by the key.
    Returns False for plaintext or non-string values.
    Propagates MissingEncryptionKeyError and InvalidEncryptionKeyError if the key configuration is missing or invalid.
    """
    if not value or not isinstance(value, str):
        return False

    # Key validation must occur and configuration errors must propagate unconditionally
    fernet = get_fernet(key)

    # Fernet ciphertext always starts with 'gAAAAA' (version 0x80 in base64)
    if not value.startswith("gAAAAA"):
        return False

    try:
        fernet.decrypt(value.encode("utf-8"))
        return True
    except InvalidToken:
        return False


def encrypt_secret(secret: Optional[str], key: Optional[str] = None) -> Optional[str]:
    """
    Encrypts a plaintext secret into an authenticated Fernet token.
    Safe against accidental double-encryption: returns value as-is if already encrypted under the current key.
    Fails closed: raises DecryptionError if the value starts with Fernet prefix 'gAAAAA' but cannot be decrypted.
    Never logs plaintext secrets or keys.
    """
    if secret is None:
        return None

    if not str(secret).strip():
        return secret

    # Fail-closed handling for Fernet-looking values:
    # If the value starts with 'gAAAAA', it is ciphertext. If it cannot be decrypted with the active key
    # (e.g. wrong key or corrupted ciphertext), refuse to silently treat it as plaintext or double-encrypt it.
    if secret.startswith("gAAAAA"):
        if is_encrypted(secret, key=key):
            return secret
        raise DecryptionError(
            "Cannot encrypt secret: value begins with Fernet prefix 'gAAAAA' but cannot be "
            "decrypted with the configured ENCRYPTION_KEY. Value may be corrupted or encrypted with a different key."
        )

    fernet = get_fernet(key)
    encrypted_bytes = fernet.encrypt(secret.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_secret(ciphertext: Optional[str], key: Optional[str] = None) -> Optional[str]:
    """
    Decrypts an authenticated Fernet token into the original plaintext secret string.
    Raises DecryptionError if the ciphertext is malformed or invalid.
    Never logs plaintext secrets or keys.
    """
    if ciphertext is None:
        return None

    if not str(ciphertext).strip():
        return ciphertext

    fernet = get_fernet(key)
    try:
        decrypted_bytes = fernet.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken as exc:
        raise DecryptionError(
            "Failed to decrypt endpoint secret: token is malformed, corrupted, or key does not match."
        ) from exc
    except Exception as exc:
        raise DecryptionError(
            f"Unexpected error during secret decryption: {type(exc).__name__}."
        ) from exc


def generate_encryption_key() -> str:
    """
    Generates a fresh cryptographically secure 32-byte URL-safe base64 Fernet key.
    """
    return Fernet.generate_key().decode("utf-8")
