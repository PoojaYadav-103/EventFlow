"""Module 3 security: Encrypt webhook endpoint signing secrets at rest

Revision ID: 003_encrypt_secrets
Revises: 002_reliability
Create Date: 2026-11-11 00:00:00.000000

"""
import os
from alembic import op
import sqlalchemy as sa
from cryptography.fernet import Fernet

revision = "003_encrypt_secrets"
down_revision = "002_reliability"
branch_labels = None
depends_on = None


def _get_fernet_for_migration() -> Fernet:
    """
    Loads and validates ENCRYPTION_KEY for migration.
    Fails safely if missing or invalid.
    Never logs or exposes the key.
    """
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        try:
            from app.core.config import settings
            key = settings.ENCRYPTION_KEY
        except Exception:
            key = None

    if not key or not str(key).strip():
        raise RuntimeError(
            "Cannot perform migration 003_encrypt_secrets: ENCRYPTION_KEY is required to "
            "encrypt/decrypt endpoint secrets at rest. Please set ENCRYPTION_KEY in environment."
        )

    clean_key = str(key).strip()
    try:
        f = Fernet(clean_key.encode("utf-8"))
        # Validate roundtrip capability
        probe = b"eventflow_migration_probe"
        if f.decrypt(f.encrypt(probe)) != probe:
            raise ValueError("Probe roundtrip failed")
        return f
    except Exception as exc:
        raise RuntimeError(
            f"Cannot perform migration 003_encrypt_secrets: Invalid ENCRYPTION_KEY format: {type(exc).__name__}."
        ) from exc


def upgrade() -> None:
    # 1. Unconditionally validate ENCRYPTION_KEY first (even on empty tables)
    fernet = _get_fernet_for_migration()

    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, secret FROM endpoints")).fetchall()

    # 2. Pre-validate 100% of existing secrets BEFORE altering table or modifying any records
    pending_encrypt = []
    for row in rows:
        ep_id = row[0]
        raw_secret = row[1]
        if raw_secret and str(raw_secret).strip():
            if raw_secret.startswith("gAAAAA"):
                try:
                    fernet.decrypt(raw_secret.encode("utf-8"))
                    # Successfully decrypted: secret is already encrypted with current key.
                    # Do not re-encrypt.
                except Exception as exc:
                    raise RuntimeError(
                        f"Cannot perform migration 003_encrypt_secrets: Endpoint {ep_id} contains ciphertext "
                        f"with prefix 'gAAAAA' that cannot be decrypted with the configured ENCRYPTION_KEY. "
                        f"Aborting migration to prevent data loss or double-encryption."
                    ) from exc
            else:
                # Plaintext secret that must be encrypted
                pending_encrypt.append((ep_id, raw_secret))

    # 3. Widen endpoints.secret column from String(255) to String(512) to hold Fernet ciphertext tokens
    with op.batch_alter_table("endpoints") as batch_op:
        batch_op.alter_column(
            "secret",
            type_=sa.String(512),
            existing_type=sa.String(255),
            nullable=False,
        )

    # 4. Encrypt and persist only unencrypted plaintext rows
    for ep_id, raw_secret in pending_encrypt:
        ciphertext = fernet.encrypt(raw_secret.encode("utf-8")).decode("utf-8")
        bind.execute(
            sa.text("UPDATE endpoints SET secret = :ciphertext WHERE id = :ep_id"),
            {"ciphertext": ciphertext, "ep_id": ep_id},
        )
    # Note: Plaintext secrets and ciphertext are never printed or logged during migration.


def downgrade() -> None:
    # 1. Unconditionally validate ENCRYPTION_KEY first (even on empty tables)
    fernet = _get_fernet_for_migration()

    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, secret FROM endpoints")).fetchall()

    # 2. Pre-validate and decrypt 100% of encrypted secrets BEFORE altering table or modifying any records
    pending_downgrades = []
    for row in rows:
        ep_id = row[0]
        stored_secret = row[1]
        if stored_secret and str(stored_secret).strip():
            if stored_secret.startswith("gAAAAA"):
                try:
                    plaintext = fernet.decrypt(stored_secret.encode("utf-8")).decode("utf-8")
                    pending_downgrades.append((ep_id, plaintext))
                except Exception as exc:
                    raise RuntimeError(
                        f"Cannot perform downgrade 003_encrypt_secrets: Endpoint {ep_id} secret "
                        f"starts with Fernet prefix 'gAAAAA' but cannot be decrypted with the configured ENCRYPTION_KEY. "
                        f"Aborting downgrade without modifying any database records."
                    ) from exc
            else:
                # Value was not encrypted (edge case); preserve as is
                pending_downgrades.append((ep_id, stored_secret))

    # 3. Update database rows to plaintext
    for ep_id, plaintext in pending_downgrades:
        bind.execute(
            sa.text("UPDATE endpoints SET secret = :plaintext WHERE id = :ep_id"),
            {"plaintext": plaintext, "ep_id": ep_id},
        )

    # 4. Revert column width back to String(255)
    with op.batch_alter_table("endpoints") as batch_op:
        batch_op.alter_column(
            "secret",
            type_=sa.String(255),
            existing_type=sa.String(512),
            nullable=False,
        )
