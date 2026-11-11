import os
import json
import tempfile
import pytest
from sqlalchemy import text, create_engine
from alembic import command
from alembic.config import Config

from app.core.config import settings
from app.workers.celery_app import (
    validate_celery_worker_key,
    validate_celery_beat_key,
    ValidateEncryptionKeyBootStep,
)
from app.core.security import sign_payload, verify_signature
from app.core.encryption import (
    encrypt_secret,
    decrypt_secret,
    is_encrypted,
    validate_encryption_key,
    generate_encryption_key,
    get_encryption_key,
    MissingEncryptionKeyError,
    InvalidEncryptionKeyError,
    DecryptionError,
)
from app.models.endpoint import Endpoint
from app.models.event import Event
from app.models.delivery import Delivery
from app.services.endpoint_service import EndpointService
from app.services.delivery_service import DeliveryService


def test_encrypt_decrypt_round_trip():
    """Verify that encrypting and decrypting any plaintext secret preserves the exact original string."""
    key = generate_encryption_key()
    test_secrets = [
        "whsec_standard_49_char_signing_secret_1234567890",
        "whsec_short",
        "whsec_very_long_secret_" + "x" * 200,
        "special_chars_!@#$%^&*()_+~`|}{[]:;?><,./-=",
        "unicode_secret_🔒_webhook_🔑_key",
    ]
    for plain in test_secrets:
        ciphertext = encrypt_secret(plain, key=key)
        assert ciphertext != plain
        assert ciphertext.startswith("gAAAAA")
        assert is_encrypted(ciphertext, key=key) is True
        decrypted = decrypt_secret(ciphertext, key=key)
        assert decrypted == plain


def test_invalid_encryption_key():
    """Verify that malformed or non-base64 encryption keys raise InvalidEncryptionKeyError."""
    bad_keys = [
        "too_short",
        "not_valid_base64_!@#$",
        "yU8qY9hWcKjP3vF7rB2sT6xZ1aE4dG5hI7kL9mN2pQ4",  # 43 chars (must be 44)
        "yU8qY9hWcKjP3vF7rB2sT6xZ1aE4dG5hI7kL9mN2pQ4==",  # 46 chars
        "A" * 44,  # valid length but decodes to all 0s/invalid Fernet probe failure
    ]
    for bad_key in bad_keys:
        with pytest.raises(InvalidEncryptionKeyError):
            validate_encryption_key(bad_key)


def test_missing_encryption_key(monkeypatch):
    """Verify that missing or whitespace-only keys raise MissingEncryptionKeyError."""
    # Explicit whitespace or empty key
    for empty_key in ["", "   "]:
        with pytest.raises(MissingEncryptionKeyError):
            validate_encryption_key(empty_key)

    # When no key is configured in settings or environment
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)

    with pytest.raises(MissingEncryptionKeyError):
        get_encryption_key()

    with pytest.raises(MissingEncryptionKeyError):
        validate_encryption_key()


def test_malformed_ciphertext_handling():
    """Verify that malformed ciphertext or corrupted tokens fail safely with DecryptionError."""
    key = generate_encryption_key()
    malformed_tokens = [
        "not_a_fernet_token",
        "gAAAAA_corrupted_payload_that_is_too_short",
        "gAAAAA" + "A" * 150,  # invalid signature / HMAC mismatch
    ]
    for token in malformed_tokens:
        with pytest.raises(DecryptionError):
            decrypt_secret(token, key=key)


def test_no_double_encryption():
    """Verify that passing an already-encrypted secret does not re-encrypt it."""
    key = generate_encryption_key()
    plain = "whsec_prevent_double_encryption_token"

    ciphertext_1 = encrypt_secret(plain, key=key)
    ciphertext_2 = encrypt_secret(ciphertext_1, key=key)
    ciphertext_3 = encrypt_secret(ciphertext_2, key=key)

    assert ciphertext_1 == ciphertext_2 == ciphertext_3
    assert decrypt_secret(ciphertext_3, key=key) == plain


def test_encrypt_secret_rejects_corrupted_fernet_prefix_input():
    """
    Verify that encrypt_secret() fails closed when given a corrupted token that starts with
    'gAAAAA', raising DecryptionError rather than treating it as plaintext or double-encrypting it.
    """
    key = generate_encryption_key()
    corrupted_tokens = [
        "gAAAAA_corrupted_payload_that_is_too_short",
        "gAAAAA" + "A" * 150,  # invalid signature / HMAC mismatch
    ]
    for token in corrupted_tokens:
        with pytest.raises(DecryptionError) as exc_info:
            encrypt_secret(token, key=key)
        assert "cannot be decrypted with the configured ENCRYPTION_KEY" in str(exc_info.value)


def test_encrypt_secret_rejects_wrong_key_ciphertext():
    """
    Verify that encrypt_secret() fails closed when given ciphertext encrypted under a different key,
    raising DecryptionError rather than silently re-encrypting/double-encrypting it.
    """
    key_a = generate_encryption_key()
    key_b = generate_encryption_key()
    plaintext = "whsec_secret_under_key_a"

    ciphertext_a = encrypt_secret(plaintext, key=key_a)
    assert ciphertext_a.startswith("gAAAAA")

    # Attempting to encrypt Key A's ciphertext using Key B must fail closed
    with pytest.raises(DecryptionError) as exc_info:
        encrypt_secret(ciphertext_a, key=key_b)
    assert "cannot be decrypted with the configured ENCRYPTION_KEY" in str(exc_info.value)


def test_is_encrypted_propagates_missing_and_invalid_key_errors(monkeypatch):
    """
    Verify that is_encrypted() does not catch and mask configuration errors,
    but propagates MissingEncryptionKeyError and InvalidEncryptionKeyError.
    """
    # 1. Missing key
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)

    with pytest.raises(MissingEncryptionKeyError):
        is_encrypted("whsec_test_secret")

    with pytest.raises(MissingEncryptionKeyError):
        is_encrypted("gAAAAA_some_ciphertext")

    # 2. Invalid key
    with pytest.raises(InvalidEncryptionKeyError):
        is_encrypted("whsec_test_secret", key="not_a_valid_fernet_key")

    with pytest.raises(InvalidEncryptionKeyError):
        is_encrypted("gAAAAA_some_ciphertext", key="not_a_valid_fernet_key")


def test_encrypt_secret_idempotent_on_valid_ciphertext():
    """
    Verify that encrypt_secret() preserves legitimate plaintext encryption
    and idempotently returns valid existing ciphertext without re-encrypting.
    """
    key = generate_encryption_key()
    plaintext = "whsec_idempotent_test_secret"

    ciphertext = encrypt_secret(plaintext, key=key)
    assert ciphertext.startswith("gAAAAA")

    # Calling encrypt_secret again with the same key returns the exact same token
    re_encrypted = encrypt_secret(ciphertext, key=key)
    assert re_encrypted == ciphertext
    assert decrypt_secret(re_encrypted, key=key) == plaintext


def test_database_stores_ciphertext_not_plaintext(db_session):
    """
    Verify that Endpoint secrets are stored in the database as Fernet ciphertext (starting with gAAAAA),
    while the ORM transparently surfaces the decrypted logical plaintext secret.
    """
    raw_secret = "whsec_database_ciphertext_verification_12345"
    ep = Endpoint(
        url="https://api.example.com/test-encryption",
        description="Encrypted Endpoint Test",
        secret=raw_secret,
        event_types=["*"],
    )
    db_session.add(ep)
    db_session.commit()
    ep_id = ep.id

    # 1. Direct raw SQL inspection: verify the physical column contains Fernet ciphertext
    raw_row = db_session.execute(
        text("SELECT secret FROM endpoints WHERE id = :id"),
        {"id": ep_id},
    ).fetchone()

    assert raw_row is not None
    db_secret_val = raw_row[0]
    assert db_secret_val != raw_secret, "Secret must NOT be stored in plaintext"
    assert db_secret_val.startswith("gAAAAA"), "Stored secret must be an authentic Fernet token"
    assert len(db_secret_val) > len(raw_secret)

    # 2. ORM inspection: transparently decrypts back to raw_secret
    db_session.expire_all()
    queried_ep = db_session.query(Endpoint).filter_by(id=ep_id).first()
    assert queried_ep is not None
    assert queried_ep.secret == raw_secret, "ORM attribute access must yield decrypted plaintext"


def test_hmac_signing_uses_decrypted_logical_secret(db_session):
    """
    Verify that webhook dispatching reads the decrypted logical secret from the endpoint
    and produces a cryptographically valid HMAC-SHA256 signature.
    """
    logical_secret = "whsec_hmac_verification_secret_8888"
    ep = Endpoint(
        url="https://api.example.com/webhook-hmac",
        secret=logical_secret,
        is_active=True,
        event_types=["order.placed"],
    )
    ev = Event(event_type="order.placed", payload={"order_id": "ord_999"})
    db_session.add_all([ep, ev])
    db_session.commit()

    deliv = Delivery(event_id=ev.id, endpoint_id=ep.id)
    db_session.add(deliv)
    db_session.commit()

    # The delivery service extracts delivery.endpoint.secret
    endpoint_secret = deliv.endpoint.secret
    assert endpoint_secret == logical_secret

    payload_str = json.dumps(ev.payload, separators=(",", ":"), ensure_ascii=False)
    sig_header, ts = sign_payload(endpoint_secret, payload_str)

    # Verify signature
    assert verify_signature(
        secret=logical_secret,
        payload_str=payload_str,
        header_value=sig_header,
    ) is True


def test_api_responses_do_not_expose_plaintext_secrets(client):
    """
    Verify that API endpoints (list, get, delivery details) never expose plaintext signing secrets.
    Only Endpoint creation and secret rotation return the one-time secret.
    """
    # 1. Register endpoint
    create_resp = client.post(
        "/api/v1/endpoints",
        json={"url": "https://api.example.com/safe-api", "event_types": ["*"]},
    )
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    ep_id = created_data["id"]
    one_time_secret = created_data["signing_secret"]
    assert "••••" in created_data["signing_secret_masked"]

    # 2. GET /endpoints (list): must not expose signing_secret
    list_resp = client.get("/api/v1/endpoints")
    assert list_resp.status_code == 200
    listed_items = list_resp.json()
    item = next(i for i in listed_items if i["id"] == ep_id)
    assert "signing_secret" not in item
    assert item["signing_secret_masked"].startswith("whsec_")
    assert one_time_secret not in item["signing_secret_masked"]

    # 3. GET /endpoints/{id}: must not expose signing_secret
    get_resp = client.get(f"/api/v1/endpoints/{ep_id}")
    assert get_resp.status_code == 200
    detail = get_resp.json()
    assert "signing_secret" not in detail
    assert detail["signing_secret_masked"].startswith("whsec_")
    assert one_time_secret not in detail["signing_secret_masked"]


def test_existing_endpoint_secret_migration_and_rollback():
    """
    Verify that Alembic migration 003_encrypt_secrets:
    1. Upgrades from 002_reliability to 003_encrypt_secrets and converts existing plaintext secrets to Fernet tokens.
    2. Preserves every endpoint's original logical secret.
    3. Prevents double encryption on idempotent re-runs.
    4. Downgrades cleanly from 003_encrypt_secrets back to 002_reliability, restoring plaintext.
    """
    test_key = "yU8qY9hWcKjP3vF7rB2sT6xZ1aE4dG5hI7kL9mN2pQ4="
    os.environ["ENCRYPTION_KEY"] = test_key

    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_encryption_test.db")
    db_url = f"sqlite:///{db_path}"

    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    alembic_ini = os.path.join(backend_dir, "alembic.ini")

    config = Config(alembic_ini)
    config.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    config.set_main_option("sqlalchemy.url", db_url)

    engine = create_engine(db_url)

    try:
        # Step 1: Upgrade to 002_reliability (plaintext schema)
        command.upgrade(config, "002_reliability")

        # Step 2: Insert endpoints with plaintext secrets
        plaintext_secrets = {
            "ep_1": "whsec_plaintext_alpha_1111111111",
            "ep_2": "whsec_plaintext_bravo_2222222222",
        }
        with engine.connect() as conn:
            for ep_id, sec in plaintext_secrets.items():
                conn.execute(
                    text(
                        "INSERT INTO endpoints (id, url, secret, is_active, is_deleted, event_types, created_at, updated_at) "
                        "VALUES (:id, 'https://example.com/test', :sec, 1, 0, '[\"*\"]', '2026-11-11 00:00:00', '2026-11-11 00:00:00')"
                    ),
                    {"id": ep_id, "sec": sec},
                )
            conn.commit()

        # Step 3: Run migration 003_encrypt_secrets
        command.upgrade(config, "003_encrypt_secrets")

        # Step 4: Verify raw SQL table values are Fernet tokens
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT id, secret FROM endpoints")).fetchall()
            for r in rows:
                ep_id, stored_secret = r[0], r[1]
                assert stored_secret.startswith("gAAAAA"), f"Endpoint {ep_id} secret is not a Fernet token"
                assert stored_secret != plaintext_secrets[ep_id]
                # Decrypt and verify exact preservation
                decrypted = decrypt_secret(stored_secret, key=test_key)
                assert decrypted == plaintext_secrets[ep_id], f"Decrypted secret mismatch for {ep_id}"

        # Step 5: Test idempotency: re-running upgrade must not double-encrypt
        command.upgrade(config, "003_encrypt_secrets")
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT id, secret FROM endpoints")).fetchall()
            for r in rows:
                ep_id, stored_secret = r[0], r[1]
                decrypted = decrypt_secret(stored_secret, key=test_key)
                assert decrypted == plaintext_secrets[ep_id]

        # Step 6: Test downgrade back to 002_reliability
        command.downgrade(config, "002_reliability")
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT id, secret FROM endpoints")).fetchall()
            for r in rows:
                ep_id, stored_secret = r[0], r[1]
                assert stored_secret == plaintext_secrets[ep_id], f"Downgrade failed to restore plaintext for {ep_id}"

    finally:
        engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


def test_migration_upgrade_aborts_on_wrong_key_without_corrupting_database(monkeypatch):
    """
    SEC-01: Verify that if existing endpoints contain ciphertext that cannot be decrypted
    with the configured ENCRYPTION_KEY, migration upgrade immediately aborts with RuntimeError,
    does NOT double-encrypt or alter records, and leaves the database completely intact.
    """
    key_a = "yU8qY9hWcKjP3vF7rB2sT6xZ1aE4dG5hI7kL9mN2pQ4="
    key_b = generate_encryption_key()  # different valid key

    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_wrong_key_upgrade.db")
    db_url = f"sqlite:///{db_path}"

    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    alembic_ini = os.path.join(backend_dir, "alembic.ini")

    config = Config(alembic_ini)
    config.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    config.set_main_option("sqlalchemy.url", db_url)

    engine = create_engine(db_url)

    try:
        # Step 1: Initialize to 002_reliability
        command.upgrade(config, "002_reliability")

        # Step 2: Insert secret already encrypted with Key A (or simulating prior migration under Key A)
        plaintext = "whsec_preserve_me_under_key_a_9999"
        ciphertext_key_a = encrypt_secret(plaintext, key=key_a)
        with engine.connect() as conn:
            conn.execute(
                text(
                    "INSERT INTO endpoints (id, url, secret, is_active, is_deleted, event_types, created_at, updated_at) "
                    "VALUES ('ep_key_a', 'https://example.com/test', :sec, 1, 0, '[\"*\"]', '2026-11-11 00:00:00', '2026-11-11 00:00:00')"
                ),
                {"sec": ciphertext_key_a},
            )
            conn.commit()

        # Step 3: Run migration upgrade 003 using Key B (wrong key!)
        monkeypatch.setenv("ENCRYPTION_KEY", key_b)
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", key_b)

        with pytest.raises(RuntimeError) as exc_info:
            command.upgrade(config, "003_encrypt_secrets")

        err_msg = str(exc_info.value)
        assert "cannot be decrypted with the configured ENCRYPTION_KEY" in err_msg
        assert "ep_key_a" in err_msg

        # Step 4: Verify the database was NOT corrupted or modified in any way
        with engine.connect() as conn:
            row = conn.execute(text("SELECT secret FROM endpoints WHERE id = 'ep_key_a'")).fetchone()
            assert row is not None
            current_secret = row[0]
            # Must remain the exact Key A ciphertext token - not double-encrypted with Key B!
            assert current_secret == ciphertext_key_a
            # Decrypt with Key A must succeed and match original plaintext
            assert decrypt_secret(current_secret, key=key_a) == plaintext

    finally:
        engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


def test_migration_downgrade_aborts_on_wrong_key_without_corrupting_database(monkeypatch):
    """
    SEC-03: Verify that migration downgrade pre-validates all encrypted records and aborts
    if any record cannot be decrypted, leaving all database records untouched.
    """
    key_a = "yU8qY9hWcKjP3vF7rB2sT6xZ1aE4dG5hI7kL9mN2pQ4="
    key_b = generate_encryption_key()

    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_wrong_key_downgrade.db")
    db_url = f"sqlite:///{db_path}"

    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    alembic_ini = os.path.join(backend_dir, "alembic.ini")

    config = Config(alembic_ini)
    config.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    config.set_main_option("sqlalchemy.url", db_url)

    engine = create_engine(db_url)

    try:
        # Step 1: Upgrade to 002
        command.upgrade(config, "002_reliability")

        # Step 2: Insert endpoints and upgrade to 003 under Key A
        monkeypatch.setenv("ENCRYPTION_KEY", key_a)
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", key_a)

        plaintext = "whsec_key_a_downgrade_protection"
        with engine.connect() as conn:
            conn.execute(
                text(
                    "INSERT INTO endpoints (id, url, secret, is_active, is_deleted, event_types, created_at, updated_at) "
                    "VALUES ('ep_down', 'https://example.com/test', :sec, 1, 0, '[\"*\"]', '2026-11-11 00:00:00', '2026-11-11 00:00:00')"
                ),
                {"sec": plaintext},
            )
            conn.commit()

        command.upgrade(config, "003_encrypt_secrets")

        with engine.connect() as conn:
            row = conn.execute(text("SELECT secret FROM endpoints WHERE id = 'ep_down'")).fetchone()
            assert row[0].startswith("gAAAAA")
            ciphertext_a = row[0]

        # Step 3: Attempt downgrade with Key B (wrong key!)
        monkeypatch.setenv("ENCRYPTION_KEY", key_b)
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", key_b)

        with pytest.raises(RuntimeError) as exc_info:
            command.downgrade(config, "002_reliability")

        err_msg = str(exc_info.value)
        assert "cannot be decrypted with the configured ENCRYPTION_KEY" in err_msg
        assert "ep_down" in err_msg

        # Step 4: Verify that the record in DB is untouched
        with engine.connect() as conn:
            row = conn.execute(text("SELECT secret FROM endpoints WHERE id = 'ep_down'")).fetchone()
            assert row[0] == ciphertext_a
            assert decrypt_secret(row[0], key=key_a) == plaintext

    finally:
        engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


def test_empty_database_migration_requires_valid_key(monkeypatch):
    """
    SEC-05: Verify that Alembic upgrade and downgrade validate ENCRYPTION_KEY
    even when the endpoints table contains zero records.
    """
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_empty_db.db")
    db_url = f"sqlite:///{db_path}"

    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    alembic_ini = os.path.join(backend_dir, "alembic.ini")

    config = Config(alembic_ini)
    config.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    config.set_main_option("sqlalchemy.url", db_url)

    engine = create_engine(db_url)

    try:
        command.upgrade(config, "002_reliability")

        # 1. Missing key on upgrade
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)

        with pytest.raises(RuntimeError) as exc_info:
            command.upgrade(config, "003_encrypt_secrets")
        assert "ENCRYPTION_KEY is required" in str(exc_info.value)

        # 2. Invalid key on upgrade
        monkeypatch.setenv("ENCRYPTION_KEY", "not_a_valid_key")
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", "not_a_valid_key")

        with pytest.raises(RuntimeError) as exc_info:
            command.upgrade(config, "003_encrypt_secrets")
        assert "Invalid ENCRYPTION_KEY" in str(exc_info.value)

        # 3. Upgrade with valid key
        valid_key = "yU8qY9hWcKjP3vF7rB2sT6xZ1aE4dG5hI7kL9mN2pQ4="
        monkeypatch.setenv("ENCRYPTION_KEY", valid_key)
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", valid_key)
        command.upgrade(config, "003_encrypt_secrets")

        # 4. Missing key on downgrade
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)

        with pytest.raises(RuntimeError) as exc_info:
            command.downgrade(config, "002_reliability")
        assert "ENCRYPTION_KEY is required" in str(exc_info.value)

    finally:
        engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


def test_orm_raises_decryption_error_on_corrupted_ciphertext(db_session):
    """
    SEC-02: Verify that if a stored value starts with 'gAAAAA' but fails decryption,
    the ORM raises DecryptionError and NEVER returns raw ciphertext as a signing secret.
    """
    corrupted_token = "gAAAAAB_corrupted_ciphertext_token_that_cannot_decrypt_1234567890"

    # Insert directly via SQL bypassing TypeDecorator
    db_session.execute(
        text(
            "INSERT INTO endpoints (id, url, secret, is_active, is_deleted, event_types, created_at, updated_at) "
            "VALUES ('ep_corrupted', 'https://example.com/bad', :sec, 1, 0, '[\"*\"]', '2026-11-11 00:00:00', '2026-11-11 00:00:00')"
        ),
        {"sec": corrupted_token},
    )
    db_session.commit()
    db_session.expire_all()

    # Querying the endpoint via ORM must raise DecryptionError during row processing
    with pytest.raises(DecryptionError):
        db_session.query(Endpoint).filter_by(id="ep_corrupted").first()


def test_orm_rejects_unencrypted_plaintext_secrets(db_session):
    """
    SEC-02: Verify that unencrypted legacy plaintext secrets are strictly rejected
    by the ORM and raise DecryptionError rather than silently returning plaintext.
    """
    raw_plaintext = "whsec_legacy_unmigrated_plaintext_secret_123"

    # Insert raw plaintext directly via SQL
    db_session.execute(
        text(
            "INSERT INTO endpoints (id, url, secret, is_active, is_deleted, event_types, created_at, updated_at) "
            "VALUES ('ep_plain', 'https://example.com/plain', :sec, 1, 0, '[\"*\"]', '2026-11-11 00:00:00', '2026-11-11 00:00:00')"
        ),
        {"sec": raw_plaintext},
    )
    db_session.commit()
    db_session.expire_all()

    with pytest.raises(DecryptionError) as exc_info:
        db_session.query(Endpoint).filter_by(id="ep_plain").first()
    assert "Unencrypted plaintext endpoint secret detected" in str(exc_info.value)


def test_celery_worker_and_beat_startup_fails_without_key(monkeypatch):
    """
    SEC-04: Verify that Celery worker and Celery Beat startup fail fast
    when ENCRYPTION_KEY is missing or invalid.
    """
    # 1. Missing key
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)

    with pytest.raises(MissingEncryptionKeyError):
        validate_celery_worker_key()

    with pytest.raises(MissingEncryptionKeyError):
        validate_celery_beat_key()

    with pytest.raises(MissingEncryptionKeyError):
        ValidateEncryptionKeyBootStep(None)

    # 2. Invalid key
    monkeypatch.setenv("ENCRYPTION_KEY", "invalid_fernet_key_string")
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", "invalid_fernet_key_string")

    with pytest.raises(InvalidEncryptionKeyError):
        validate_celery_worker_key()

    with pytest.raises(InvalidEncryptionKeyError):
        validate_celery_beat_key()

    with pytest.raises(InvalidEncryptionKeyError):
        ValidateEncryptionKeyBootStep(None)

    # 3. Valid key succeeds
    valid_key = "yU8qY9hWcKjP3vF7rB2sT6xZ1aE4dG5hI7kL9mN2pQ4="
    monkeypatch.setenv("ENCRYPTION_KEY", valid_key)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", valid_key)

    validate_celery_worker_key()
    validate_celery_beat_key()
    step = ValidateEncryptionKeyBootStep(None)
    assert step is not None
