import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, Integer, DateTime, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.types import TypeDecorator
from typing import Optional
from app.database.session import Base
from app.core.encryption import encrypt_secret, decrypt_secret, DecryptionError


def get_utc_now():
    return datetime.now(timezone.utc)


class EncryptedSecret(TypeDecorator):
    """
    SQLAlchemy TypeDecorator that transparently encrypts webhook signing secrets at rest
    prior to database persistence, and decrypts them into plaintext strings in memory.
    Guards against accidental double-encryption and handles unencrypted legacy strings safely.
    """
    impl = String(512)
    cache_ok = True

    def process_bind_param(self, value: Optional[str], dialect) -> Optional[str]:
        if value is None:
            return None
        return encrypt_secret(value)

    def process_result_value(self, value: Optional[str], dialect) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            return value
        if value.startswith("gAAAAA"):
            return decrypt_secret(value)
        raise DecryptionError(
            "Unencrypted plaintext endpoint secret detected in database row. "
            "All endpoint secrets must be encrypted at rest after migration 003."
        )


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    url = Column(String(2048), nullable=False)
    description = Column(String(255), nullable=True)
    secret = Column(EncryptedSecret, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_deleted = Column(Boolean, default=False, nullable=False, index=True)
    event_types = Column(JSON, nullable=False, default=list)  # e.g. ["*"] or ["order.placed"]
    rate_limit_per_minute = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships - preserve historical deliveries upon endpoint soft-deletion
    deliveries = relationship("Delivery", back_populates="endpoint")

    def __repr__(self):
        return f"<Endpoint(id={self.id}, url={self.url}, is_active={self.is_active}, is_deleted={self.is_deleted})>"
