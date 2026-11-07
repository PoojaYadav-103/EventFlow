import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey, UniqueConstraint, Enum
from sqlalchemy.orm import relationship
from app.database.session import Base


def get_utc_now():
    return datetime.now(timezone.utc)


class DeliveryStatus(str, enum.Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    SUCCESS = "SUCCESS"
    RETRYING = "RETRYING"
    FAILED = "FAILED"
    DEAD_LETTER = "DEAD_LETTER"


class Delivery(Base):
    __tablename__ = "deliveries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(36), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(String(36), ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True)
    
    status = Column(
        Enum(DeliveryStatus, name="delivery_status_enum", native_enum=False),
        default=DeliveryStatus.PENDING,
        nullable=False,
        index=True
    )
    attempt_count = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=5, nullable=False)
    lease_token = Column(String(36), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    lease_worker_id = Column(String(255), nullable=True)
    next_retry_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_http_status = Column(Integer, nullable=True)
    last_error = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("event_id", "endpoint_id", name="uq_delivery_event_endpoint"),
    )

    # Relationships
    event = relationship("Event", back_populates="deliveries")
    endpoint = relationship("Endpoint", back_populates="deliveries")
    attempts = relationship("DeliveryAttempt", back_populates="delivery", cascade="all, delete-orphan", order_by="DeliveryAttempt.attempt_number")
    outbox_events = relationship("OutboxEvent", back_populates="delivery", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Delivery(id={self.id}, status={self.status}, attempts={self.attempt_count})>"
