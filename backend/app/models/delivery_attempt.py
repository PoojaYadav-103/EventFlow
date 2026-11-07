import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey, JSON, Enum, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database.session import Base


def get_utc_now():
    return datetime.now(timezone.utc)


class AttemptStatus(str, enum.Enum):
    STARTED = "STARTED"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class DeliveryAttempt(Base):
    __tablename__ = "delivery_attempts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    delivery_id = Column(String(36), ForeignKey("deliveries.id", ondelete="CASCADE"), nullable=False, index=True)
    attempt_number = Column(Integer, nullable=False)
    
    status = Column(
        Enum(AttemptStatus, name="attempt_status_enum", native_enum=False),
        default=AttemptStatus.STARTED,
        nullable=False,
        index=True,
    )
    http_status = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    request_headers = Column(JSON, nullable=True)
    response_headers = Column(JSON, nullable=True)
    response_body = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    executed_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("delivery_id", "attempt_number", name="uq_delivery_attempts_delivery_attempt_number"),
    )

    # Relationship
    delivery = relationship("Delivery", back_populates="attempts")

    def __repr__(self):
        return f"<DeliveryAttempt(id={self.id}, attempt={self.attempt_number}, status={self.status})>"
