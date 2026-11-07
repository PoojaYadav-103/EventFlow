import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, Integer, DateTime, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base


def get_utc_now():
    return datetime.now(timezone.utc)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    url = Column(String(2048), nullable=False)
    description = Column(String(255), nullable=True)
    secret = Column(String(255), nullable=False)
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
