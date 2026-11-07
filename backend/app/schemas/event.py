from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class EventCreate(BaseModel):
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        examples=["order.placed"],
        description="Event classification identifier (e.g. order.placed, payment.processed)"
    )
    payload: Dict[str, Any] = Field(
        ...,
        description="JSON payload containing event data"
    )
    idempotency_key: Optional[str] = Field(
        None,
        max_length=255,
        description="Optional client-specified idempotency key to prevent duplicate publishing"
    )


class DeliverySummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    endpoint_id: str
    endpoint_url: str
    status: str
    attempt_count: int
    last_http_status: Optional[int] = None
    created_at: datetime


class EventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_type: str
    payload: Dict[str, Any]
    idempotency_key: Optional[str] = None
    created_at: datetime
    deliveries_count: int = 0
    successful_deliveries_count: int = 0


class EventDetailResponse(EventResponse):
    deliveries: List[DeliverySummary] = []
