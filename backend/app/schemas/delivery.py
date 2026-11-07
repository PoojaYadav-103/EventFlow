from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class DeliveryAttemptResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    delivery_id: str
    attempt_number: int
    status: str
    http_status: Optional[int] = None
    response_time_ms: Optional[int] = None
    request_headers: Optional[Dict[str, Any]] = None
    response_headers: Optional[Dict[str, Any]] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    executed_at: datetime


class DeliveryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_id: str
    endpoint_id: str
    endpoint_url: Optional[str] = None
    event_type: Optional[str] = None
    status: str
    attempt_count: int
    max_attempts: int
    next_retry_at: Optional[datetime] = None
    last_http_status: Optional[int] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class DeliveryDetailResponse(DeliveryResponse):
    event_payload: Optional[Dict[str, Any]] = None
    signing_secret_masked: Optional[str] = None
    attempts: List[DeliveryAttemptResponse] = []


class ManualRetryResponse(BaseModel):
    delivery_id: str
    status: str
    message: str
