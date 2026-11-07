from typing import Any, Dict, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class MockReceiverConfig(BaseModel):
    status_code: int = Field(200, description="HTTP status code the mock receiver should respond with")
    delay_seconds: float = Field(0.0, description="Simulated processing delay in seconds")
    reject_all: bool = Field(False, description="Simulate network / socket drops")
    signing_secret: Optional[str] = Field(None, description="Explicit secret to use for cryptographic verification")


class MockWebhookLog(BaseModel):
    id: str
    received_at: datetime
    event_id: Optional[str] = None
    delivery_id: Optional[str] = None
    event_type: Optional[str] = None
    signature_header: Optional[str] = None
    signature_valid: Optional[bool] = None
    headers: Dict[str, str]
    payload: Dict[str, Any]
