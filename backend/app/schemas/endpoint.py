from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.core.ssrf import validate_webhook_url
from app.core.security import mask_secret


class EndpointBase(BaseModel):
    url: str = Field(..., description="Target HTTP/HTTPS webhook destination URL")
    description: Optional[str] = Field(None, max_length=255, description="Human-readable description")
    event_types: List[str] = Field(
        default=["*"],
        description="List of event types to subscribe to (e.g. ['order.placed'] or ['*'] for all)"
    )
    rate_limit_per_minute: Optional[int] = Field(None, ge=1, le=10000, description="Optional rate limit")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class EndpointCreate(EndpointBase):
    pass


class EndpointUpdate(BaseModel):
    url: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    event_types: Optional[List[str]] = None
    rate_limit_per_minute: Optional[int] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v.startswith(("http://", "https://")):
                raise ValueError("URL must start with http:// or https://")
        return v


class EndpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    url: str
    description: Optional[str] = None
    is_active: bool
    event_types: List[str]
    rate_limit_per_minute: Optional[int] = None
    signing_secret_masked: str
    created_at: datetime
    updated_at: datetime
    deliveries_count: int = 0


class EndpointCreatedResponse(EndpointResponse):
    signing_secret: str = Field(
        ...,
        description="Full signing secret. Only shown once upon creation! Store securely."
    )


class EndpointSecretRollResponse(BaseModel):
    endpoint_id: str
    signing_secret: str
    signing_secret_masked: str
    message: str
