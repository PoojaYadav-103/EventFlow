from typing import List, Optional
from pydantic import BaseModel
from app.schemas.delivery import DeliveryResponse


class DashboardStats(BaseModel):
    total_events: int
    total_deliveries: int
    successful_deliveries: int
    failed_deliveries: int
    pending_deliveries: int
    dead_letter_deliveries: int
    success_rate: float
    active_endpoints: int
    total_endpoints: int
    processing_deliveries: Optional[int] = 0
    retrying_deliveries: Optional[int] = 0
    recent_deliveries: List[DeliveryResponse] = []
