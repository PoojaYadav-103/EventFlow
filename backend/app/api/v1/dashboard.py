from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func

from app.api.deps import get_db
from app.models.endpoint import Endpoint
from app.models.event import Event
from app.models.delivery import Delivery, DeliveryStatus
from app.schemas.dashboard import DashboardStats
from app.schemas.delivery import DeliveryResponse

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats, summary="Get dashboard summary analytics")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_events = db.query(func.count(Event.id)).scalar() or 0
    total_deliveries = db.query(func.count(Delivery.id)).scalar() or 0
    
    # Counts by status
    status_counts = (
        db.query(Delivery.status, func.count(Delivery.id))
        .group_by(Delivery.status)
        .all()
    )
    status_map = {str(row[0]).replace("DeliveryStatus.", ""): row[1] for row in status_counts}

    successful = status_map.get("SUCCESS", 0)
    failed = status_map.get("FAILED", 0)
    dead_letter = status_map.get("DEAD_LETTER", 0)
    processing = status_map.get("PROCESSING", 0)
    retrying = status_map.get("RETRYING", 0)
    pending_only = status_map.get("PENDING", 0)

    # In-flight active deliveries: PENDING + PROCESSING + RETRYING
    total_in_flight = pending_only + processing + retrying

    # Terminal delivery states: SUCCESS, FAILED, DEAD_LETTER
    # Note: RETRYING is an in-flight transient retry state, NOT a permanently failed delivery.
    terminal_count = successful + failed + dead_letter
    success_rate = round((successful / terminal_count * 100), 2) if terminal_count > 0 else 100.0

    total_endpoints = db.query(func.count(Endpoint.id)).filter(Endpoint.is_deleted == False).scalar() or 0
    active_endpoints = db.query(func.count(Endpoint.id)).filter(Endpoint.is_active == True, Endpoint.is_deleted == False).scalar() or 0

    # Recent 10 deliveries
    recent = (
        db.query(Delivery)
        .options(joinedload(Delivery.endpoint), joinedload(Delivery.event))
        .order_by(Delivery.created_at.desc())
        .limit(10)
        .all()
    )

    recent_responses = [
        DeliveryResponse(
            id=d.id,
            event_id=d.event_id,
            endpoint_id=d.endpoint_id,
            endpoint_url=d.endpoint.url if d.endpoint else "Deleted",
            event_type=d.event.event_type if d.event else "Unknown",
            status=d.status.value if hasattr(d.status, "value") else str(d.status),
            attempt_count=d.attempt_count,
            max_attempts=d.max_attempts,
            next_retry_at=d.next_retry_at,
            last_http_status=d.last_http_status,
            last_error=d.last_error,
            created_at=d.created_at,
            updated_at=d.updated_at,
        )
        for d in recent
    ]

    return DashboardStats(
        total_events=total_events,
        total_deliveries=total_deliveries,
        successful_deliveries=successful,
        failed_deliveries=failed,
        pending_deliveries=total_in_flight,
        dead_letter_deliveries=dead_letter,
        success_rate=success_rate,
        active_endpoints=active_endpoints,
        total_endpoints=total_endpoints,
        processing_deliveries=processing,
        retrying_deliveries=retrying,
        recent_deliveries=recent_responses,
    )
