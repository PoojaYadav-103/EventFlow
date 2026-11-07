from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_db
from app.models.delivery import Delivery, DeliveryStatus
from app.schemas.delivery import (
    DeliveryResponse,
    DeliveryDetailResponse,
    DeliveryAttemptResponse,
    ManualRetryResponse,
)
from app.services.delivery_service import DeliveryService, DeliveryRetryError
from app.core.security import mask_secret

router = APIRouter(prefix="/deliveries", tags=["Deliveries"])


@router.get(
    "",
    response_model=List[DeliveryResponse],
    summary="List delivery records",
)
def list_deliveries(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status_filter: Optional[DeliveryStatus] = Query(None, alias="status", description="Filter by status"),
    event_id: Optional[str] = Query(None, description="Filter by event ID"),
    endpoint_id: Optional[str] = Query(None, description="Filter by endpoint ID"),
    db: Session = Depends(get_db),
):
    query = (
        db.query(Delivery)
        .options(
            joinedload(Delivery.endpoint),
            joinedload(Delivery.event),
        )
    )

    if status_filter:
        query = query.filter(Delivery.status == status_filter)
    if event_id:
        query = query.filter(Delivery.event_id == event_id)
    if endpoint_id:
        query = query.filter(Delivery.endpoint_id == endpoint_id)

    deliveries = query.order_by(Delivery.created_at.desc()).offset(skip).limit(limit).all()

    return [
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
        for d in deliveries
    ]


@router.get(
    "/{delivery_id}",
    response_model=DeliveryDetailResponse,
    summary="Get delivery detail with attempt history",
)
def get_delivery(delivery_id: str, db: Session = Depends(get_db)):
    delivery = (
        db.query(Delivery)
        .options(
            joinedload(Delivery.endpoint),
            joinedload(Delivery.event),
            joinedload(Delivery.attempts),
        )
        .filter(Delivery.id == delivery_id)
        .first()
    )

    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")

    attempts_responses = [
        DeliveryAttemptResponse(
            id=att.id,
            delivery_id=att.delivery_id,
            attempt_number=att.attempt_number,
            status=att.status.value if hasattr(att.status, "value") else str(att.status),
            http_status=att.http_status,
            response_time_ms=att.response_time_ms,
            request_headers=att.request_headers,
            response_headers=att.response_headers,
            response_body=att.response_body,
            error_message=att.error_message,
            executed_at=att.executed_at,
        )
        for att in sorted(delivery.attempts, key=lambda x: x.attempt_number)
    ]

    return DeliveryDetailResponse(
        id=delivery.id,
        event_id=delivery.event_id,
        endpoint_id=delivery.endpoint_id,
        endpoint_url=delivery.endpoint.url if delivery.endpoint else "Deleted",
        event_type=delivery.event.event_type if delivery.event else "Unknown",
        status=delivery.status.value if hasattr(delivery.status, "value") else str(delivery.status),
        attempt_count=delivery.attempt_count,
        max_attempts=delivery.max_attempts,
        next_retry_at=delivery.next_retry_at,
        last_http_status=delivery.last_http_status,
        last_error=delivery.last_error,
        created_at=delivery.created_at,
        updated_at=delivery.updated_at,
        event_payload=delivery.event.payload if delivery.event else {},
        signing_secret_masked=mask_secret(delivery.endpoint.secret) if delivery.endpoint else None,
        attempts=attempts_responses,
    )


@router.post(
    "/{delivery_id}/retry",
    response_model=ManualRetryResponse,
    summary="Trigger manual retry for a delivery",
    description="Manually re-enqueues delivery for failed or dead-letter webhooks."
)
def manual_retry_delivery(delivery_id: str, db: Session = Depends(get_db)):
    try:
        delivery = DeliveryService.retry_manually(db, delivery_id)
    except DeliveryRetryError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")

    status_str = delivery.status.value if hasattr(delivery.status, "value") else str(delivery.status)
    return ManualRetryResponse(
        delivery_id=delivery.id,
        status=status_str,
        message="Manual retry scheduled successfully."
    )
