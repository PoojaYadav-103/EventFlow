from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.event import (
    EventCreate,
    EventResponse,
    EventDetailResponse,
    DeliverySummary,
)
from app.services.event_service import EventService

router = APIRouter(prefix="/events", tags=["Events"])


@router.post(
    "",
    response_model=EventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Publish an event to EventFlow",
    description="Asynchronously dispatches the event to all active endpoints subscribed to the given event_type."
)
def publish_event(
    data: EventCreate,
    response: Response,
    db: Session = Depends(get_db),
):
    event, deliveries, is_duplicate = EventService.publish_event(db, data)
    
    # If duplicate idempotency key was submitted, return 200 OK instead of 201 Created
    if is_duplicate:
        response.status_code = status.HTTP_200_OK

    successful_count = sum(1 for d in deliveries if d.status == "SUCCESS")

    return EventResponse(
        id=event.id,
        event_type=event.event_type,
        payload=event.payload,
        idempotency_key=event.idempotency_key,
        created_at=event.created_at,
        deliveries_count=len(deliveries),
        successful_deliveries_count=successful_count,
    )


@router.get(
    "",
    response_model=List[EventResponse],
    summary="List published events",
)
def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    db: Session = Depends(get_db),
):
    results = EventService.get_events(db, skip=skip, limit=limit, event_type=event_type)
    return [
        EventResponse(
            id=ev.id,
            event_type=ev.event_type,
            payload=ev.payload,
            idempotency_key=ev.idempotency_key,
            created_at=ev.created_at,
            deliveries_count=total,
            successful_deliveries_count=successful,
        )
        for ev, total, successful in results
    ]


@router.get(
    "/{event_id}",
    response_model=EventDetailResponse,
    summary="Get event details and delivery records",
)
def get_event(event_id: str, db: Session = Depends(get_db)):
    event = EventService.get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    deliveries_summary = [
        DeliverySummary(
            id=d.id,
            endpoint_id=d.endpoint_id,
            endpoint_url=d.endpoint.url if d.endpoint else "Unknown",
            status=d.status.value if hasattr(d.status, "value") else str(d.status),
            attempt_count=d.attempt_count,
            last_http_status=d.last_http_status,
            created_at=d.created_at,
        )
        for d in event.deliveries
    ]

    successful_count = sum(1 for d in event.deliveries if str(d.status) in ("SUCCESS", "DeliveryStatus.SUCCESS"))

    return EventDetailResponse(
        id=event.id,
        event_type=event.event_type,
        payload=event.payload,
        idempotency_key=event.idempotency_key,
        created_at=event.created_at,
        deliveries_count=len(event.deliveries),
        successful_deliveries_count=successful_count,
        deliveries=deliveries_summary,
    )
