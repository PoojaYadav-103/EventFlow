from typing import List, Optional, Tuple
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, case

from app.models.event import Event
from app.models.endpoint import Endpoint
from app.models.delivery import Delivery, DeliveryStatus
from app.models.outbox import OutboxEvent, OutboxStatus
from app.schemas.event import EventCreate
from app.workers.tasks import deliver_webhook_task
from app.core.config import settings


class EventService:
    @staticmethod
    def publish_event(
        db: Session,
        data: EventCreate,
    ) -> Tuple[Event, List[Delivery], bool]:
        """
        Publishes a new event using the Transactional Outbox pattern.
        Checks idempotency key if provided to prevent duplicate publishing.
        Identifies all active endpoints subscribed to the event_type.
        Creates Event, Delivery, and Outbox records atomically.
        Enqueues asynchronous delivery tasks.
        
        Returns:
            (event, deliveries, is_duplicate)
        """
        # 1. Idempotency verification
        if data.idempotency_key:
            existing_event = (
                db.query(Event)
                .options(joinedload(Event.deliveries))
                .filter(Event.idempotency_key == data.idempotency_key)
                .first()
            )
            if existing_event:
                return existing_event, existing_event.deliveries, True

        # 2. Find eligible active non-deleted endpoints
        active_endpoints = db.query(Endpoint).filter(Endpoint.is_active == True, Endpoint.is_deleted == False).all()
        matched_endpoints: List[Endpoint] = []
        for ep in active_endpoints:
            types = ep.event_types or []
            if "*" in types or data.event_type in types:
                matched_endpoints.append(ep)

        # 3. Create Event record
        event = Event(
            event_type=data.event_type,
            payload=data.payload,
            idempotency_key=data.idempotency_key,
        )
        db.add(event)
        db.flush()  # Populates event.id

        # 4. Create Delivery & Outbox records for each matched endpoint
        created_deliveries: List[Delivery] = []
        for ep in matched_endpoints:
            delivery = Delivery(
                event_id=event.id,
                endpoint_id=ep.id,
                status=DeliveryStatus.PENDING,
                max_attempts=settings.MAX_DELIVERY_ATTEMPTS,
            )
            db.add(delivery)
            db.flush()  # Populates delivery.id

            outbox = OutboxEvent(
                delivery_id=delivery.id,
                status=OutboxStatus.PENDING,
            )
            db.add(outbox)
            created_deliveries.append(delivery)

        # 5. Commit atomic transaction
        db.commit()
        db.refresh(event)

        # Notice: Transactional Outbox is the primary dispatch mechanism.
        # FastAPI does NOT directly enqueue to Celery/Redis from the HTTP request.
        # The outbox processor (sweep_outbox_task) claims pending outbox rows and dispatches them.

        return event, created_deliveries, False

    @staticmethod
    def get_events(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        event_type: Optional[str] = None,
    ) -> List[Tuple[Event, int, int]]:
        """
        List events with counts of total deliveries and successful deliveries.
        Returns: [(event, total_deliveries, successful_deliveries)]
        """
        query = db.query(Event)
        if event_type:
            query = query.filter(Event.event_type == event_type)

        events = query.order_by(Event.created_at.desc()).offset(skip).limit(limit).all()
        if not events:
            return []

        event_ids = [e.id for e in events]

        # Calculate counts
        counts_query = (
            db.query(
                Delivery.event_id,
                func.count(Delivery.id).label("total"),
                func.sum(
                    case((Delivery.status == DeliveryStatus.SUCCESS, 1), else_=0)
                ).label("successful")
            )
            .filter(Delivery.event_id.in_(event_ids))
            .group_by(Delivery.event_id)
            .all()
        )
        counts_map = {row[0]: (row[1], row[2] or 0) for row in counts_query}

        result = []
        for e in events:
            total, success = counts_map.get(e.id, (0, 0))
            result.append((e, total, success))
        return result

    @staticmethod
    def get_event_by_id(db: Session, event_id: str) -> Optional[Event]:
        return (
            db.query(Event)
            .options(
                joinedload(Event.deliveries).joinedload(Delivery.endpoint)
            )
            .filter(Event.id == event_id)
            .first()
        )
