from datetime import datetime, timezone
import logging
from app.workers.celery_app import celery_app
from app.database.session import SessionLocal
from app.services.delivery_service import DeliveryService
from app.models.delivery import Delivery, DeliveryStatus
from app.models.outbox import OutboxEvent, OutboxStatus

from sqlalchemy import or_

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.tasks.deliver_webhook_task", bind=True, max_retries=3)
def deliver_webhook_task(self, delivery_id: str):
    """
    Background Celery task that executes a webhook delivery attempt.
    """
    logger.info(f"Executing delivery task for delivery_id: {delivery_id}")
    db = SessionLocal()
    try:
        delivery = DeliveryService.execute_delivery(db, delivery_id)
        if delivery:
            logger.info(f"Delivery {delivery_id} completed with status: {delivery.status}")
        return {"delivery_id": delivery_id, "status": delivery.status.value if delivery else None}
    except Exception as exc:
        logger.error(f"Error processing delivery {delivery_id}: {exc}", exc_info=True)
        if not celery_app.conf.task_always_eager:
            raise self.retry(exc=exc, countdown=10)
        raise exc
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.sweep_outbox_task")
def sweep_outbox_task():
    """
    Sweeper task implementing the Transactional Outbox Relay.
    Picks up pending outbox records (where scheduled_for is due) and publishes
    tasks to the Redis/Celery broker.

    At-least-once dispatch semantics:
    If broker publishing succeeds, the record is marked PUBLISHED.
    If broker publishing raises an error (e.g. broker unreachable), the record
    remains in PENDING state and will be retried on the next sweep cycle.
    If Redis accepts a task but the database transaction fails before PUBLISHED
    is committed, the delivery task may be re-published on the next sweep.
    Worker-side idempotency checks in DeliveryService guarantee that duplicate
    dispatches do not result in duplicate deliveries.
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        query = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.status == OutboxStatus.PENDING,
                or_(OutboxEvent.scheduled_for.is_(None), OutboxEvent.scheduled_for <= now),
            )
            .order_by(OutboxEvent.created_at.asc())
            .limit(100)
        )
        # Apply row-level locking on PostgreSQL for multi-worker concurrency
        if db.bind and db.bind.dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)

        pending_outbox = query.all()
        processed = 0
        for item in pending_outbox:
            try:
                deliver_webhook_task.delay(item.delivery_id)
                # Successful publishing to broker
                item.status = OutboxStatus.PUBLISHED
                item.processed_at = datetime.now(timezone.utc)
                processed += 1
            except Exception as e:
                # Broker publication failed: do not mark PUBLISHED; keep retryable in PENDING state
                logger.error(
                    f"Failed to publish delivery task to broker for outbox event {item.id} "
                    f"(delivery_id: {item.delivery_id}): {e}",
                    exc_info=True,
                )
                continue

        if processed > 0:
            db.commit()
        return processed
    except Exception as exc:
        db.rollback()
        logger.error(f"Error in sweep_outbox_task: {exc}", exc_info=True)
        raise exc
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.sweep_retries_task")
def sweep_retries_task():
    """
    Reliability fallback: picks up any deliveries stuck in RETRYING state
    where next_retry_at has passed. Creates scheduled outbox records if missing,
    ensuring that the Outbox Relay remains the sole publisher of delivery tasks to Redis.
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        overdue_retries = (
            db.query(Delivery)
            .filter(
                Delivery.status == DeliveryStatus.RETRYING,
                Delivery.next_retry_at <= now,
            )
            .limit(50)
            .all()
        )
        enqueued_count = 0
        for d in overdue_retries:
            # Check if there is already an active pending outbox event for this delivery
            has_pending_outbox = (
                db.query(OutboxEvent)
                .filter(
                    OutboxEvent.delivery_id == d.id,
                    OutboxEvent.status == OutboxStatus.PENDING,
                )
                .first()
            )
            if not has_pending_outbox:
                outbox_item = OutboxEvent(
                    delivery_id=d.id,
                    status=OutboxStatus.PENDING,
                    scheduled_for=now,
                )
                db.add(outbox_item)
                enqueued_count += 1
        if enqueued_count > 0:
            db.commit()
        return enqueued_count
    except Exception as exc:
        db.rollback()
        logger.error(f"Error in sweep_retries_task: {exc}", exc_info=True)
        raise exc
    finally:
        db.close()
