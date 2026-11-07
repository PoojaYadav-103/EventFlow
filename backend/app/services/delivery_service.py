import random
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.models.delivery import Delivery, DeliveryStatus
from app.models.delivery_attempt import DeliveryAttempt, AttemptStatus
from app.models.outbox import OutboxEvent, OutboxStatus
from app.services.webhook_client import execute_webhook_request


class DeliveryRetryError(Exception):
    """Raised when a manual delivery retry request violates state validation rules."""
    pass


def get_utc_now():
    return datetime.now(timezone.utc)


class DeliveryService:
    @staticmethod
    def calculate_backoff(attempt_count: int) -> float:
        """
        Calculate exponential backoff with full jitter:
        backoff = min(max_backoff, base * 2^(attempt - 1))
        jittered = random.uniform(0.8, 1.2) * backoff
        """
        base = settings.BASE_BACKOFF_SECONDS
        max_backoff = settings.MAX_BACKOFF_SECONDS
        backoff = min(max_backoff, base * (2 ** max(0, attempt_count - 1)))
        # Add jitter between 0.8 and 1.2 to avoid thundering herd
        jitter = random.uniform(0.8, 1.2)
        return round(backoff * jitter, 2)

    @classmethod
    def execute_delivery(cls, db: Session, delivery_id: str) -> Optional[Delivery]:
        """
        Executes a single delivery attempt synchronously within a DB session.
        Handles status transitions, attempt logging, retries, and dead-letter state.
        Safe against duplicate executions (idempotency).
        """
        delivery: Optional[Delivery] = (
            db.query(Delivery)
            .options(
                joinedload(Delivery.endpoint),
                joinedload(Delivery.event),
            )
            .filter(Delivery.id == delivery_id)
            .first()
        )

        if not delivery:
            return None

        # Idempotent guard: if already delivered successfully or dead-lettered, do not re-execute
        if delivery.status in (DeliveryStatus.SUCCESS, DeliveryStatus.DEAD_LETTER):
            return delivery

        # If endpoint was deleted or disabled, do not deliver
        if not delivery.endpoint or not delivery.endpoint.is_active:
            delivery.status = DeliveryStatus.FAILED
            delivery.last_error = "Target endpoint is inactive or was deleted."
            db.commit()
            return delivery

        # Update status to PROCESSING and increment attempt count
        delivery.attempt_count += 1
        current_attempt_num = delivery.attempt_count
        delivery.status = DeliveryStatus.PROCESSING
        delivery.updated_at = get_utc_now()
        db.commit()

        # Perform the actual HTTP webhook call
        result = execute_webhook_request(
            url=delivery.endpoint.url,
            secret=delivery.endpoint.secret,
            event_id=delivery.event.id,
            delivery_id=delivery.id,
            event_type=delivery.event.event_type,
            payload=delivery.event.payload,
            timeout_seconds=settings.DEFAULT_TIMEOUT_SECONDS,
            allow_internal=settings.ALLOW_INTERNAL_NETWORKS,
        )

        # Record attempt log (preserves full attempt history)
        attempt = DeliveryAttempt(
            delivery_id=delivery.id,
            attempt_number=current_attempt_num,
            status=AttemptStatus.SUCCESS if result.success else AttemptStatus.FAILED,
            http_status=result.http_status,
            response_time_ms=result.response_time_ms,
            request_headers=result.request_headers,
            response_headers=result.response_headers,
            response_body=result.response_body,
            error_message=result.error_message,
            executed_at=get_utc_now(),
        )
        db.add(attempt)

        # Update delivery state
        delivery.last_http_status = result.http_status
        delivery.updated_at = get_utc_now()

        if result.success:
            delivery.status = DeliveryStatus.SUCCESS
            delivery.last_error = None
            delivery.next_retry_at = None
            # Cancel / mark processed any lingering pending outbox records for this delivery
            db.query(OutboxEvent).filter(
                OutboxEvent.delivery_id == delivery.id,
                OutboxEvent.status == OutboxStatus.PENDING,
            ).update({"status": OutboxStatus.PUBLISHED, "processed_at": get_utc_now()})
        else:
            delivery.last_error = result.error_message
            if delivery.attempt_count >= delivery.max_attempts:
                # Exhausted all attempts -> Dead Letter Queue
                delivery.status = DeliveryStatus.DEAD_LETTER
                delivery.next_retry_at = None
                # Mark any lingering pending outbox records for this delivery as processed
                db.query(OutboxEvent).filter(
                    OutboxEvent.delivery_id == delivery.id,
                    OutboxEvent.status == OutboxStatus.PENDING,
                ).update({"status": OutboxStatus.PUBLISHED, "processed_at": get_utc_now()})
            else:
                # Schedule retry with exponential backoff via Transactional Outbox
                delivery.status = DeliveryStatus.RETRYING
                delay_seconds = cls.calculate_backoff(delivery.attempt_count)
                next_eta = get_utc_now() + timedelta(seconds=delay_seconds)
                delivery.next_retry_at = next_eta

                # Automatic retry writes an OutboxEvent in the same transaction;
                # the independent Outbox Relay remains the sole publisher of Celery tasks.
                retry_outbox = OutboxEvent(
                    delivery_id=delivery.id,
                    status=OutboxStatus.PENDING,
                    scheduled_for=next_eta,
                )
                db.add(retry_outbox)

        db.commit()
        db.refresh(delivery)
        return delivery

    @classmethod
    def retry_manually(cls, db: Session, delivery_id: str) -> Optional[Delivery]:
        """
        Manually re-triggers a delivery that has failed or was sent to dead letter.
        Captures original status, validates eligibility, guards against concurrent duplicate
        retries, preserves attempt history, and commits the state reset and outbox record atomically.
        """
        query = (
            db.query(Delivery)
            .options(joinedload(Delivery.endpoint), joinedload(Delivery.event))
            .filter(Delivery.id == delivery_id)
        )
        if db.bind and db.bind.dialect.name == "postgresql":
            query = query.with_for_update()

        delivery: Optional[Delivery] = query.first()
        if not delivery:
            return None

        # 1. Capture original status
        original_status = delivery.status

        # 2. Permit manual retry only for eligible failed or dead-letter deliveries
        # Reject retry of SUCCESS, PROCESSING, PENDING and RETRYING deliveries
        if original_status not in (DeliveryStatus.FAILED, DeliveryStatus.DEAD_LETTER):
            raise DeliveryRetryError(
                f"Cannot manually retry delivery with status '{original_status.value}'. "
                f"Only FAILED or DEAD_LETTER deliveries can be manually retried."
            )

        # 3. Guard against duplicate concurrent manual retry requests:
        # Check if an outbox record for this delivery was already inserted and is still pending
        existing_pending = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.delivery_id == delivery.id,
                OutboxEvent.status == OutboxStatus.PENDING,
            )
            .first()
        )
        if existing_pending:
            raise DeliveryRetryError(
                "A retry for this delivery is already pending in the transactional outbox."
            )

        # 4. Reset status to PENDING and clear next_retry_at (attempt history is preserved in delivery_attempts)
        delivery.status = DeliveryStatus.PENDING
        delivery.next_retry_at = None
        delivery.last_error = None
        delivery.updated_at = get_utc_now()

        # If it was dead-lettered, increase max_attempts to give retry room to succeed
        if original_status == DeliveryStatus.DEAD_LETTER or delivery.attempt_count >= delivery.max_attempts:
            delivery.max_attempts = max(delivery.max_attempts, delivery.attempt_count + 3)

        # 5. Insert OutboxEvent atomically within the exact same database transaction
        outbox = OutboxEvent(
            delivery_id=delivery.id,
            status=OutboxStatus.PENDING,
            scheduled_for=None,
        )
        db.add(outbox)
        db.commit()
        db.refresh(delivery)
        return delivery

    @classmethod
    def recover_stuck_deliveries(cls, db: Session, threshold_minutes: int = 5) -> int:
        """
        Crash recovery mechanism:
        Identifies deliveries stuck in PROCESSING beyond threshold_minutes
        (e.g., worker container crashed, process killed) and recovers them.
        """
        cutoff = get_utc_now() - timedelta(minutes=threshold_minutes)
        stuck_deliveries = (
            db.query(Delivery)
            .filter(
                Delivery.status == DeliveryStatus.PROCESSING,
                Delivery.updated_at <= cutoff,
            )
            .limit(100)
            .all()
        )

        recovered_count = 0
        for d in stuck_deliveries:
            if d.attempt_count >= d.max_attempts:
                d.status = DeliveryStatus.DEAD_LETTER
                d.last_error = "Worker terminated unexpectedly during processing (attempts exhausted)."
                d.next_retry_at = None
            else:
                d.status = DeliveryStatus.RETRYING
                d.last_error = "Worker terminated unexpectedly. Automatically recovered for retry."
                delay = cls.calculate_backoff(d.attempt_count)
                d.next_retry_at = get_utc_now() + timedelta(seconds=delay)
            d.updated_at = get_utc_now()
            recovered_count += 1

        if recovered_count > 0:
            db.commit()

        return recovered_count
