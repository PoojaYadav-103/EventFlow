import logging
import random
import socket
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.models.delivery import Delivery, DeliveryStatus
from app.models.delivery_attempt import DeliveryAttempt, AttemptStatus
from app.models.outbox import OutboxEvent, OutboxStatus
from app.services.webhook_client import execute_webhook_request, HTTPOutcome

logger = logging.getLogger(__name__)


class DeliveryRetryError(Exception):
    """Raised when a manual delivery retry request violates state validation rules."""
    pass


def get_utc_now():
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime is timezone-aware UTC, handling SQLite naive datetimes."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class DeliveryService:
    @staticmethod
    def calculate_backoff(attempt_count: int, retry_after_seconds: Optional[float] = None) -> float:
        """
        Calculate delay for next retry attempt.
        If retry_after_seconds is provided (e.g. from HTTP 429/503 Retry-After header),
        respect it (bounded by settings.RETRY_MAX_DELAY).
        Otherwise, calculate exponential backoff with uniform additive jitter:
        delay = min(max_delay, min(max_delay, base * 2^(attempt - 1)) + uniform(0, jitter))
        """
        if retry_after_seconds is not None and retry_after_seconds > 0:
            return round(min(settings.RETRY_MAX_DELAY, float(retry_after_seconds)), 2)

        base = settings.RETRY_BASE_DELAY
        max_delay = settings.RETRY_MAX_DELAY
        jitter = settings.RETRY_JITTER

        exponential = min(max_delay, base * (2 ** max(0, attempt_count - 1)))
        delay = exponential + random.uniform(0.0, jitter)
        return round(min(max_delay, delay), 2)

    @classmethod
    def renew_lease(
        cls,
        db: Session,
        delivery_id: str,
        lease_token: str,
        extension_seconds: Optional[float] = None,
    ) -> bool:
        """
        Extends the lease duration for an actively processing delivery.
        Only succeeds if lease_token matches and lease has not yet expired.
        """
        if extension_seconds is None:
            extension_seconds = settings.LEASE_DURATION_SECONDS

        now = get_utc_now()
        new_expires_at = now + timedelta(seconds=extension_seconds)

        rows_updated = (
            db.query(Delivery)
            .filter(
                Delivery.id == delivery_id,
                Delivery.lease_token == lease_token,
                Delivery.lease_expires_at > now,
            )
            .update(
                {
                    "lease_expires_at": new_expires_at,
                    "updated_at": now,
                },
                synchronize_session=False,
            )
        )
        if rows_updated > 0:
            db.commit()
            return True
        return False

    @classmethod
    def execute_delivery(
        cls,
        db: Session,
        delivery_id: str,
        worker_id: Optional[str] = None,
    ) -> Optional[Delivery]:
        """
        Executes a delivery attempt using atomic worker leasing, pre-flight attempt tracking,
        strict HTTP timeouts, and post-HTTP CAS fencing.

        State Flow:
        1. Atomically claims delivery with lease_token, lease_expires_at, and lease_worker_id.
        2. Guards against premature retry (next_retry_at <= NOW()).
        3. Pre-flight writes DeliveryAttempt with status=STARTED before HTTP dispatch.
        4. Executes HTTP call outside DB transaction with strict timeout.
        5. Validates lease ownership upon HTTP completion (lease_token == my_token and lease_expires_at > NOW()).
        6. If lease is valid: updates delivery and attempt to terminal/retry state.
        7. If lease expired / stolen (stale worker): reconciles own attempt (UNKNOWN -> SUCCESS/FAILED)
           with audit note; never mutates deliveries table.
        """
        now = get_utc_now()

        # Step 1: Claim delivery row with locking
        query = db.query(Delivery).filter(Delivery.id == delivery_id)
        if db.bind and db.bind.dialect.name == "postgresql":
            query = query.with_for_update(of=Delivery, skip_locked=True)

        delivery: Optional[Delivery] = query.first()
        if not delivery:
            return None

        # Idempotency guard: terminal deliveries are no-ops
        if delivery.status in (DeliveryStatus.SUCCESS, DeliveryStatus.DEAD_LETTER):
            return delivery

        # Safeguard 2: Guard against executing scheduled retries prematurely
        if delivery.next_retry_at is not None and ensure_utc(delivery.next_retry_at) > now:
            logger.info(
                f"Delivery {delivery_id} retry not yet due (scheduled for {delivery.next_retry_at}). Skipping."
            )
            return delivery

        # State eligibility check
        if delivery.status == DeliveryStatus.PROCESSING:
            # If currently PROCESSING and lease is still unexpired, another worker holds it
            if delivery.lease_expires_at is not None and ensure_utc(delivery.lease_expires_at) > now:
                logger.info(
                    f"Delivery {delivery_id} actively held by another worker until {delivery.lease_expires_at}."
                )
                return delivery
            # If lease expired, this worker can re-claim it
        elif delivery.status not in (DeliveryStatus.PENDING, DeliveryStatus.RETRYING):
            return delivery

        # Check endpoint validity
        if not delivery.endpoint or not delivery.endpoint.is_active:
            delivery.status = DeliveryStatus.FAILED
            delivery.last_error = "Target endpoint is inactive or was deleted."
            delivery.updated_at = now
            delivery.next_retry_at = None
            db.commit()
            return delivery

        # Step 2: Establish lease and pre-flight attempt record
        lease_token = str(uuid.uuid4())
        assigned_worker = worker_id or socket.gethostname()
        lease_expires = now + timedelta(seconds=settings.LEASE_DURATION_SECONDS)

        delivery.status = DeliveryStatus.PROCESSING
        delivery.lease_token = lease_token
        delivery.lease_expires_at = lease_expires
        delivery.lease_worker_id = assigned_worker
        delivery.attempt_count += 1
        delivery.updated_at = now

        # Calculate globally sequential attempt_number across all cycles
        max_attempt_num = (
            db.query(func.max(DeliveryAttempt.attempt_number))
            .filter(DeliveryAttempt.delivery_id == delivery.id)
            .scalar()
        ) or 0
        current_attempt_num = max_attempt_num + 1

        # Pre-flight commit attempt with status STARTED before HTTP socket dispatch
        attempt = DeliveryAttempt(
            delivery_id=delivery.id,
            attempt_number=current_attempt_num,
            status=AttemptStatus.STARTED,
            executed_at=now,
        )
        db.add(attempt)
        db.commit()
        attempt_id = attempt.id

        # Extract parameters for HTTP dispatch outside the database transaction
        endpoint_url = delivery.endpoint.url
        endpoint_secret = delivery.endpoint.secret
        event_id = delivery.event.id
        event_type = delivery.event.event_type
        payload = delivery.event.payload

        # Step 3: Perform HTTP Webhook call with strict deadline
        result = execute_webhook_request(
            url=endpoint_url,
            secret=endpoint_secret,
            event_id=event_id,
            delivery_id=delivery.id,
            event_type=event_type,
            payload=payload,
            timeout_seconds=settings.WEBHOOK_TIMEOUT,
            allow_internal=settings.ALLOW_INTERNAL_NETWORKS,
        )

        # Step 4: Finalization with Atomic CAS & Fencing Check (Safeguard 1)
        now_post = get_utc_now()
        cas_query = (
            db.query(Delivery)
            .filter(
                Delivery.id == delivery_id,
                Delivery.lease_token == lease_token,
            )
        )
        if db.bind and db.bind.dialect.name == "postgresql":
            cas_query = cas_query.filter(Delivery.lease_expires_at > now_post).with_for_update(of=Delivery)

        current_delivery = cas_query.first()
        is_lease_valid = (
            current_delivery is not None
            and (current_delivery.lease_expires_at is None or ensure_utc(current_delivery.lease_expires_at) > now_post)
        )

        if is_lease_valid:
            # Lease ownership verified and still active!
            # 1. Update attempt record
            current_attempt = (
                db.query(DeliveryAttempt)
                .filter(DeliveryAttempt.id == attempt_id)
                .first()
            )
            if current_attempt:
                current_attempt.status = (
                    AttemptStatus.SUCCESS if result.outcome == HTTPOutcome.SUCCESS else AttemptStatus.FAILED
                )
                current_attempt.http_status = result.http_status
                current_attempt.response_time_ms = result.response_time_ms
                current_attempt.request_headers = result.request_headers
                current_attempt.response_headers = result.response_headers
                current_attempt.response_body = result.response_body
                current_attempt.error_message = result.error_message

            # 2. Update delivery state
            current_delivery.last_http_status = result.http_status
            current_delivery.updated_at = now_post

            if result.outcome == HTTPOutcome.SUCCESS:
                current_delivery.status = DeliveryStatus.SUCCESS
                current_delivery.last_error = None
                current_delivery.next_retry_at = None
                db.query(OutboxEvent).filter(
                    OutboxEvent.delivery_id == current_delivery.id,
                    OutboxEvent.status == OutboxStatus.PENDING,
                ).update({"status": OutboxStatus.PUBLISHED, "processed_at": now_post})

            elif result.outcome == HTTPOutcome.RETRYABLE_FAILURE:
                current_delivery.last_error = result.error_message
                if current_delivery.attempt_count >= current_delivery.max_attempts:
                    current_delivery.status = DeliveryStatus.DEAD_LETTER
                    current_delivery.next_retry_at = None
                    db.query(OutboxEvent).filter(
                        OutboxEvent.delivery_id == current_delivery.id,
                        OutboxEvent.status == OutboxStatus.PENDING,
                    ).update({"status": OutboxStatus.PUBLISHED, "processed_at": now_post})
                else:
                    current_delivery.status = DeliveryStatus.RETRYING
                    delay_seconds = cls.calculate_backoff(
                        current_delivery.attempt_count,
                        retry_after_seconds=result.retry_after_seconds,
                    )
                    next_eta = now_post + timedelta(seconds=delay_seconds)
                    current_delivery.next_retry_at = next_eta
                    retry_outbox = OutboxEvent(
                        delivery_id=current_delivery.id,
                        status=OutboxStatus.PENDING,
                        scheduled_for=next_eta,
                    )
                    db.add(retry_outbox)

            else:  # PERMANENT_FAILURE (4xx non-retryable, SSRF blocked)
                current_delivery.status = DeliveryStatus.FAILED
                current_delivery.last_error = result.error_message
                current_delivery.next_retry_at = None
                db.query(OutboxEvent).filter(
                    OutboxEvent.delivery_id == current_delivery.id,
                    OutboxEvent.status == OutboxStatus.PENDING,
                ).update({"status": OutboxStatus.PUBLISHED, "processed_at": now_post})

            # Clear lease tokens
            current_delivery.lease_token = None
            current_delivery.lease_expires_at = None
            current_delivery.lease_worker_id = None
            db.commit()
            db.refresh(current_delivery)
            return current_delivery

        else:
            # Stale Worker Late Completion:
            # Worker lease expired or was stolen/reaped.
            # INVARIANT: Worker must NEVER mutate the deliveries table!
            logger.warning(
                f"[STALE WORKER FENCING] Delivery {delivery_id} lease expired or was reclaimed. "
                f"Fencing off worker token {lease_token}."
            )
            current_attempt = (
                db.query(DeliveryAttempt)
                .filter(
                    DeliveryAttempt.id == attempt_id,
                    DeliveryAttempt.status.in_([AttemptStatus.STARTED, AttemptStatus.UNKNOWN]),
                )
                .first()
            )
            if current_attempt:
                current_attempt.status = (
                    AttemptStatus.SUCCESS if result.outcome == HTTPOutcome.SUCCESS else AttemptStatus.FAILED
                )
                current_attempt.http_status = result.http_status
                current_attempt.response_time_ms = result.response_time_ms
                current_attempt.request_headers = result.request_headers
                current_attempt.response_headers = result.response_headers
                current_attempt.response_body = result.response_body
                audit_note = (
                    f"[STALE WORKER RECONCILIATION] Completed with HTTP {result.http_status} after lease expired. "
                    f"Delivery state was not modified. "
                    f"Worker token was {lease_token}."
                )
                if result.error_message:
                    audit_note += f" Original error: {result.error_message}"
                current_attempt.error_message = audit_note
                db.commit()

            return db.query(Delivery).filter(Delivery.id == delivery_id).first()

    @classmethod
    def retry_manually(cls, db: Session, delivery_id: str) -> Optional[Delivery]:
        """
        Manually re-triggers a delivery that has failed or was sent to dead letter.
        Captures original status, validates eligibility, guards against concurrent duplicate
        retries, preserves attempt history, resets active cycle attempt_count to 0,
        and commits the state reset and outbox record atomically.
        """
        query = db.query(Delivery).filter(Delivery.id == delivery_id)
        if db.bind and db.bind.dialect.name == "postgresql":
            query = query.with_for_update(of=Delivery)

        delivery: Optional[Delivery] = query.first()
        if not delivery:
            return None

        original_status = delivery.status

        # Permit manual retry only for eligible failed or dead-letter deliveries
        # Reject retry of SUCCESS, PROCESSING, PENDING and RETRYING deliveries
        if original_status not in (DeliveryStatus.FAILED, DeliveryStatus.DEAD_LETTER):
            raise DeliveryRetryError(
                f"Cannot manually retry delivery with status '{original_status.value}'. "
                f"Only FAILED or DEAD_LETTER deliveries can be manually retried."
            )

        # Guard against duplicate concurrent manual retry requests:
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

        # Reset status to PENDING and clear next_retry_at and lease fields
        delivery.status = DeliveryStatus.PENDING
        delivery.next_retry_at = None
        delivery.last_error = None
        delivery.lease_token = None
        delivery.lease_expires_at = None
        delivery.lease_worker_id = None
        delivery.updated_at = get_utc_now()

        # Reset active cycle attempt count to 0 (Requirement D.2: gives fresh automatic retry cycle quota)
        # Note: All historical attempts remain in delivery_attempts table and next attempt will receive
        # attempt_number = MAX(previous attempt_numbers) + 1.
        delivery.attempt_count = 0

        # Insert OutboxEvent atomically within the exact same database transaction
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
    def reap_stuck_deliveries(cls, db: Session) -> int:
        """
        Crash recovery reaper:
        Identifies deliveries stuck in PROCESSING with expired leases (lease_expires_at <= NOW()).
        Reconciles any in-flight STARTED attempts to UNKNOWN.
        Moves deliveries to RETRYING (with backoff + OutboxEvent) or DEAD_LETTER.
        """
        now = get_utc_now()
        query = (
            db.query(Delivery)
            .filter(
                Delivery.status == DeliveryStatus.PROCESSING,
                Delivery.lease_expires_at <= now,
            )
            .order_by(Delivery.lease_expires_at.asc())
            .limit(100)
        )
        if db.bind and db.bind.dialect.name == "postgresql":
            query = query.with_for_update(of=Delivery, skip_locked=True)

        stuck_deliveries = query.all()
        reaped_count = 0

        for d in stuck_deliveries:
            # 1. Reconcile any in-flight STARTED attempts to UNKNOWN
            db.query(DeliveryAttempt).filter(
                DeliveryAttempt.delivery_id == d.id,
                DeliveryAttempt.status == AttemptStatus.STARTED,
            ).update(
                {
                    "status": AttemptStatus.UNKNOWN,
                    "error_message": "[CRASH REAPER] Worker lease expired. Execution outcome unknown; delivery recovered.",
                },
                synchronize_session=False,
            )

            # 2. Check if attempts exhausted
            if d.attempt_count >= d.max_attempts:
                d.status = DeliveryStatus.DEAD_LETTER
                d.last_error = "Worker lease expired and max delivery attempts exhausted."
                d.next_retry_at = None
                db.query(OutboxEvent).filter(
                    OutboxEvent.delivery_id == d.id,
                    OutboxEvent.status == OutboxStatus.PENDING,
                ).update({"status": OutboxStatus.PUBLISHED, "processed_at": now})
            else:
                d.status = DeliveryStatus.RETRYING
                delay = cls.calculate_backoff(d.attempt_count)
                next_eta = now + timedelta(seconds=delay)
                d.next_retry_at = next_eta
                d.last_error = "Worker lease expired. Automatically recovered for retry."

                # Create scheduled outbox event for retry
                retry_outbox = OutboxEvent(
                    delivery_id=d.id,
                    status=OutboxStatus.PENDING,
                    scheduled_for=next_eta,
                )
                db.add(retry_outbox)

            # 3. Clear lease fields
            d.lease_token = None
            d.lease_expires_at = None
            d.lease_worker_id = None
            d.updated_at = now
            reaped_count += 1

        if reaped_count > 0:
            db.commit()

        return reaped_count

    @classmethod
    def recover_stuck_deliveries(cls, db: Session, threshold_minutes: int = 5) -> int:
        """Backward compatibility alias for reap_stuck_deliveries."""
        return cls.reap_stuck_deliveries(db)
