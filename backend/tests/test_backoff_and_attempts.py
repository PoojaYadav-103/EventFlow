import email.utils
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.models.delivery import Delivery, DeliveryStatus
from app.models.delivery_attempt import DeliveryAttempt, AttemptStatus
from app.models.endpoint import Endpoint
from app.models.event import Event
from app.services.delivery_service import DeliveryService
from app.services.webhook_client import (
    classify_webhook_outcome,
    parse_retry_after,
    sanitize_headers,
    HTTPOutcome,
    WebhookExecutionResult,
)


def test_exponential_backoff_with_jitter():
    """Verify exponential backoff calculation and jitter bounds."""
    # Attempt 1: min(3600, 5 * 2^0) + uniform(0, 2) => [5.0, 7.0]
    for _ in range(20):
        delay = DeliveryService.calculate_backoff(1)
        assert 5.0 <= delay <= 7.0, f"Attempt 1 delay {delay} outside [5.0, 7.0]"

    # Attempt 2: min(3600, 5 * 2^1) + uniform(0, 2) => [10.0, 12.0]
    for _ in range(20):
        delay = DeliveryService.calculate_backoff(2)
        assert 10.0 <= delay <= 12.0, f"Attempt 2 delay {delay} outside [10.0, 12.0]"

    # Attempt 3: min(3600, 5 * 2^2) + uniform(0, 2) => [20.0, 22.0]
    for _ in range(20):
        delay = DeliveryService.calculate_backoff(3)
        assert 20.0 <= delay <= 22.0, f"Attempt 3 delay {delay} outside [20.0, 22.0]"

    # Attempt 15: capped at max_delay (3600)
    delay_large = DeliveryService.calculate_backoff(15)
    assert delay_large <= settings.RETRY_MAX_DELAY


def test_retry_after_delay_seconds():
    """Verify integer/float seconds parsing from Retry-After header."""
    assert parse_retry_after("120", max_delay=3600.0) == 120.0
    assert parse_retry_after("45.5", max_delay=3600.0) == 45.5
    # Capped at max_delay
    assert parse_retry_after("10000", max_delay=3600.0) == 3600.0
    # Negative / zero / invalid
    assert parse_retry_after("-5", max_delay=3600.0) is None
    assert parse_retry_after("0", max_delay=3600.0) is None
    assert parse_retry_after("invalid", max_delay=3600.0) is None
    assert parse_retry_after(None, max_delay=3600.0) is None


def test_retry_after_http_date():
    """Verify RFC 7231 HTTP-date parsing from Retry-After header."""
    target_time = datetime.now(timezone.utc) + timedelta(seconds=90)
    http_date = email.utils.format_datetime(target_time)

    delay = parse_retry_after(http_date, max_delay=3600.0)
    assert delay is not None
    assert 85.0 <= delay <= 95.0

    # Far future date capped at max_delay
    far_future = datetime.now(timezone.utc) + timedelta(days=10)
    far_http_date = email.utils.format_datetime(far_future)
    assert parse_retry_after(far_http_date, max_delay=3600.0) == 3600.0

    # Past date
    past_time = datetime.now(timezone.utc) - timedelta(seconds=30)
    past_http_date = email.utils.format_datetime(past_time)
    assert parse_retry_after(past_http_date, max_delay=3600.0) is None


def test_calculate_backoff_respects_retry_after():
    """Verify that calculate_backoff honors valid retry_after_seconds."""
    delay = DeliveryService.calculate_backoff(attempt_count=1, retry_after_seconds=42.0)
    assert delay == 42.0

    # Fallback to exponential when retry_after_seconds is None or <= 0
    delay_fallback = DeliveryService.calculate_backoff(attempt_count=1, retry_after_seconds=None)
    assert 5.0 <= delay_fallback <= 7.0


def test_http_outcome_classifier():
    """Verify centralized HTTP status outcome classification."""
    # 2xx -> SUCCESS
    assert classify_webhook_outcome(200) == HTTPOutcome.SUCCESS
    assert classify_webhook_outcome(201) == HTTPOutcome.SUCCESS
    assert classify_webhook_outcome(204) == HTTPOutcome.SUCCESS

    # Configured retryable codes -> RETRYABLE_FAILURE
    assert classify_webhook_outcome(408) == HTTPOutcome.RETRYABLE_FAILURE
    assert classify_webhook_outcome(425) == HTTPOutcome.RETRYABLE_FAILURE
    assert classify_webhook_outcome(429) == HTTPOutcome.RETRYABLE_FAILURE
    assert classify_webhook_outcome(500) == HTTPOutcome.RETRYABLE_FAILURE
    assert classify_webhook_outcome(502) == HTTPOutcome.RETRYABLE_FAILURE
    assert classify_webhook_outcome(503) == HTTPOutcome.RETRYABLE_FAILURE
    assert classify_webhook_outcome(504) == HTTPOutcome.RETRYABLE_FAILURE

    # Timeouts and connection errors -> RETRYABLE_FAILURE
    assert classify_webhook_outcome(None, is_timeout=True) == HTTPOutcome.RETRYABLE_FAILURE
    assert classify_webhook_outcome(None, is_connection_error=True) == HTTPOutcome.RETRYABLE_FAILURE

    # Permanent 4xx client errors -> PERMANENT_FAILURE
    assert classify_webhook_outcome(400) == HTTPOutcome.PERMANENT_FAILURE
    assert classify_webhook_outcome(401) == HTTPOutcome.PERMANENT_FAILURE
    assert classify_webhook_outcome(403) == HTTPOutcome.PERMANENT_FAILURE
    assert classify_webhook_outcome(404) == HTTPOutcome.PERMANENT_FAILURE
    assert classify_webhook_outcome(422) == HTTPOutcome.PERMANENT_FAILURE

    # SSRF error -> PERMANENT_FAILURE
    assert classify_webhook_outcome(None, is_ssrf_error=True) == HTTPOutcome.PERMANENT_FAILURE


def test_header_sanitization():
    """Verify sensitive headers are redacted and signature masked."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer super-secret-token",
        "Cookie": "session=abc123xyz",
        "Proxy-Authorization": "Basic dXNlcjpwYXNz",
        "X-EventFlow-Signature": "t=1731000000,v1=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "X-Custom-Header": "public-value",
    }
    sanitized = sanitize_headers(headers)
    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["Proxy-Authorization"] == "[REDACTED]"
    assert sanitized["X-Custom-Header"] == "public-value"
    # Signature masked
    sig = sanitized["X-EventFlow-Signature"]
    assert "t=1731000000,v1=abcdef...6789" == sig
    assert "super-secret" not in str(sanitized)


def test_unique_constraint_delivery_attempt_number(db_session):
    """Verify database unique constraint prevents duplicate attempt numbers for same delivery."""
    ep = Endpoint(url="https://test.example.com", secret="whsec_test12345", is_active=True, event_types=["*"])
    ev = Event(event_type="test.event", payload={})
    db_session.add_all([ep, ev])
    db_session.commit()

    deliv = Delivery(event_id=ev.id, endpoint_id=ep.id, status=DeliveryStatus.PENDING)
    db_session.add(deliv)
    db_session.commit()

    att1 = DeliveryAttempt(
        delivery_id=deliv.id,
        attempt_number=1,
        status=AttemptStatus.STARTED,
        executed_at=datetime.now(timezone.utc),
    )
    db_session.add(att1)
    db_session.commit()

    # Attempting to insert duplicate attempt_number=1 must raise IntegrityError
    att_dup = DeliveryAttempt(
        delivery_id=deliv.id,
        attempt_number=1,
        status=AttemptStatus.STARTED,
        executed_at=datetime.now(timezone.utc),
    )
    db_session.add(att_dup)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
