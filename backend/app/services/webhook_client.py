import asyncio
import concurrent.futures
import enum
import email.utils
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
import httpx

from app.core.config import settings
from app.core.security import sign_payload
from app.core.ssrf import validate_webhook_url, SSRFProtectionError


class HTTPOutcome(str, enum.Enum):
    SUCCESS = "SUCCESS"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    PERMANENT_FAILURE = "PERMANENT_FAILURE"


def sanitize_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Redact sensitive headers (Authorization, Cookie, complete signatures)."""
    if not headers:
        return {}
    sensitive_keys = {"authorization", "cookie", "set-cookie", "proxy-authorization"}
    sanitized = {}
    for k, v in headers.items():
        lower_k = k.lower()
        if lower_k in sensitive_keys:
            sanitized[k] = "[REDACTED]"
        elif lower_k == "x-eventflow-signature" and len(v) > 20:
            parts = v.split("v1=")
            if len(parts) == 2:
                prefix = parts[0] + "v1="
                digest = parts[1]
                sanitized[k] = f"{prefix}{digest[:6]}...{digest[-4:]}"
            else:
                sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


def parse_retry_after(header_value: Optional[str], max_delay: float) -> Optional[float]:
    """
    Parses Retry-After header supporting:
    1. Integer/float delay-seconds (e.g. "120")
    2. RFC 7231 / RFC 2822 HTTP-date (e.g. "Wed, 21 Oct 2026 07:28:00 GMT")
    Returns capped seconds or None if missing/invalid.
    """
    if not header_value or not str(header_value).strip():
        return None
    val = str(header_value).strip()

    # 1. Decimal or integer seconds
    try:
        seconds = float(val)
        if seconds > 0:
            return round(min(max_delay, seconds), 2)
        return None
    except ValueError:
        pass

    # 2. HTTP-Date
    try:
        dt = email.utils.parsedate_to_datetime(val)
        if dt is not None:
            now = datetime.now(timezone.utc)
            delta = (dt - now).total_seconds()
            if delta > 0:
                return round(min(max_delay, delta), 2)
    except Exception:
        pass

    return None


def classify_webhook_outcome(
    http_status: Optional[int],
    error_message: Optional[str] = None,
    is_timeout: bool = False,
    is_connection_error: bool = False,
    is_ssrf_error: bool = False,
) -> HTTPOutcome:
    """
    Centralized HTTP retry policy:
    - HTTP 2xx -> SUCCESS
    - Network drops, timeouts, HTTP 408, 425, 429, 5xx -> RETRYABLE_FAILURE
    - Other HTTP 4xx, SSRF blocks -> PERMANENT_FAILURE
    """
    if is_ssrf_error:
        return HTTPOutcome.PERMANENT_FAILURE

    if is_timeout or is_connection_error:
        return HTTPOutcome.RETRYABLE_FAILURE

    if http_status is None:
        return HTTPOutcome.PERMANENT_FAILURE

    if 200 <= http_status < 300:
        return HTTPOutcome.SUCCESS

    if http_status in settings.RETRYABLE_STATUS_CODES:
        return HTTPOutcome.RETRYABLE_FAILURE

    return HTTPOutcome.PERMANENT_FAILURE


class WebhookExecutionResult:
    def __init__(
        self,
        success: bool,
        http_status: Optional[int],
        response_time_ms: int,
        request_headers: Dict[str, str],
        response_headers: Optional[Dict[str, str]] = None,
        response_body: Optional[str] = None,
        error_message: Optional[str] = None,
        outcome: Optional[HTTPOutcome] = None,
        retry_after_seconds: Optional[float] = None,
    ):
        self.success = success
        self.http_status = http_status
        self.response_time_ms = response_time_ms
        self.request_headers = sanitize_headers(request_headers)
        self.response_headers = sanitize_headers(response_headers or {})
        self.response_body = response_body
        self.error_message = error_message
        self.retry_after_seconds = retry_after_seconds
        
        if outcome is not None:
            self.outcome = outcome
        elif success:
            self.outcome = HTTPOutcome.SUCCESS
        elif http_status in settings.RETRYABLE_STATUS_CODES or http_status is None:
            self.outcome = HTTPOutcome.RETRYABLE_FAILURE
        else:
            self.outcome = HTTPOutcome.PERMANENT_FAILURE


def _run_with_overall_deadline(coro_fn, *args, **kwargs):
    """
    Safely executes an async coroutine from synchronous worker threads or active event loops.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(lambda: asyncio.run(coro_fn(*args, **kwargs))).result()
    else:
        return asyncio.run(coro_fn(*args, **kwargs))


async def _async_http_post(
    url: str,
    payload_str: str,
    headers: Dict[str, str],
    timeout_seconds: float,
) -> Tuple[int, str, Dict[str, str], str]:
    """
    Executes async HTTP POST under an explicit, cancellable asyncio wall-clock deadline.
    Guarantees immediate task cancellation and TCP socket teardown if the total
    wall-clock duration exceeds timeout_seconds (e.g. slowloris / slow-trickle stream).
    """
    socket_timeout = httpx.Timeout(
        timeout=timeout_seconds,
        connect=min(5.0, timeout_seconds),
        read=timeout_seconds,
        write=timeout_seconds,
        pool=timeout_seconds,
    )
    async with asyncio.timeout(timeout_seconds):
        async with httpx.AsyncClient(timeout=socket_timeout, follow_redirects=False) as client:
            resp = await client.post(
                url,
                content=payload_str,
                headers=headers,
            )
            body_preview = resp.text[:4096] if resp.text else ""
            return resp.status_code, resp.reason_phrase, dict(resp.headers), body_preview


def execute_webhook_request(
    url: str,
    secret: str,
    event_id: str,
    delivery_id: str,
    event_type: str,
    payload: Dict[str, Any],
    timeout_seconds: float = None,
    allow_internal: bool = None,
) -> WebhookExecutionResult:
    """
    Executes a webhook HTTP POST request with HMAC-SHA256 signing,
    SSRF validation, genuine cancellable overall HTTP deadline, Retry-After extraction,
    and outcome classification.
    """
    if timeout_seconds is None:
        timeout_seconds = settings.WEBHOOK_TIMEOUT

    # Enforce overall wall-clock deadline strictly shorter than the delivery lease duration
    max_safe_deadline = max(1.0, settings.LEASE_DURATION_SECONDS - 5.0)
    effective_timeout = min(float(timeout_seconds), max_safe_deadline)

    # 1. SSRF validation check
    try:
        validated_url = validate_webhook_url(url, allow_internal=allow_internal)
    except SSRFProtectionError as e:
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=0,
            request_headers={},
            error_message=f"SSRF Protection blocked request: {str(e)}",
            outcome=HTTPOutcome.PERMANENT_FAILURE,
        )

    # 2. Serialize payload & sign
    payload_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    sig_header, timestamp = sign_payload(secret, payload_str)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "EventFlow-Webhook/1.0",
        "X-EventFlow-Delivery-Id": delivery_id,
        "X-EventFlow-Event-Id": event_id,
        "X-EventFlow-Event-Type": event_type,
        "X-EventFlow-Timestamp": str(timestamp),
        "X-EventFlow-Signature": sig_header,
    }

    start_time = time.perf_counter()
    try:
        status_code, reason_phrase, resp_headers, resp_body_preview = _run_with_overall_deadline(
            _async_http_post,
            validated_url,
            payload_str,
            headers,
            effective_timeout,
        )
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)

        # Inspect Retry-After header for 429 and 503
        retry_after_sec = None
        if status_code in (429, 503):
            retry_after_header = next(
                (v for k, v in resp_headers.items() if k.lower() == "retry-after"),
                None,
            )
            retry_after_sec = parse_retry_after(retry_after_header, settings.RETRY_MAX_DELAY)

        outcome = classify_webhook_outcome(status_code)
        is_success = (outcome == HTTPOutcome.SUCCESS)
        error_msg = None if is_success else f"HTTP Error {status_code}: {reason_phrase}"

        return WebhookExecutionResult(
            success=is_success,
            http_status=status_code,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            response_headers=resp_headers,
            response_body=resp_body_preview,
            error_message=error_msg,
            outcome=outcome,
            retry_after_seconds=retry_after_sec,
        )

    except (TimeoutError, asyncio.TimeoutError, httpx.TimeoutException):
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"Request timed out after {effective_timeout}s total deadline",
            outcome=HTTPOutcome.RETRYABLE_FAILURE,
        )
    except httpx.ConnectError as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"Connection failed: {str(e)}",
            outcome=HTTPOutcome.RETRYABLE_FAILURE,
        )
    except Exception as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"Unexpected network/client error: {type(e).__name__} - {str(e)}",
            outcome=HTTPOutcome.RETRYABLE_FAILURE,
        )
