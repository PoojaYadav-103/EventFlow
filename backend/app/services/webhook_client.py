import asyncio
import concurrent.futures
import enum
import email.utils
import json
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
import httpx

from app.core.config import settings
from app.core.pinned_transport import PinnedAsyncHTTPTransport, resolve_verified_ssl_context
from app.core.security import sign_payload
from app.core.ssrf import (
    DNSResolutionTimeoutError,
    PermanentDNSResolutionError,
    SSRFProtectionError,
    TransientDNSResolutionError,
    async_resolve_and_pin_target,
    prevalidate_webhook_url_static,
)


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


def _is_tls_certificate_error(exc: BaseException) -> bool:
    """Walk exception causes to identify TLS certificate or hostname verification failures."""
    seen: set[int] = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ssl.SSLCertVerificationError):
            return True
        if isinstance(cur, ssl.SSLError):
            msg = str(cur).lower()
            if "certificate verify failed" in msg or "hostname mismatch" in msg:
                return True
        cur = cur.__cause__ or cur.__context__
    return False


async def _async_http_post(
    url: str,
    payload_bytes: bytes,
    headers: Dict[str, str],
    timeout_seconds: float,
    allow_internal: Optional[bool] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Tuple[int, str, Dict[str, str], str]:
    """
    Executes async HTTP POST under an explicit, cancellable asyncio wall-clock deadline.
    Resolves DNS and pins the validated IP immediately before TCP connection establishment
    using an isolated per-delivery PinnedAsyncHTTPTransport with pooling disabled.
    """
    verified_ssl_ctx = resolve_verified_ssl_context(ssl_context)
    deadline_start = time.monotonic()

    async with asyncio.timeout(timeout_seconds):
        dns_budget = min(5.0, float(timeout_seconds))
        pinned_target = await async_resolve_and_pin_target(
            url,
            allow_internal=allow_internal,
            dns_timeout=dns_budget,
        )

        remaining_budget = max(0.05, float(timeout_seconds) - (time.monotonic() - deadline_start))
        socket_timeout = httpx.Timeout(
            timeout=remaining_budget,
            connect=min(5.0, remaining_budget),
            read=remaining_budget,
            write=remaining_budget,
            pool=remaining_budget,
        )
        transport = PinnedAsyncHTTPTransport(
            pinned_target,
            ssl_context=verified_ssl_ctx,
        )
        async with httpx.AsyncClient(
            transport=transport,
            timeout=socket_timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            resp = await client.post(
                pinned_target.normalized_url,
                content=payload_bytes,
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
    ssl_context: Optional[ssl.SSLContext] = None,
) -> WebhookExecutionResult:
    """
    Executes a webhook HTTP POST request with HMAC-SHA256 signing,
    SSRF validation + DNS IP pinning, genuine cancellable overall HTTP deadline,
    Retry-After extraction, and outcome classification.
    """
    if timeout_seconds is None:
        timeout_seconds = settings.WEBHOOK_TIMEOUT

    # Enforce strict TLS verification if a custom CA context is supplied (e.g. tests)
    if ssl_context is not None:
        resolve_verified_ssl_context(ssl_context)

    # Enforce overall wall-clock deadline strictly shorter than the delivery lease duration
    max_safe_deadline = max(1.0, settings.LEASE_DURATION_SECONDS - 5.0)
    effective_timeout = min(float(timeout_seconds), max_safe_deadline)

    # 1. Static SSRF pre-validation and URL normalization (no blocking DNS outside deadline)
    try:
        validated_url = prevalidate_webhook_url_static(url, allow_internal=allow_internal)
    except (SSRFProtectionError, ValueError) as e:
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=0,
            request_headers={},
            error_message=f"SSRF Protection blocked request: {str(e)}",
            outcome=HTTPOutcome.PERMANENT_FAILURE,
        )

    # 2. Serialize payload & sign exact raw bytes (single payload_bytes buffer)
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig_header, timestamp = sign_payload(secret, payload_bytes)

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
            payload_bytes,
            headers,
            effective_timeout,
            allow_internal=allow_internal,
            ssl_context=ssl_context,
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

    except PermanentDNSResolutionError as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"SSRF/DNS permanent resolution failure: {str(e)}",
            outcome=HTTPOutcome.PERMANENT_FAILURE,
        )
    except SSRFProtectionError as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"SSRF Protection blocked request: {str(e)}",
            outcome=HTTPOutcome.PERMANENT_FAILURE,
        )
    except TransientDNSResolutionError as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"Temporary DNS resolution failure: {str(e)}",
            outcome=HTTPOutcome.RETRYABLE_FAILURE,
        )
    except (DNSResolutionTimeoutError, TimeoutError, asyncio.TimeoutError, httpx.TimeoutException) as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        msg = (
            f"DNS resolution timed out after {effective_timeout}s total deadline: {str(e)}"
            if isinstance(e, DNSResolutionTimeoutError)
            else f"Request timed out after {effective_timeout}s total deadline"
        )
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=msg,
            outcome=HTTPOutcome.RETRYABLE_FAILURE,
        )
    except httpx.InvalidURL as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"Invalid destination URL: {str(e)}",
            outcome=HTTPOutcome.PERMANENT_FAILURE,
        )
    except httpx.ConnectError as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        if _is_tls_certificate_error(e):
            return WebhookExecutionResult(
                success=False,
                http_status=None,
                response_time_ms=elapsed_ms,
                request_headers=headers,
                error_message=f"TLS certificate verification failed: {str(e)}",
                outcome=HTTPOutcome.PERMANENT_FAILURE,
            )
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
