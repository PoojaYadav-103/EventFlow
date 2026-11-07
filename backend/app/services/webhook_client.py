import json
import time
from typing import Any, Dict, Optional, Tuple
import httpx

from app.core.config import settings
from app.core.security import sign_payload
from app.core.ssrf import validate_webhook_url, SSRFProtectionError


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
    ):
        self.success = success
        self.http_status = http_status
        self.response_time_ms = response_time_ms
        self.request_headers = request_headers
        self.response_headers = response_headers or {}
        self.response_body = response_body
        self.error_message = error_message


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
    SSRF validation, latency measurement, and robust error handling.
    """
    if timeout_seconds is None:
        timeout_seconds = settings.DEFAULT_TIMEOUT_SECONDS

    # 1. SSRF validation check
    try:
        validated_url = validate_webhook_url(url, allow_internal=allow_internal)
    except SSRFProtectionError as e:
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=0,
            request_headers={},
            error_message=f"SSRF Protection blocked request: {str(e)}"
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
        with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
            resp = client.post(
                validated_url,
                content=payload_str,
                headers=headers,
            )
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            
            # Truncate response body if needed (prevent DB overflow)
            resp_body_preview = resp.text[:4096] if resp.text else ""
            resp_headers = dict(resp.headers)
            
            # Consider 2xx as success
            is_success = 200 <= resp.status_code < 300
            error_msg = None if is_success else f"HTTP Error {resp.status_code}: {resp.reason_phrase}"
            
            return WebhookExecutionResult(
                success=is_success,
                http_status=resp.status_code,
                response_time_ms=elapsed_ms,
                request_headers=headers,
                response_headers=resp_headers,
                response_body=resp_body_preview,
                error_message=error_msg,
            )
    except httpx.TimeoutException:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"Request timed out after {timeout_seconds}s"
        )
    except httpx.ConnectError as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"Connection failed: {str(e)}"
        )
    except Exception as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookExecutionResult(
            success=False,
            http_status=None,
            response_time_ms=elapsed_ms,
            request_headers=headers,
            error_message=f"Unexpected error: {type(e).__name__} - {str(e)}"
        )
