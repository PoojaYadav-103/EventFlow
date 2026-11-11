import asyncio
import collections
import enum
import json
import math
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session, joinedload

from app.database.session import SessionLocal
from app.models.delivery import Delivery
from app.core.config import settings
from app.core.security import verify_signature_detailed, mask_secret
from app.schemas.mock_receiver import MockWebhookLog, MockReceiverConfig

router = APIRouter(prefix="/mock-receiver", tags=["Mock Webhook Receiver"])


class ReplayRecordResult(str, enum.Enum):
    ACCEPTED = "ACCEPTED"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    CAPACITY_EXHAUSTED = "CAPACITY_EXHAUSTED"


class InMemoryReplayStore:
    """
    Thread-safe, bounded, TTL-evicted in-memory replay store with fail-closed capacity limits.

    Process-Local Scope Limitations:
    - This store is local to the active Python process.
    - In horizontally-scaled deployments across multiple process workers or container replicas,
      replayed requests routed to different processes would not share cache state.
    - In multi-process production environments, a centralized distributed store such as Redis
      (e.g., SET key EX 300 NX) is standard.
    - For EventFlow's mock receiver and demonstration test harness, this process-local store
      provides robust replay mitigation without introducing external database migrations or Redis dependencies.

    Fail-Closed Policy:
    - Purges expired entries before checking or recording.
    - Never evicts unexpired entries when capacity is reached.
    - If capacity is exhausted, fails closed and rejects new entries (returns CAPACITY_EXHAUSTED).
    """
    def __init__(self, max_entries: int = 10000, default_ttl_seconds: float = 300.0):
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise ValueError("max_entries must be a positive integer > 0.")
        if (
            isinstance(default_ttl_seconds, bool)
            or not isinstance(default_ttl_seconds, (int, float))
            or math.isnan(default_ttl_seconds)
            or math.isinf(default_ttl_seconds)
            or default_ttl_seconds <= 0
            or default_ttl_seconds > 86400
        ):
            raise ValueError("default_ttl_seconds must be a positive finite number <= 86400 (24 hours).")

        self._lock = threading.Lock()
        self._entries: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._max_entries = max_entries
        self._default_ttl = float(default_ttl_seconds)

    def check_and_record(self, key: str, ttl: Optional[float] = None) -> ReplayRecordResult:
        """
        Atomically checks if key exists and is unexpired under the mutex.
        If key exists and is unexpired -> REPLAY_DETECTED.
        If capacity is exhausted after purging expired items -> CAPACITY_EXHAUSTED (fail closed).
        Otherwise records the key and returns ACCEPTED.
        """
        if ttl is not None:
            if (
                isinstance(ttl, bool)
                or not isinstance(ttl, (int, float))
                or math.isnan(ttl)
                or math.isinf(ttl)
                or ttl <= 0
            ):
                raise ValueError("TTL must be a positive finite number.")
            effective_ttl = float(ttl)
        else:
            effective_ttl = self._default_ttl

        if not key or not str(key).strip():
            return ReplayRecordResult.REPLAY_DETECTED

        with self._lock:
            now = time.time()
            # Step 1: Active purge of expired entries
            expired = [k for k, exp in self._entries.items() if exp <= now]
            for k in expired:
                del self._entries[k]

            # Step 2: Replay check
            if key in self._entries:
                return ReplayRecordResult.REPLAY_DETECTED

            # Step 3: Fail-closed capacity check: never evict unexpired entries
            if len(self._entries) >= self._max_entries:
                return ReplayRecordResult.CAPACITY_EXHAUSTED

            # Step 4: Record new authenticated entry with expiration timestamp
            self._entries[key] = now + effective_ttl
            return ReplayRecordResult.ACCEPTED

    def clear(self) -> None:
        """Reset replay store."""
        with self._lock:
            self._entries.clear()


_replay_store = InMemoryReplayStore(
    max_entries=10000,
    default_ttl_seconds=float(settings.SIGNATURE_TOLERANCE_SECONDS),
)


def reset_replay_store_for_testing() -> None:
    """Internal test helper to reset the replay store for test isolation."""
    _replay_store.clear()

# In-memory storage for test receiver
_mock_logs: List[MockWebhookLog] = []
_mock_config = {
    "status_code": 200,
    "delay_seconds": 0.0,
    "reject_all": False,
    "signing_secret": None,
}


@router.post("/webhook", summary="Receive mock webhook POST")
async def receive_webhook(request: Request):
    """
    Simulated webhook destination endpoint.
    Logs received headers and payloads, performs cryptographic HMAC-SHA256
    signature verification using the endpoint secret, guards against replay attacks,
    and returns a configurable response.
    """
    global _mock_logs, _mock_config, _replay_store

    if _mock_config.get("reject_all"):
        return Response(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content="Simulated network failure")

    delay = _mock_config.get("delay_seconds", 0.0)
    if delay > 0:
        await asyncio.sleep(delay)

    headers = dict(request.headers)
    body_bytes = await request.body()
    raw_body_str = body_bytes.decode("utf-8") if body_bytes else ""
    try:
        payload = json.loads(raw_body_str) if raw_body_str else {}
    except Exception:
        payload = {"raw": raw_body_str}

    sig_header = headers.get("x-eventflow-signature")
    aux_ts_header = headers.get("x-eventflow-timestamp")
    event_id = headers.get("x-eventflow-event-id")
    delivery_id = headers.get("x-eventflow-delivery-id")
    event_type = headers.get("x-eventflow-event-type")

    # Resolve signing secret according to strict precedence:
    # 1. Explicit per-request override (?secret=... query param or X-Signing-Secret header)
    # 2. Database lookup: When a delivery ID identifies an existing delivery, its endpoint's
    #    database secret MUST be authoritative. Do not silently fall back to a global mock secret
    #    if the delivery or endpoint secret is missing.
    # 3. Fallback: Only if delivery is unknown in DB (e.g. standalone test mocks without DB fixtures),
    #    fall back to configured global mock secret (_mock_config["signing_secret"]).
    secret: Optional[str] = (
        request.query_params.get("secret")
        or headers.get("x-signing-secret")
    )

    is_delivery_known = False

    if not secret and (delivery_id or event_id):
        try:
            db = SessionLocal()
            try:
                delivery = None
                if delivery_id:
                    delivery = (
                        db.query(Delivery)
                        .options(joinedload(Delivery.endpoint))
                        .filter(Delivery.id == delivery_id)
                        .first()
                    )
                if not delivery and event_id:
                    delivery = (
                        db.query(Delivery)
                        .options(joinedload(Delivery.endpoint))
                        .filter(Delivery.event_id == event_id)
                        .first()
                    )
                if delivery:
                    is_delivery_known = True
                    if delivery.endpoint and delivery.endpoint.secret:
                        secret = delivery.endpoint.secret
                    else:
                        # Delivery exists in DB, but has no endpoint or secret.
                        # As required: do not silently fall back to global mock secret.
                        secret = None
            finally:
                db.close()
        except Exception:
            pass

    # Fallback to configured global secret ONLY when delivery is not a known DB delivery
    if not secret and not is_delivery_known:
        secret = _mock_config.get("signing_secret")

    # Verification & Replay Protection with Explicit HTTP Rejection
    is_valid_sig: bool = False
    is_replay: bool = False
    is_capacity_exhausted: bool = False
    rejection_response: Optional[Response] = None

    if secret or sig_header:
        if not sig_header:
            is_valid_sig = False
            rejection_response = Response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=json.dumps({"error": "Missing signature header", "delivery_id": delivery_id, "signature_valid": False}),
                media_type="application/json",
            )
        elif not secret:
            is_valid_sig = False
            rejection_response = Response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=json.dumps({"error": "Unknown endpoint or signing secret", "delivery_id": delivery_id, "signature_valid": False}),
                media_type="application/json",
            )
        else:
            sig_result = verify_signature_detailed(
                secret=secret,
                payload=body_bytes,  # Verified against exact raw request body bytes
                header_value=sig_header,
                tolerance_seconds=settings.SIGNATURE_TOLERANCE_SECONDS,
                future_tolerance_seconds=settings.SIGNATURE_FUTURE_TOLERANCE_SECONDS,
                auxiliary_timestamp_header=aux_ts_header,
            )
            is_valid_sig = sig_result.is_valid

            if not is_valid_sig:
                rejection_response = Response(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content=json.dumps({
                        "error": f"Invalid signature: {sig_result.error_message}",
                        "delivery_id": delivery_id,
                        "signature_valid": False,
                    }),
                    media_type="application/json",
                )
            else:
                # Cryptographic verification SUCCEEDED!
                # Dynamic TTL from actual remaining signature validity (no artificial extension)
                now = time.time()
                remaining_validity = (sig_result.timestamp + settings.SIGNATURE_TOLERANCE_SECONDS) - now

                if remaining_validity <= 0:
                    is_valid_sig = False
                    rejection_response = Response(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content=json.dumps({
                            "error": "Invalid signature: remaining signature validity expired",
                            "delivery_id": delivery_id,
                            "signature_valid": False,
                        }),
                        media_type="application/json",
                    )
                else:
                    replay_key = f"sig:{sig_result.matched_digest}"
                    store_res = _replay_store.check_and_record(replay_key, ttl=remaining_validity)

                    if store_res == ReplayRecordResult.REPLAY_DETECTED:
                        is_replay = True
                        is_valid_sig = False
                        rejection_response = Response(
                            status_code=status.HTTP_409_CONFLICT,
                            content=json.dumps({
                                "error": "Webhook replay detected",
                                "delivery_id": delivery_id,
                                "signature_valid": False,
                                "replay_detected": True,
                            }),
                            media_type="application/json",
                        )
                    elif store_res == ReplayRecordResult.CAPACITY_EXHAUSTED:
                        is_capacity_exhausted = True
                        is_valid_sig = False
                        rejection_response = Response(
                            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            content=json.dumps({
                                "error": "Replay cache capacity exhausted",
                                "delivery_id": delivery_id,
                                "signature_valid": False,
                                "capacity_exhausted": True,
                            }),
                            media_type="application/json",
                        )

    log_entry = MockWebhookLog(
        id=str(uuid.uuid4()),
        received_at=datetime.now(timezone.utc),
        event_id=event_id,
        delivery_id=delivery_id,
        event_type=event_type,
        signature_header=sig_header,
        signature_valid=is_valid_sig,
        headers=headers,
        payload=payload,
    )
    # Keep last 100 entries
    _mock_logs.insert(0, log_entry)
    if len(_mock_logs) > 100:
        _mock_logs.pop()

    # If rejected due to authentication, replay, or capacity exhaustion, return explicit rejection
    if rejection_response is not None:
        return rejection_response

    # Only successfully authenticated, non-replayed requests reach the configurable mock response
    resp_code = _mock_config.get("status_code", 200)
    return Response(
        status_code=resp_code,
        content=json.dumps({
            "received": True,
            "delivery_id": delivery_id,
            "signature_valid": is_valid_sig,
            "replay_detected": is_replay,
        }),
        media_type="application/json",
    )


@router.get("/logs", response_model=List[MockWebhookLog], summary="Get mock receiver received logs")
def get_mock_logs():
    return _mock_logs


@router.delete("/logs", status_code=status.HTTP_204_NO_CONTENT, summary="Clear mock receiver logs")
def clear_mock_logs():
    """Clears received webhook log history without weakening or resetting the replay store."""
    global _mock_logs
    _mock_logs = []
    return None


@router.post("/config", response_model=MockReceiverConfig, summary="Configure mock receiver response behavior")
def configure_mock_receiver(config: MockReceiverConfig):
    global _mock_config
    _mock_config["status_code"] = config.status_code
    _mock_config["delay_seconds"] = config.delay_seconds
    _mock_config["reject_all"] = config.reject_all

    # Explicit secret clearing or setting
    if "signing_secret" in config.model_fields_set:
        val = config.signing_secret
        if not val or not val.strip():
            _mock_config["signing_secret"] = None
        elif "••••" not in val:
            # Only set raw secret if it's not a masked string from GET response
            _mock_config["signing_secret"] = val

    # Return the actual current configuration with masked secret (GET/POST consistency)
    return get_mock_config()


@router.get("/config", response_model=MockReceiverConfig, summary="Get mock receiver configuration")
def get_mock_config():
    sec = _mock_config.get("signing_secret")
    masked_sec = mask_secret(sec) if sec else None
    return MockReceiverConfig(
        status_code=_mock_config.get("status_code", 200),
        delay_seconds=_mock_config.get("delay_seconds", 0.0),
        reject_all=_mock_config.get("reject_all", False),
        signing_secret=masked_sec,
    )
