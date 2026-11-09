import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session, joinedload

from app.database.session import SessionLocal
from app.models.delivery import Delivery
from app.core.security import verify_signature, mask_secret
from app.schemas.mock_receiver import MockWebhookLog, MockReceiverConfig

router = APIRouter(prefix="/mock-receiver", tags=["Mock Webhook Receiver"])

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
    signature verification using the endpoint secret, and returns a configurable response.
    """
    global _mock_logs, _mock_config

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

    # Perform authentic cryptographic HMAC-SHA256 signature verification
    is_valid_sig: bool = False
    if sig_header and secret:
        is_valid_sig = verify_signature(
            secret=secret,
            payload_str=raw_body_str,
            header_value=sig_header,
            tolerance_seconds=300,
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

    resp_code = _mock_config.get("status_code", 200)
    return Response(
        status_code=resp_code,
        content=json.dumps({"received": True, "delivery_id": delivery_id, "signature_valid": is_valid_sig}),
        media_type="application/json"
    )


@router.get("/logs", response_model=List[MockWebhookLog], summary="Get mock receiver received logs")
def get_mock_logs():
    return _mock_logs


@router.delete("/logs", status_code=status.HTTP_204_NO_CONTENT, summary="Clear mock receiver logs")
def clear_mock_logs():
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
