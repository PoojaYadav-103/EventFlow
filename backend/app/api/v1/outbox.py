from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.api.deps import get_db
from app.models.outbox import OutboxEvent

router = APIRouter(prefix="/outbox", tags=["Transactional Outbox"])


@router.get("/status", summary="Get outbox queue status")
def get_outbox_status(db: Session = Depends(get_db)):
    """
    Returns counts of outbox events grouped by status.
    The Outbox Relay independently sweeps pending records on a scheduled interval.
    """
    counts = (
        db.query(OutboxEvent.status, func.count(OutboxEvent.id))
        .group_by(OutboxEvent.status)
        .all()
    )
    status_map = {str(row[0]).replace("OutboxStatus.", ""): row[1] for row in counts}
    return {
        "pending": status_map.get("PENDING", 0),
        "published": status_map.get("PUBLISHED", 0),
        "failed": status_map.get("FAILED", 0),
    }

