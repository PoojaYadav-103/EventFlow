from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.endpoint import Endpoint
from app.models.delivery import Delivery
from app.schemas.endpoint import EndpointCreate, EndpointUpdate
from app.core.security import generate_signing_secret, mask_secret
from app.core.ssrf import validate_webhook_url


class EndpointService:
    @staticmethod
    def create_endpoint(db: Session, data: EndpointCreate) -> Tuple[Endpoint, str]:
        """
        Registers a new webhook endpoint.
        Validates URL (including SSRF checks) and generates a cryptographic signing secret.
        Returns (endpoint, unmasked_secret).
        """
        # Validate SSRF and persist canonical normalized URL
        normalized_url = validate_webhook_url(data.url)

        secret = generate_signing_secret()
        endpoint = Endpoint(
            url=normalized_url,
            description=data.description,
            secret=secret,
            is_active=True,
            event_types=data.event_types or ["*"],
            rate_limit_per_minute=data.rate_limit_per_minute,
        )
        db.add(endpoint)
        db.commit()
        db.refresh(endpoint)
        return endpoint, secret

    @staticmethod
    def get_endpoints(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        is_active: Optional[bool] = None,
    ) -> List[Tuple[Endpoint, int]]:
        """
        List endpoints with total delivery counts.
        """
        query = db.query(Endpoint).filter(Endpoint.is_deleted == False)
        if is_active is not None:
            query = query.filter(Endpoint.is_active == is_active)
        
        endpoints = query.order_by(Endpoint.created_at.desc()).offset(skip).limit(limit).all()
        
        # Aggregate delivery counts
        endpoint_ids = [ep.id for ep in endpoints]
        counts = {}
        if endpoint_ids:
            count_rows = (
                db.query(Delivery.endpoint_id, func.count(Delivery.id))
                .filter(Delivery.endpoint_id.in_(endpoint_ids))
                .group_by(Delivery.endpoint_id)
                .all()
            )
            counts = {row[0]: row[1] for row in count_rows}

        return [(ep, counts.get(ep.id, 0)) for ep in endpoints]

    @staticmethod
    def get_endpoint_by_id(db: Session, endpoint_id: str) -> Optional[Endpoint]:
        return db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.is_deleted == False).first()

    @staticmethod
    def update_endpoint(
        db: Session,
        endpoint_id: str,
        data: EndpointUpdate,
    ) -> Optional[Endpoint]:
        endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.is_deleted == False).first()
        if not endpoint:
            return None

        if data.url is not None:
            normalized_url = validate_webhook_url(data.url)
            endpoint.url = normalized_url
        if data.description is not None:
            endpoint.description = data.description
        if data.is_active is not None:
            endpoint.is_active = data.is_active
        if data.event_types is not None:
            endpoint.event_types = data.event_types
        if data.rate_limit_per_minute is not None:
            endpoint.rate_limit_per_minute = data.rate_limit_per_minute

        db.commit()
        db.refresh(endpoint)
        return endpoint

    @staticmethod
    def roll_signing_secret(db: Session, endpoint_id: str) -> Optional[Tuple[Endpoint, str]]:
        endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.is_deleted == False).first()
        if not endpoint:
            return None

        new_secret = generate_signing_secret()
        endpoint.secret = new_secret
        db.commit()
        db.refresh(endpoint)
        return endpoint, new_secret

    @staticmethod
    def delete_endpoint(db: Session, endpoint_id: str) -> bool:
        """
        Soft-deletes the endpoint to preserve historical delivery attempts and audit logs.
        """
        endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.is_deleted == False).first()
        if not endpoint:
            return False
        endpoint.is_deleted = True
        endpoint.is_active = False
        db.commit()
        return True
