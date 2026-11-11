from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.endpoint import (
    EndpointCreate,
    EndpointUpdate,
    EndpointResponse,
    EndpointCreatedResponse,
    EndpointSecretRollResponse,
)
from app.services.endpoint_service import EndpointService
from app.core.security import mask_secret
from app.core.ssrf import SSRFProtectionError

router = APIRouter(prefix="/endpoints", tags=["Endpoints"])


@router.post(
    "",
    response_model=EndpointCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new webhook endpoint",
    description="Registers an HTTP/HTTPS destination URL, generates a unique HMAC signing secret, and validates SSRF safety."
)
def create_endpoint(data: EndpointCreate, db: Session = Depends(get_db)):
    try:
        endpoint, secret = EndpointService.create_endpoint(db, data)
        return EndpointCreatedResponse(
            id=endpoint.id,
            url=endpoint.url,
            description=endpoint.description,
            is_active=endpoint.is_active,
            event_types=endpoint.event_types,
            rate_limit_per_minute=endpoint.rate_limit_per_minute,
            signing_secret=secret,
            signing_secret_masked=mask_secret(secret),
            created_at=endpoint.created_at,
            updated_at=endpoint.updated_at,
            deliveries_count=0,
        )
    except SSRFProtectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSRF Protection Error: {str(e)}"
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )


@router.get(
    "",
    response_model=List[EndpointResponse],
    summary="List registered webhook endpoints",
    description="Lists registered webhook endpoints with masked secrets and aggregated delivery counts."
)
def list_endpoints(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    db: Session = Depends(get_db),
):
    results = EndpointService.get_endpoints(db, skip=skip, limit=limit, is_active=is_active)
    responses = []
    for ep, count in results:
        responses.append(
            EndpointResponse(
                id=ep.id,
                url=ep.url,
                description=ep.description,
                is_active=ep.is_active,
                event_types=ep.event_types,
                rate_limit_per_minute=ep.rate_limit_per_minute,
                signing_secret_masked=mask_secret(ep.secret),
                created_at=ep.created_at,
                updated_at=ep.updated_at,
                deliveries_count=count,
            )
        )
    return responses


@router.get(
    "/{endpoint_id}",
    response_model=EndpointResponse,
    summary="Get webhook endpoint details",
)
def get_endpoint(endpoint_id: str, db: Session = Depends(get_db)):
    endpoint = EndpointService.get_endpoint_by_id(db, endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    
    count = len(endpoint.deliveries)
    return EndpointResponse(
        id=endpoint.id,
        url=endpoint.url,
        description=endpoint.description,
        is_active=endpoint.is_active,
        event_types=endpoint.event_types,
        rate_limit_per_minute=endpoint.rate_limit_per_minute,
        signing_secret_masked=mask_secret(endpoint.secret),
        created_at=endpoint.created_at,
        updated_at=endpoint.updated_at,
        deliveries_count=count,
    )


@router.patch(
    "/{endpoint_id}",
    response_model=EndpointResponse,
    summary="Update webhook endpoint",
)
def update_endpoint(
    endpoint_id: str,
    data: EndpointUpdate,
    db: Session = Depends(get_db),
):
    try:
        endpoint = EndpointService.update_endpoint(db, endpoint_id, data)
        if not endpoint:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
        
        return EndpointResponse(
            id=endpoint.id,
            url=endpoint.url,
            description=endpoint.description,
            is_active=endpoint.is_active,
            event_types=endpoint.event_types,
            rate_limit_per_minute=endpoint.rate_limit_per_minute,
            signing_secret_masked=mask_secret(endpoint.secret),
            created_at=endpoint.created_at,
            updated_at=endpoint.updated_at,
            deliveries_count=len(endpoint.deliveries),
        )
    except SSRFProtectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSRF Protection Error: {str(e)}"
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )


@router.post(
    "/{endpoint_id}/roll-secret",
    response_model=EndpointSecretRollResponse,
    summary="Rotate/roll endpoint signing secret",
)
def roll_secret(endpoint_id: str, db: Session = Depends(get_db)):
    result = EndpointService.roll_signing_secret(db, endpoint_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    
    endpoint, new_secret = result
    return EndpointSecretRollResponse(
        endpoint_id=endpoint.id,
        signing_secret=new_secret,
        signing_secret_masked=mask_secret(new_secret),
        message="Signing secret rotated successfully. Ensure your receiving service updates its verification key."
    )


@router.delete(
    "/{endpoint_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete webhook endpoint",
)
def delete_endpoint(endpoint_id: str, db: Session = Depends(get_db)):
    success = EndpointService.delete_endpoint(db, endpoint_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    return None
