from fastapi import APIRouter
from app.api.v1.endpoints import router as endpoints_router
from app.api.v1.events import router as events_router
from app.api.v1.deliveries import router as deliveries_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.mock_receiver import router as mock_receiver_router
from app.api.v1.outbox import router as outbox_router

api_router = APIRouter()
api_router.include_router(endpoints_router)
api_router.include_router(events_router)
api_router.include_router(deliveries_router)
api_router.include_router(dashboard_router)
api_router.include_router(mock_receiver_router)
api_router.include_router(outbox_router)
