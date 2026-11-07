from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.core.config import settings
from app.database.session import engine, Base
import app.models  # Ensure all SQLAlchemy models are registered
from app.api.v1 import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Schema lifecycle is strictly governed by Alembic migrations
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="EventFlow is an industry-grade reliable webhook delivery platform featuring asynchronous execution, transactional outbox guarantees, exponential backoff retries, dead-letter queuing, and HMAC-SHA256 signatures.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits local React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API v1 router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["Health"], summary="System health status")
def health_check():
    """
    Checks relational database connectivity and overall platform health.
    """
    db_healthy = False
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            db_healthy = True
    except Exception:
        db_healthy = False

    return {
        "status": "healthy" if db_healthy else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database": "connected" if db_healthy else "disconnected",
    }
