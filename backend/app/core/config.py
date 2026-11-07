from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "EventFlow"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = "sqlite:///./eventflow.db"
    # For Docker: postgresql+psycopg://postgres:postgres@postgres:5432/eventflow
    
    # Redis & Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None
    CELERY_TASK_ALWAYS_EAGER: bool = False  # Set to True for synchronous testing/dev
    
    # Webhook Delivery Settings
    DEFAULT_TIMEOUT_SECONDS: float = 10.0
    MAX_DELIVERY_ATTEMPTS: int = 5
    BASE_BACKOFF_SECONDS: float = 5.0
    MAX_BACKOFF_SECONDS: float = 3600.0
    
    # Security & SSRF
    ALLOW_INTERNAL_NETWORKS: bool = True  # Allows localhost/internal IPs in development
    SIGNING_SECRET_PREFIX: str = "whsec_"
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    def get_celery_broker_url(self) -> str:
        return self.CELERY_BROKER_URL or self.REDIS_URL

    def get_celery_backend_url(self) -> str:
        return self.CELERY_RESULT_BACKEND or self.REDIS_URL


settings = Settings()
