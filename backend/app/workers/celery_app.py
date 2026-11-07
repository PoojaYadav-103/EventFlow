from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "eventflow",
    broker=settings.get_celery_broker_url(),
    backend=settings.get_celery_backend_url(),
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
)

# Auto-discover tasks in app.workers.tasks
celery_app.autodiscover_tasks(["app.workers"])

# Scheduled periodic tasks for Outbox Relay and Retries
celery_app.conf.beat_schedule = {
    "outbox-relay-sweeper": {
        "task": "app.workers.tasks.sweep_outbox_task",
        "schedule": 2.0,  # Sweeps pending outbox records every 2 seconds
    },
    "retry-delivery-sweeper": {
        "task": "app.workers.tasks.sweep_retries_task",
        "schedule": 10.0,  # Sweeps overdue retries every 10 seconds
    },
}
