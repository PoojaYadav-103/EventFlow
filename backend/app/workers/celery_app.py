from celery import Celery, signals, bootsteps
from app.core.config import settings
from app.core.encryption import validate_encryption_key

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

# Validate encryption key at Celery worker launch
class ValidateEncryptionKeyBootStep(bootsteps.Step):
    def __init__(self, parent, **kwargs):
        validate_encryption_key()

celery_app.steps["worker"].add(ValidateEncryptionKeyBootStep)


@signals.worker_init.connect
def validate_celery_worker_key(**kwargs):
    """
    Validates that a valid ENCRYPTION_KEY is available when Celery worker starts.
    Fails fast if missing or invalid.
    """
    validate_encryption_key()


@signals.beat_init.connect
def validate_celery_beat_key(**kwargs):
    """
    Validates that a valid ENCRYPTION_KEY is available when Celery Beat starts.
    Fails fast if missing or invalid.
    """
    validate_encryption_key()

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
    "stuck-deliveries-reaper": {
        "task": "app.workers.tasks.reap_stuck_deliveries_task",
        "schedule": 15.0,  # Sweeps expired worker leases every 15 seconds
    },
}
