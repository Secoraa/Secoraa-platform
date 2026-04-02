from __future__ import annotations

import os
from pathlib import Path

# Load .env so the worker has DATABASE_URL, MINIO_*, etc.
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "secoraa",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # Long-running scans — don't kill them
    task_soft_time_limit=1800,  # 30 min soft limit
    task_time_limit=3600,       # 60 min hard limit
)

# Auto-discover tasks from app.worker.tasks
celery_app.autodiscover_tasks(["app.worker"])
