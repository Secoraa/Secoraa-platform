import asyncio
import logging

# Configure logging so scanner logs are visible
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
# Reduce noise from third-party libs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("hpack").setLevel(logging.WARNING)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Routers
from app.api.scans import router as scans_router
from app.api.scans import start_schedule_worker
from app.api.api_scanner import router as api_scanner_router
from app.api.auth import router as auth_router
from app.api.vulnerabilities import router as vulnerabilities_router
from app.api.reports import router as reports_router
from app.api.help_center import router as help_center_router
from app.api.settings import router as settings_router
from app.api.ci import router as ci_router

from app.endpoints.assets import router as asset_router
from app.endpoints.subdomain import router as subdomain_router
from app.endpoints.minio_events import router as minio_events_router
from app.endpoints.docs import build_docs_router
from app.endpoints.subdomain_scan import scan_router as subdomain_scan_router

# Docs + static
from app.custom_swagger import mount_static_files, register_custom_docs

# ✅ DB migrations
from app.scripts.create_tables import run_migrations


app = FastAPI(
    title="Secoraa Backend",
    docs_url=None,
    redoc_url=None,
)

# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://localhost:8502",
        "http://127.0.0.1:8502",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://secoraa-platform.vercel.app",
        "https://secorra-platform.vercel.app",
        "https://secoraa-platform-production.up.railway.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# Custom Docs
# ---------------------------------------------------------
DOCS_PATH = "/api/v1alpha1/backend/docs"

mount_static_files(app)
register_custom_docs(app, DOCS_PATH)
app.include_router(build_docs_router(DOCS_PATH))

# ---------------------------------------------------------
# API Routers
# ---------------------------------------------------------
app.include_router(auth_router)
app.include_router(vulnerabilities_router)
app.include_router(reports_router)
app.include_router(scans_router)
app.include_router(api_scanner_router)
app.include_router(help_center_router)
app.include_router(settings_router)
app.include_router(ci_router)

app.include_router(asset_router)
app.include_router(minio_events_router)
app.include_router(subdomain_router)
app.include_router(subdomain_scan_router)


# ---------------------------------------------------------
# Health Check (REQUIRED for Railway)
# ---------------------------------------------------------
logger = logging.getLogger("secoraa.health")


def _check_redis() -> dict:
    try:
        import redis as _redis
        import os
        r = _redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        r.ping()
        return {"status": "up"}
    except Exception as e:
        return {"status": "down", "error": str(e)}


def _check_db() -> dict:
    try:
        from app.database.session import SessionLocal
        if SessionLocal is None:
            return {"status": "down", "error": "not configured"}
        db = SessionLocal()
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db.close()
        return {"status": "up"}
    except Exception as e:
        return {"status": "down", "error": str(e)}


def _check_minio() -> dict:
    try:
        from app.storage.minio_client import get_minio_client, MINIO_BUCKET
        client = get_minio_client()
        client.bucket_exists(MINIO_BUCKET)
        return {"status": "up"}
    except Exception as e:
        return {"status": "down", "error": str(e)}


@app.get("/health")
def health():
    redis_status = _check_redis()
    db_status = _check_db()
    minio_status = _check_minio()

    all_up = all(
        s["status"] == "up" for s in [redis_status, db_status, minio_status]
    )

    return {
        "status": "healthy" if all_up else "degraded",
        "services": {
            "redis": redis_status,
            "database": db_status,
            "minio": minio_status,
        },
    }


# ---------------------------------------------------------
# TEMP: One-time DB migration trigger (remove after use)
# ---------------------------------------------------------
@app.get("/create-tables")
def create_tables():
    run_migrations()
    return {"message": "tables created"}


# ---------------------------------------------------------
# Startup
# ---------------------------------------------------------
from app.database.session import engine, Base


_redis_was_up = True  # track state transitions


async def _redis_heartbeat():
    """Check Redis every 60s. Log warnings on state change."""
    global _redis_was_up
    while True:
        await asyncio.sleep(60)
        status = _check_redis()
        is_up = status["status"] == "up"

        if not is_up and _redis_was_up:
            logger.warning(
                "🔴 Redis is DOWN — background scans will fall back to sync. Error: %s",
                status.get("error", "unknown"),
            )
        elif is_up and not _redis_was_up:
            logger.info("🟢 Redis is back UP — background scan processing restored.")

        _redis_was_up = is_up


@app.on_event("startup")
def startup():
    try:
        Base.metadata.create_all(bind=engine)
        start_schedule_worker()
        print("✅ Database initialized")
    except Exception as e:
        print(f"⚠️ Startup warning: {e}")

    # Start Redis heartbeat monitor
    asyncio.get_event_loop().create_task(_redis_heartbeat())
    redis_status = _check_redis()
    if redis_status["status"] == "up":
        print("✅ Redis connected — Celery background scans enabled")
    else:
        print(f"⚠️ Redis not reachable — scans will run synchronously. Error: {redis_status.get('error')}")
