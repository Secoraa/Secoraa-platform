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

app.include_router(asset_router)
app.include_router(minio_events_router)
app.include_router(subdomain_router)
app.include_router(subdomain_scan_router)


# ---------------------------------------------------------
# Health Check (REQUIRED for Railway)
# ---------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------
# Startup
# ---------------------------------------------------------
from app.database.session import engine, Base


@app.on_event("startup")
def startup():
    try:
        Base.metadata.create_all(bind=engine)
        start_schedule_worker()
        print("✅ Database initialized")
    except Exception as e:
        print(f"⚠️ Startup warning: {e}")
