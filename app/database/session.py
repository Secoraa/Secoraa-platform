import os
import logging
import re
import socket
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy import create_engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import QueuePool

logger = logging.getLogger(__name__)

# Render internal hostnames look like dpg-xxxxx-a (no dots). External: dpg-xxxxx-a.oregon-postgres.render.com
_RENDER_INTERNAL_PG_HOST = re.compile(r"^dpg-[a-z0-9]+-a$", re.IGNORECASE)
_RENDER_PG_REGIONS = ("oregon", "ohio", "virginia", "frankfurt", "singapore")


def _normalize_postgres_url(url: str) -> str:
    """Render/Railway often provide postgres:// — SQLAlchemy 2 needs postgresql://."""
    u = (url or "").strip()
    if u.startswith("postgres://"):
        return "postgresql://" + u[len("postgres://") :]
    return u


def _render_external_host_candidates(internal_host: str) -> list[str]:
    """Build likely Render external Postgres hostnames for an internal dpg-*-a host."""
    region_hint = (os.getenv("RENDER_PG_REGION") or os.getenv("POSTGRES_REGION") or "").strip().lower()
    candidates: list[str] = []
    if region_hint:
        candidates.append(f"{internal_host}.{region_hint}-postgres.render.com")
    for region in _RENDER_PG_REGIONS:
        host = f"{internal_host}.{region}-postgres.render.com"
        if host not in candidates:
            candidates.append(host)
    return candidates


def _resolve_render_postgres_host(internal_host: str) -> Optional[str]:
    """Pick a DNS-resolvable Render Postgres hostname when internal short name fails."""
    override = (os.getenv("POSTGRES_HOST") or os.getenv("DATABASE_HOST") or "").strip()
    if override:
        return override

    for candidate in _render_external_host_candidates(internal_host):
        try:
            socket.getaddrinfo(candidate, 5432, type=socket.SOCK_STREAM)
            return candidate
        except socket.gaierror:
            continue
    return None


def _running_on_render() -> bool:
    return bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))


def _ensure_sslmode(url: str, mode: str = "require") -> str:
    """Render external Postgres (*.postgres.render.com) requires SSL."""
    try:
        sa_url = make_url(url)
        query = dict(sa_url.query) if sa_url.query else {}
        if str(query.get("sslmode", "")).lower() in ("require", "verify-ca", "verify-full"):
            return url
        query["sslmode"] = mode
        return str(sa_url.set(query=query))
    except Exception:
        if "sslmode=" in url.lower():
            return url
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}sslmode={mode}"


def _finalize_render_database_url(url: str) -> str:
    """Apply Render-specific URL fixes (SSL, internal vs external host)."""
    host = (urlparse(url).hostname or "").strip()

    # On Render's network, internal host (dpg-*-a) is correct — external URL needs SSL and is slower.
    if not _running_on_render() and host and _RENDER_INTERNAL_PG_HOST.match(host):
        url = _upgrade_render_internal_database_url(url)
        host = (urlparse(url).hostname or "").strip()

    if host and "postgres.render.com" in host:
        url = _ensure_sslmode(url, "require")
    return url


def _upgrade_render_internal_database_url(url: str) -> str:
    """
    If DATABASE_URL uses Render's short internal host (dpg-*-a) and it does not resolve,
    rewrite to the external hostname (dpg-*-a.<region>-postgres.render.com).
    """
    try:
        parsed = urlparse(url)
        internal_host = (parsed.hostname or "").strip()
    except Exception:
        return url

    if not internal_host or not _RENDER_INTERNAL_PG_HOST.match(internal_host):
        return url

    external_host = _resolve_render_postgres_host(internal_host)
    if not external_host or external_host == internal_host:
        return url

    try:
        sa_url = make_url(url)
        upgraded = sa_url.set(host=external_host)
        logger.info(
            "Upgraded Render DATABASE_URL host %s -> %s",
            internal_host,
            external_host,
        )
        return str(upgraded)
    except Exception as exc:
        logger.warning("Could not upgrade Render DATABASE_URL: %s", exc)
        return url


def _resolve_database_url() -> Optional[str]:
    """
    Resolve DB URL for local, Railway, and Render.

    On Render, if the web service has a stale or unlinked internal hostname
    (dpg-…-a) that does not resolve, set DATABASE_EXTERNAL_URL in the dashboard
    to the Postgres *External* connection string from the database Connect menu.
    """
    external = _normalize_postgres_url(os.getenv("DATABASE_EXTERNAL_URL", "") or "")
    if external:
        logger.info("Using DATABASE_EXTERNAL_URL for PostgreSQL")
        return _finalize_render_database_url(external)

    primary = _normalize_postgres_url(os.getenv("DATABASE_URL", "") or "")
    if primary:
        return _finalize_render_database_url(primary)

    return None


DATABASE_URL = _resolve_database_url()

# 2️⃣ Fallback to local Docker variables
if not DATABASE_URL:
    POSTGRES_USER = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
    POSTGRES_DB = os.getenv("POSTGRES_DB")
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")

    if all([POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB]):
        DATABASE_URL = (
            f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
            f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
        )

# 3️⃣ Create engine safely (do NOT crash at import time)
engine = None
SessionLocal = None

if not DATABASE_URL:
    logger.error("❌ DATABASE_URL not set. Database will be unavailable.")
else:
    try:
        parsed = urlparse(DATABASE_URL)
        host = parsed.hostname or ""
        if _RENDER_INTERNAL_PG_HOST.match(host):
            logger.warning(
                "DATABASE_URL still uses short Render host '%s'. Set DATABASE_EXTERNAL_URL "
                "from Postgres → Connect, or verify the database exists and is linked.",
                host,
            )
    except Exception:
        pass
    logger.info("✅ DATABASE_URL detected. Initializing database engine.")

    _connect_args: dict = {}
    _host = (urlparse(DATABASE_URL).hostname or "")
    if "postgres.render.com" in _host:
        _connect_args["sslmode"] = "require"

    engine = create_engine(
        DATABASE_URL,
        connect_args=_connect_args,
        poolclass=QueuePool,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=300,
    )

    SessionLocal = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
    )

# 4️⃣ Base model
Base = declarative_base()


# 5️⃣ Dependency for FastAPI
def get_db():
    if engine is None or SessionLocal is None:
        raise RuntimeError("Database not configured")

    db = SessionLocal()
    try:
        yield db
    except OperationalError as e:
        logger.error(f"❌ Database error: {e}")
        raise
    finally:
        db.close()
