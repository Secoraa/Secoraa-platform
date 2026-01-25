import os
import logging
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.exc import OperationalError, DisconnectionError
from sqlalchemy.pool import QueuePool

logger = logging.getLogger(__name__)

# ✅ Prefer Railway DATABASE_URL
DATABASE_URL = os.getenv("DATABASE_URL")

# 🔁 Fallback for LOCAL docker usage
if not DATABASE_URL:
    POSTGRES_USER = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
    POSTGRES_DB = os.getenv("POSTGRES_DB")
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT = os.getenv("POSTGRES_PORT", "15432")

    if not all([POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB]):
        raise RuntimeError(
            "Database config missing. Set DATABASE_URL (Railway) "
            "or POSTGRES_* variables (local)."
        )

    DATABASE_URL = (
        f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
        f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
    )

logger.info(f"📦 Using database: {DATABASE_URL.split('@')[-1]}")

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def get_db() -> Session:
    db = None
    try:
        db = SessionLocal()
        yield db
    except (OperationalError, DisconnectionError) as e:
        logger.error(f"❌ Database connection error: {e}")
        raise HTTPException(status_code=503, detail="Database unavailable")
    finally:
        if db:
            db.close()
