import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import QueuePool

logger = logging.getLogger(__name__)

# 1️⃣ Prefer DATABASE_URL (Railway)
DATABASE_URL = os.getenv("DATABASE_URL")

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
    logger.info("✅ DATABASE_URL detected. Initializing database engine.")

    engine = create_engine(
        DATABASE_URL,
        poolclass=QueuePool,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=3600,
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
