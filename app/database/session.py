import os
import logging
from fastapi import HTTPException
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.exc import OperationalError, DisconnectionError
from sqlalchemy.pool import QueuePool

logger = logging.getLogger(__name__)

POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_DB = os.getenv("POSTGRES_DB")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "15432")

# Validate required environment variables
if not all([POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB]):
    logger.warning(
        "⚠️  Database environment variables not set. "
        "Please set POSTGRES_USER, POSTGRES_PASSWORD, and POSTGRES_DB"
    )

DATABASE_URL = (
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)

# Create engine with connection pooling and automatic reconnection
engine = create_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    poolclass=QueuePool,
    pool_size=5,  # Number of connections to maintain
    max_overflow=10,  # Maximum number of connections beyond pool_size
    pool_pre_ping=True,  # Automatically reconnect if connection is lost
    pool_recycle=3600,  # Recycle connections after 1 hour
    connect_args={
        "connect_timeout": 10,  # Connection timeout in seconds
    }
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()


def get_db() -> Session:
    """Dependency function for FastAPI to get database session."""
    db = None
    try:
        db = SessionLocal()
        # pool_pre_ping=True handles connection testing automatically
        yield db
    except (OperationalError, DisconnectionError) as e:
        if db:
            try:
                db.rollback()
            except:
                pass
            try:
                db.close()
            except:
                pass
        
        error_msg = str(e)
        logger.error(
            f"❌ Database connection error: {error_msg}\n"
            f"   Please ensure PostgreSQL is running on {POSTGRES_HOST}:{POSTGRES_PORT}\n"
            f"   You can start it with: docker-compose up -d postgres"
        )
        
        # Convert to HTTPException with 503 status
        raise HTTPException(
            status_code=503,
            detail=(
                f"Database connection failed. Please ensure PostgreSQL is running on "
                f"{POSTGRES_HOST}:{POSTGRES_PORT}. "
                f"Error: {error_msg}"
            )
        )
    except HTTPException:
        # Re-raise HTTPExceptions (like 503 from connection errors) without modification
        raise
    except Exception as e:
        if db:
            try:
                db.rollback()
            except:
                pass
        logger.error(f"❌ Unexpected database error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Database error: {str(e)}"
        )
    finally:
        if db:
            try:
                db.close()
            except:
                pass
