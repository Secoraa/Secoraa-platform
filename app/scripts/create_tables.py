# app/scripts/create_tables.py

from sqlalchemy import text, inspect
from app.database.session import engine
from app.database.models import Base


def add_missing_columns():
    inspector = inspect(engine)

    # domains table
    if inspector.has_table("domains"):
        existing_columns = [c["name"] for c in inspector.get_columns("domains")]

        with engine.begin() as conn:
            if "discovery_source" not in existing_columns:
                conn.execute(text("""
                    ALTER TABLE domains
                    ADD COLUMN discovery_source VARCHAR DEFAULT 'manual';
                """))

            if "asn" not in existing_columns:
                conn.execute(text("""
                    ALTER TABLE domains
                    ADD COLUMN asn VARCHAR;
                """))

    # api_scan_reports table
    if inspector.has_table("api_scan_reports"):
        existing_columns = [c["name"] for c in inspector.get_columns("api_scan_reports")]

        with engine.begin() as conn:
            if "asset_url" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE api_scan_reports ADD COLUMN asset_url VARCHAR;"
                ))
            if "minio_bucket" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE api_scan_reports ADD COLUMN minio_bucket VARCHAR;"
                ))
            if "minio_object_name" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE api_scan_reports ADD COLUMN minio_object_name VARCHAR;"
                ))

    # reports table
    if inspector.has_table("reports"):
        existing_columns = [c["name"] for c in inspector.get_columns("reports")]

        with engine.begin() as conn:
            if "minio_bucket" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE reports ADD COLUMN minio_bucket VARCHAR;"
                ))
            if "minio_object_name" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE reports ADD COLUMN minio_object_name VARCHAR;"
                ))


def run_migrations():
    print("🚀 Running database migrations...")
    Base.metadata.create_all(bind=engine)
    add_missing_columns()
    print("✅ Database schema ready")


if __name__ == "__main__":
    run_migrations()
