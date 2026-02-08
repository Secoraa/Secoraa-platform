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
            # Remove global unique constraint on domain_name if it exists
            conn.execute(text("""
                ALTER TABLE domains
                DROP CONSTRAINT IF EXISTS domains_domain_name_key;
            """))

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

    # subdomains table
    if inspector.has_table("subdomains"):
        with engine.begin() as conn:
            conn.execute(text("""
                ALTER TABLE subdomains
                DROP CONSTRAINT IF EXISTS subdomains_domain_id_subdomain_name_key;
            """))

    # ipaddress table
    if inspector.has_table("ipaddress"):
        with engine.begin() as conn:
            conn.execute(text("""
                ALTER TABLE ipaddress
                DROP CONSTRAINT IF EXISTS ipaddress_domain_id_ipaddress_name_key;
            """))

    # urls table
    if inspector.has_table("urls"):
        with engine.begin() as conn:
            conn.execute(text("""
                ALTER TABLE urls
                DROP CONSTRAINT IF EXISTS urls_domain_id_url_name_key;
            """))

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
    try:
        Base.metadata.create_all(bind=engine)
        add_missing_columns()
    except Exception as exc:
        print(f"❌ Migration failed: {exc}")
        raise
    print("✅ Database schema ready")

