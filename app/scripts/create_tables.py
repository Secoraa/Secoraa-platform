# app/scripts/create_tables.py

import os
from pathlib import Path

# Load .env from repo root before any app imports so DATABASE_URL is available
_env_file = Path(__file__).resolve().parents[2] / ".env"
if _env_file.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=_env_file, override=False)
    except ImportError:
        # dotenv not installed — parse manually
        for line in _env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

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

    # users table — add is_email_verified for existing DBs
    if inspector.has_table("users"):
        existing_columns = [c["name"] for c in inspector.get_columns("users")]
        with engine.begin() as conn:
            if "is_email_verified" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE users ADD COLUMN is_email_verified BOOLEAN NOT NULL DEFAULT TRUE;"
                ))

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
        existing_columns = [c["name"] for c in inspector.get_columns("subdomains")]

        with engine.begin() as conn:
            conn.execute(text("""
                ALTER TABLE subdomains
                DROP CONSTRAINT IF EXISTS subdomains_domain_id_subdomain_name_key;
            """))

            if "discovery_source" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE subdomains ADD COLUMN discovery_source VARCHAR DEFAULT 'manual';"
                ))

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

    # scans table - progress tracking columns
    if inspector.has_table("scans"):
        existing_columns = [c["name"] for c in inspector.get_columns("scans")]

        with engine.begin() as conn:
            if "created_by" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE scans ADD COLUMN created_by VARCHAR;"
                ))
            if "progress" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE scans ADD COLUMN progress INTEGER DEFAULT 0;"
                ))
            if "current_phase" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE scans ADD COLUMN current_phase VARCHAR;"
                ))
            if "findings_count" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE scans ADD COLUMN findings_count INTEGER DEFAULT 0;"
                ))
            if "endpoints_total" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE scans ADD COLUMN endpoints_total INTEGER DEFAULT 0;"
                ))
            if "endpoints_scanned" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE scans ADD COLUMN endpoints_scanned INTEGER DEFAULT 0;"
                ))

    # api_keys table
    if not inspector.has_table("api_keys"):
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name VARCHAR NOT NULL,
                    key_prefix VARCHAR(8) NOT NULL,
                    key_hash VARCHAR NOT NULL,
                    scopes VARCHAR[] DEFAULT ARRAY['ci'],
                    is_active BOOLEAN DEFAULT TRUE,
                    last_used_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """))

    # vulnerabilities table — add columns that may be missing from older schemas
    if inspector.has_table("vulnerabilities"):
        existing_columns = [c["name"] for c in inspector.get_columns("vulnerabilities")]

        with engine.begin() as conn:
            if "cvss_vector" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE vulnerabilities ADD COLUMN cvss_vector VARCHAR;"
                ))
            if "recommendation" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE vulnerabilities ADD COLUMN recommendation TEXT;"
                ))
            if "reference" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE vulnerabilities ADD COLUMN reference TEXT;"
                ))
            if "cvss_score" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE vulnerabilities ADD COLUMN cvss_score FLOAT;"
                ))
            if "tags" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE vulnerabilities ADD COLUMN tags VARCHAR[];"
                ))
            if "subdomain_id" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE vulnerabilities ADD COLUMN subdomain_id UUID REFERENCES subdomains(id) ON DELETE CASCADE;"
                ))
            if "description" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE vulnerabilities ADD COLUMN description TEXT;"
                ))
            if "created_by" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE vulnerabilities ADD COLUMN created_by VARCHAR;"
                ))
            if "updated_by" not in existing_columns:
                conn.execute(text(
                    "ALTER TABLE vulnerabilities ADD COLUMN updated_by VARCHAR;"
                ))

    # ip_blocks table (ensure cidr can be nullable for IP selection based blocks)
    if inspector.has_table("ip_blocks"):
        existing_columns = [c["name"] for c in inspector.get_columns("ip_blocks")]
        with engine.begin() as conn:
            if "name" not in existing_columns:
                conn.execute(text("ALTER TABLE ip_blocks ADD COLUMN name VARCHAR;"))
            try:
                conn.execute(text("ALTER TABLE ip_blocks ALTER COLUMN cidr DROP NOT NULL;"))
            except Exception:
                pass


def add_pentest_columns():
    inspector = inspect(engine)
    if not inspector.has_table("pentests"):
        return
    existing_columns = [c["name"] for c in inspector.get_columns("pentests")]
    with engine.begin() as conn:
        if "pentest_type" not in existing_columns:
            conn.execute(text("ALTER TABLE pentests ADD COLUMN pentest_type VARCHAR;"))
        if "assets" not in existing_columns:
            conn.execute(text("ALTER TABLE pentests ADD COLUMN assets JSON;"))
        # Relax legacy NOT NULL constraints so creates can rely solely on assets list
        try:
            conn.execute(text("ALTER TABLE pentests ALTER COLUMN target_type DROP NOT NULL;"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE pentests ALTER COLUMN target_value DROP NOT NULL;"))
        except Exception:
            pass


def run_migrations():
    print("🚀 Running database migrations...")
    try:
        Base.metadata.create_all(bind=engine)
        add_missing_columns()
        add_pentest_columns()
    except Exception as exc:
        print(f"❌ Migration failed: {exc}")
        raise
    print("✅ Database schema ready")


if __name__ == "__main__":
    run_migrations()
