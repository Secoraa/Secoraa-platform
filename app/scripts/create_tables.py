import sys
import os
from pathlib import Path

# Add parent directory to path so we can import app modules
# This needs to happen BEFORE importing app modules
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    env_path = Path(project_root) / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv not installed, skip

from sqlalchemy import text, inspect
from sqlalchemy.exc import ProgrammingError
from app.database.session import engine
from app.database.models import Base, Domain, User, ApiScanReport, Report

def add_missing_columns():
    """Add missing columns to existing tables based on model definitions"""
    inspector = inspect(engine)
    
    # Check Domain table for missing discovery_source column
    if inspector.has_table('domains'):
        existing_columns = [col['name'] for col in inspector.get_columns('domains')]
        
        if 'discovery_source' not in existing_columns:
            print("Adding missing 'discovery_source' column to 'domains' table...")
            try:
                with engine.begin() as conn:
                    conn.execute(text("""
                        ALTER TABLE domains 
                        ADD COLUMN discovery_source VARCHAR DEFAULT 'manual';
                    """))
                    # Update existing rows
                    conn.execute(text("""
                        UPDATE domains 
                        SET discovery_source = 'manual' 
                        WHERE discovery_source IS NULL;
                    """))
                print("✅ Successfully added 'discovery_source' column to 'domains' table")
            except Exception as e:
                print(f"⚠️  Warning: Could not add 'discovery_source' column: {e}")

    # Add missing columns to api_scan_reports if table already exists
    if inspector.has_table('api_scan_reports'):
        existing_columns = [col['name'] for col in inspector.get_columns('api_scan_reports')]
        with engine.begin() as conn:
            if 'asset_url' not in existing_columns:
                try:
                    conn.execute(text("ALTER TABLE api_scan_reports ADD COLUMN asset_url VARCHAR;"))
                    print("✅ Added api_scan_reports.asset_url")
                except Exception as e:
                    print(f"⚠️  Warning: Could not add api_scan_reports.asset_url: {e}")
            if 'minio_bucket' not in existing_columns:
                try:
                    conn.execute(text("ALTER TABLE api_scan_reports ADD COLUMN minio_bucket VARCHAR;"))
                    print("✅ Added api_scan_reports.minio_bucket")
                except Exception as e:
                    print(f"⚠️  Warning: Could not add api_scan_reports.minio_bucket: {e}")
            if 'minio_object_name' not in existing_columns:
                try:
                    conn.execute(text("ALTER TABLE api_scan_reports ADD COLUMN minio_object_name VARCHAR;"))
                    print("✅ Added api_scan_reports.minio_object_name")
                except Exception as e:
                    print(f"⚠️  Warning: Could not add api_scan_reports.minio_object_name: {e}")

    # Add missing columns to vulnerabilities table (older DBs may have only a subset)
    if inspector.has_table('vulnerabilities'):
        existing_columns = [col['name'] for col in inspector.get_columns('vulnerabilities')]
        with engine.begin() as conn:
            def _add(colname: str, ddl: str):
                if colname in existing_columns:
                    return
                try:
                    conn.execute(text(ddl))
                    print(f"✅ Added vulnerabilities.{colname}")
                except Exception as e:
                    print(f"⚠️  Warning: Could not add vulnerabilities.{colname}: {e}")

            _add("description", "ALTER TABLE vulnerabilities ADD COLUMN description TEXT;")
            _add("cvss_score", "ALTER TABLE vulnerabilities ADD COLUMN cvss_score INTEGER;")
            _add("cvss_vectore", "ALTER TABLE vulnerabilities ADD COLUMN cvss_vectore INTEGER;")
            _add("recommendation", "ALTER TABLE vulnerabilities ADD COLUMN recommendation TEXT;")
            _add("reference", "ALTER TABLE vulnerabilities ADD COLUMN reference TEXT;")
            _add("tags", "ALTER TABLE vulnerabilities ADD COLUMN tags TEXT[];")
            _add("created_at", "ALTER TABLE vulnerabilities ADD COLUMN created_at TIMESTAMP;")
            _add("updated_at", "ALTER TABLE vulnerabilities ADD COLUMN updated_at TIMESTAMP;")
            _add("created_by", "ALTER TABLE vulnerabilities ADD COLUMN created_by VARCHAR;")
            _add("updated_by", "ALTER TABLE vulnerabilities ADD COLUMN updated_by VARCHAR;")

    # Reports table: if it exists, ensure new MinIO reference columns exist (older DBs)
    if inspector.has_table('reports'):
        existing_columns = [col['name'] for col in inspector.get_columns('reports')]
        with engine.begin() as conn:
            if 'minio_bucket' not in existing_columns:
                try:
                    conn.execute(text("ALTER TABLE reports ADD COLUMN minio_bucket VARCHAR;"))
                    print("✅ Added reports.minio_bucket")
                except Exception as e:
                    print(f"⚠️  Warning: Could not add reports.minio_bucket: {e}")
            if 'minio_object_name' not in existing_columns:
                try:
                    conn.execute(text("ALTER TABLE reports ADD COLUMN minio_object_name VARCHAR;"))
                    print("✅ Added reports.minio_object_name")
                except Exception as e:
                    print(f"⚠️  Warning: Could not add reports.minio_object_name: {e}")

# Create all tables
Base.metadata.create_all(bind=engine)
print("✅ Tables created/verified successfully")

# Add any missing columns
add_missing_columns()
print("✅ Schema migration completed")
