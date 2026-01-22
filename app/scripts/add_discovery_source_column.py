"""
Migration script to add discovery_source column to domains table
"""
import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Load environment variables
try:
    from dotenv import load_dotenv
    env_path = project_root / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv not installed, skip

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Database connection parameters
POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_DB = os.getenv("POSTGRES_DB")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "15432")

def add_discovery_source_column():
    """Add discovery_source column to domains table if it doesn't exist"""
    try:
        # Connect to PostgreSQL
        conn = psycopg2.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            database=POSTGRES_DB
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        # Check if column exists
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='domains' AND column_name='discovery_source';
        """)
        
        if cursor.fetchone():
            print("✅ Column 'discovery_source' already exists in 'domains' table")
        else:
            # Add the column
            cursor.execute("""
                ALTER TABLE domains 
                ADD COLUMN discovery_source VARCHAR DEFAULT 'auto_discovered';
            """)
            print("✅ Successfully added 'discovery_source' column to 'domains' table")
            
            # Update existing rows to have default value
            cursor.execute("""
                UPDATE domains 
                SET discovery_source = 'auto_discovered' 
                WHERE discovery_source IS NULL;
            """)
            print("✅ Updated existing rows with default 'auto_discovered' value")

        cursor.close()
        conn.close()
        print("✅ Migration completed successfully!")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("Running migration: Add discovery_source column to domains table...")
    add_discovery_source_column()

