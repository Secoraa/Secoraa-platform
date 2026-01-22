"""
Migration script to add discovery_source column to domains table
Run this script to add the missing column to your database.
"""
import sys
import os
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
    pass

from sqlalchemy import text
from app.database.session import engine

def add_discovery_source_column():
    """Add discovery_source column to domains table"""
    try:
        with engine.begin() as conn:
            # Check if column exists
            result = conn.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='domains' AND column_name='discovery_source';
            """))
            
            if result.fetchone():
                print("✅ Column 'discovery_source' already exists")
                return
            
            # Add the column
            conn.execute(text("""
                ALTER TABLE domains 
                ADD COLUMN discovery_source VARCHAR DEFAULT 'manual';
            """))
            
            # Update existing rows to 'manual' (since they were all added manually)
            conn.execute(text("""
                UPDATE domains 
                SET discovery_source = 'manual' 
                WHERE discovery_source IS NULL;
            """))
            
            print("✅ Successfully added 'discovery_source' column to 'domains' table")
            print("✅ Updated existing rows to 'manual' (all existing domains were added manually)")
            print("✅ Migration completed successfully!")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\n💡 Alternative: Run the SQL script directly:")
        print("   psql -h localhost -p 15432 -U <username> -d <database> -f migration_add_discovery_source.sql")
        sys.exit(1)

if __name__ == "__main__":
    print("Running migration: Add discovery_source column to domains table...")
    add_discovery_source_column()

