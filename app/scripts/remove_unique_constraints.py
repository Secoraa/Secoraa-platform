#!/usr/bin/env python3
"""
Migration script to remove unique constraints from domain-related tables.
This removes unique constraints from:
- subdomains (domain_id, subdomain_name)
- ipaddress (domain_id, ipaddress_name)
- urls (domain_id, url_name)
"""

import os
import sys
from pathlib import Path

# Add the app directory to the path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sqlalchemy import text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import database setup
from app.database.session import engine


def remove_unique_constraints():
    """Remove unique constraints from database tables."""

    if engine is None:
        raise RuntimeError("Database engine not initialized")

    # List of constraints to remove
    constraints = [
        {
            "table": "subdomains",
            "constraint_name": "uq_subdomains_domain_id_subdomain_name",
        },
        {
            "table": "ipaddress",
            "constraint_name": "uq_ipaddress_domain_id_ipaddress_name",
        },
        {"table": "urls", "constraint_name": "uq_urls_domain_id_url_name"},
    ]

    with engine.connect() as conn:
        for constraint in constraints:
            try:
                # Drop the constraint if it exists
                drop_sql = f"""
                DO $$ 
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM information_schema.table_constraints 
                        WHERE constraint_name = '{constraint["constraint_name"]}'
                        AND table_name = '{constraint["table"]}'
                    ) THEN
                        ALTER TABLE {constraint["table"]} 
                        DROP CONSTRAINT {constraint["constraint_name"]};
                        RAISE NOTICE 'Dropped constraint % from table %', '{constraint["constraint_name"]}', '{constraint["table"]}';
                    ELSE
                        RAISE NOTICE 'Constraint % does not exist on table %', '{constraint["constraint_name"]}', '{constraint["table"]}';
                    END IF;
                END $$;
                """

                conn.execute(text(drop_sql))
                print(
                    f"✅ Processed constraint {constraint['constraint_name']} on table {constraint['table']}"
                )

            except Exception as e:
                print(
                    f"❌ Error processing constraint {constraint['constraint_name']}: {e}"
                )

        conn.commit()

    print(
        "✅ Migration completed: Unique constraints removed from domain-related tables"
    )


if __name__ == "__main__":
    print("Starting migration to remove unique constraints from domain tables...")
    try:
        remove_unique_constraints()
        print("Migration completed successfully!")
    except Exception as e:
        print(f"Migration failed: {e}")
        sys.exit(1)
