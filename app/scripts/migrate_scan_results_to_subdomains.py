"""
Migration script to backfill subdomains from ScanResult table to Subdomain table.
This ensures existing scan results are visible in the UI.

Run this script to migrate existing scan results:
    python app/scripts/migrate_scan_results_to_subdomains.py
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

from sqlalchemy import Select, distinct
from app.database.session import SessionLocal
from app.database.models import ScanResult, Domain, Subdomain

def migrate_scan_results_to_subdomains():
    """Migrate subdomains from ScanResult to Subdomain table"""
    db = SessionLocal()
    
    try:
        # Get all unique domain names from ScanResult
        domain_stmt = Select(distinct(ScanResult.domain))
        unique_domains = db.execute(domain_stmt).scalars().all()
        
        print(f"Found {len(unique_domains)} unique domains in scan results")
        
        total_subdomains_created = 0
        total_subdomains_skipped = 0
        
        for domain_name in unique_domains:
            if not domain_name:
                continue
                
            print(f"\nProcessing domain: {domain_name}")
            
            # Get or create Domain record
            domain_stmt = Select(Domain).filter(Domain.domain_name == domain_name)
            domain = db.execute(domain_stmt).scalars().first()
            
            if not domain:
                # Create domain if it doesn't exist
                domain = Domain(
                    domain_name=domain_name,
                    discovery_source="auto_discovered",
                    created_by="migration_script",
                    updated_by="migration_script"
                )
                db.add(domain)
                db.commit()
                db.refresh(domain)
                print(f"  ✅ Created new domain: {domain_name}")
            else:
                print(f"  ℹ️  Found existing domain: {domain_name}")
            
            # Get all unique subdomains for this domain from ScanResult
            subdomain_stmt = Select(distinct(ScanResult.subdomain)).filter(
                ScanResult.domain == domain_name
            )
            subdomains = db.execute(subdomain_stmt).scalars().all()
            
            print(f"  Found {len(subdomains)} unique subdomains in scan results")
            
            created_count = 0
            skipped_count = 0
            
            for subdomain_name in subdomains:
                if not subdomain_name or not subdomain_name.strip():
                    continue
                
                subdomain_name = subdomain_name.strip()
                
                # Check if subdomain already exists
                existing_stmt = Select(Subdomain).filter(
                    Subdomain.domain_id == domain.id,
                    Subdomain.subdomain_name == subdomain_name
                )
                existing = db.execute(existing_stmt).scalars().first()
                
                if existing:
                    skipped_count += 1
                    continue
                
                # Create new subdomain
                subdomain = Subdomain(
                    domain_id=domain.id,
                    subdomain_name=subdomain_name,
                    created_by="migration_script",
                    updated_by="migration_script"
                )
                db.add(subdomain)
                created_count += 1
            
            db.commit()
            print(f"  ✅ Created {created_count} new subdomains, skipped {skipped_count} duplicates")
            
            total_subdomains_created += created_count
            total_subdomains_skipped += skipped_count
        
        print(f"\n{'='*60}")
        print(f"Migration completed!")
        print(f"Total subdomains created: {total_subdomains_created}")
        print(f"Total subdomains skipped (duplicates): {total_subdomains_skipped}")
        print(f"{'='*60}")
        
    except Exception as e:
        db.rollback()
        print(f"❌ Error during migration: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    print("Starting migration: ScanResult → Subdomain table")
    print("="*60)
    migrate_scan_results_to_subdomains()

