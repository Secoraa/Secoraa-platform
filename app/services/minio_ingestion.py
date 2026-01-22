import json
import logging
from sqlalchemy import Select
from app.storage.minio_client import get_minio_client

logger = logging.getLogger(__name__)

# Import models lazily to avoid circular import issues
def _get_models():
    from app.database.models import Domain, Subdomain
    return Domain, Subdomain


def ingest_from_minio(bucket: str, object_name: str, db):
    """
    Read JSON file from MinIO and insert Domain + Subdomains into PostgreSQL.
    
    Expected JSON structure:
    {
        "result": {
            "domain": "example.com",
            "subdomains": ["sub1.example.com", "sub2.example.com"]
        }
    }
    """
    # Get MinIO client (lazy initialization)
    client = get_minio_client()
    
    # Read file from MinIO
    response = client.get_object(bucket, object_name)

    try:
        data = json.load(response)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {object_name}: {e}")
        raise
    finally:
        response.close()
        response.release_conn()

    # Extract domain and subdomains from the result
    result = data.get("result", {})
    domain_name = result.get("domain")
    subdomains = result.get("subdomains", [])

    if not domain_name:
        logger.warning(f"No domain found in {object_name}")
        return

    logger.info(f"Processing domain: {domain_name} with {len(subdomains)} subdomains")

    # Import models lazily to avoid circular import issues
    Domain, Subdomain = _get_models()

    # 1️⃣ Get or create domain (handle unique constraint)
    stmt = Select(Domain).filter(Domain.domain_name == domain_name)
    domain = db.execute(stmt).scalars().first()
    
    if not domain:
        # Create new domain (auto-discovered from scan)
        domain = Domain(
            domain_name=domain_name,
            discovery_source="auto_discovered",  # Mark as auto-discovered
            created_by="pratik",
            updated_by="pratik"
        )
        db.add(domain)
        db.commit()
        db.refresh(domain)
        logger.info(f"Created new domain: {domain_name}")
    else:
        logger.info(f"Found existing domain: {domain_name}")

    # 2️⃣ Insert subdomains (skip duplicates due to unique constraint)
    created_count = 0
    skipped_count = 0
    
    for subdomain_name in subdomains:
        if not subdomain_name or not subdomain_name.strip():
            continue
            
        # Check if subdomain already exists
        stmt = Select(Subdomain).filter(
            Subdomain.domain_id == domain.id,
            Subdomain.subdomain_name == subdomain_name
        )
        existing = db.execute(stmt).scalars().first()
        
        if existing:
            skipped_count += 1
            continue
        
        # Create new subdomain
        subdomain = Subdomain(
            domain_id=domain.id,
            subdomain_name=subdomain_name,
            created_by="pratik",
            updated_by="pratik"
        )
        db.add(subdomain)
        created_count += 1

    db.commit()
    
    logger.info(
        f"Domain {domain_name}: Created {created_count} subdomains, "
        f"skipped {skipped_count} duplicates"
    )
    
    return {
        "domain": domain_name,
        "domain_id": str(domain.id),
        "subdomains_created": created_count,
        "subdomains_skipped": skipped_count,
        "total_subdomains": len(subdomains)
    }
