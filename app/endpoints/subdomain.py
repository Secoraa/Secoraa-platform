from datetime import datetime
import uuid
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import Select, select
from sqlalchemy.exc import OperationalError

from app.database.models import Domain, Subdomain
from app.database.session import get_db
from sqlalchemy.orm import selectinload

from app.endpoints.request_body import SubdomainRequestBody

from app.api.auth import get_token_claims


router = APIRouter(
    prefix="/subdomain",
    tags=["Subdomain"],
    dependencies=[Depends(get_token_claims)],
)

@router.post("/subdomain")
def create_subdomain(
    db:Session = Depends(get_db),
    request_body: SubdomainRequestBody = Body(...),
):
    try:
        body = request_body.model_dump()

        subdomain_name = body.get("subdomain_name")
        assert subdomain_name, "Subdomain name cannot be empty."

        tags = body.get("tags")

        domain_id = body.get("domain_id")
        assert domain_id, "Domain name cannot be empty."

        valid_domain = db.query(Domain).filter(Domain.id == domain_id).first()
        assert valid_domain, "Invalid Domain Id."
    

        created_at = datetime.utcnow()
        updated_at = datetime.utcnow()
        updated_by = "pratik"
        created_by = "pratik"

        subdomain = Subdomain(
            subdomain_name=subdomain_name,
            tags=tags,
            domain_id=domain_id,
            created_at=created_at,
            created_by=created_by,
            updated_at=updated_at,
            updated_by=updated_by,
        )

        db.add(subdomain)
        db.commit()
        db.flush(subdomain)

        data = {
            "id":subdomain.id,
            "subdomain_name":subdomain_name,
            "tags":tags,
            "domain_id":domain_id,
            "created_at":created_at,
            "created_by":created_by,
            "updated_at":updated_at,
            "updated_by":updated_by,
        }

        return data
    except OperationalError as e:
        # Handle database connection errors specifically
        try:
            db.rollback()
        except:
            pass
        error_msg = str(e)
        raise HTTPException(
            status_code=503,
            detail=(
                f"Database connection failed. Please ensure PostgreSQL is running on "
                f"localhost:15432. Error: {error_msg}"
            )
        )
    except Exception as ex:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(ex))


@router.get("/subdomain")
def get_subdomain(db: Session = Depends(get_db)):
    """
    Get all subdomains with their associated domain information.
    Returns: name, tags, domain_name, created_by, updated_by, created_at, updated_at
    """
    try:
        # Load subdomains with their domain relationship
        stmt = (
            Select(Subdomain)
            .options(selectinload(Subdomain.domain))
        )
        subdomains = db.execute(stmt).scalars().all()

        result = []
        for subdomain in subdomains:
            # Get domain name from the relationship
            domain_name = subdomain.domain.domain_name if subdomain.domain else None
            
            result.append({
                "id": str(subdomain.id),
                "name": subdomain.subdomain_name,
                "subdomain_name": subdomain.subdomain_name,  # Keep for backward compatibility
                "tags": subdomain.tags or [],
                "domain_name": domain_name,
                "domain_id": str(subdomain.domain_id) if subdomain.domain_id else None,
                "created_at": subdomain.created_at.isoformat() if subdomain.created_at else None,
                "created_by": subdomain.created_by,
                "updated_at": subdomain.updated_at.isoformat() if subdomain.updated_at else None,
                "updated_by": subdomain.updated_by,
            })

        return result

    except OperationalError as e:
        # Handle database connection errors specifically
        try:
            db.rollback()
        except:
            pass
        error_msg = str(e)
        raise HTTPException(
            status_code=503,
            detail=(
                f"Database connection failed. Please ensure PostgreSQL is running on "
                f"localhost:15432. Error: {error_msg}"
            )
        )
    except Exception as ex:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(ex))

@router.get("/subdomain/{subdomain_id}")
def get_subdomain_with_id(
    subdomain_id,
    db: Session = Depends(get_db),
):
    try:
        stmt = select(Subdomain).filter(Subdomain.id == subdomain_id)
        result = db.execute(stmt).scalars().one_or_none()
        if not result:
            raise HTTPException(status_code=404, detail="Subdomain with id does not exist.")
        return result
    except OperationalError as e:
        # Handle database connection errors specifically
        try:
            db.rollback()
        except:
            pass
        error_msg = str(e)
        raise HTTPException(
            status_code=503,
            detail=(
                f"Database connection failed. Please ensure PostgreSQL is running on "
                f"localhost:15432. Error: {error_msg}"
            )
        )
    except HTTPException:
        raise
    except Exception as ex:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(ex))

#TODO: Update subdomain .


#----------------------------------------
