from datetime import datetime
import uuid
from fastapi import APIRouter, Body, Depends, HTTPException
from typing import Any, Dict
from sqlalchemy.orm import Session
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from app.database.models import Domain, Subdomain, IPAddress, URLAsset
from app.database.session import get_db
from app.endpoints.request_body import (
    DomainRequestBody,
    DomainUpdateRequestBody,
    IPAddressRequestBody,
    URLRequestBody,
)
from sqlalchemy import Select
from sqlalchemy.orm import selectinload

from app.api.auth import get_token_claims, get_tenant_usernames


router = APIRouter(
    prefix="/assets",
    tags=["Assets"],
    dependencies=[Depends(get_token_claims)],
)


@router.post("/domain")
def create_domain(
    db: Session = Depends(get_db),
    request_body: DomainRequestBody = Body(...),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    body = request_body.model_dump()

    domain_name = body.get("domain_name")
    assert domain_name, "Domain name cannot be empty."

    asn = body.get("asn")
    tags = body.get("tags",[])

    created_by = str(claims.get("sub") or claims.get("username") or "manual").strip()
    updated_by = created_by
    created_at = datetime.utcnow()
    updated_at = datetime.utcnow()

    try:
        domain = Domain(
            domain_name=domain_name,
            asn=asn,
            tags=tags,
            created_at=created_at,
            created_by=created_by,
            updated_at=updated_at,
            updated_by=updated_by,
        )
        db.add(domain)
        db.commit()
        db.flush(domain)
        domain_id = str(domain.id)
    except Exception as e:
        # Backward-compatible fallback for older DB schemas missing newly added columns (asn, discovery_source, etc.)
        try:
            db.rollback()
        except Exception:
            pass

        err = str(e).lower()
        if "undefinedcolumn" in err or "does not exist" in err:
            domain_uuid = str(uuid.uuid4())
            try:
                db.execute(
                    text(
                        """
                        INSERT INTO domains (id, domain_name, tags, created_at, updated_at, created_by, updated_by)
                        VALUES (:id, :domain_name, :tags, :created_at, :updated_at, :created_by, :updated_by)
                        """
                    ),
                    {
                        "id": domain_uuid,
                        "domain_name": domain_name,
                        "tags": tags,
                        "created_at": created_at,
                        "updated_at": updated_at,
                        "created_by": created_by,
                        "updated_by": updated_by,
                    },
                )
                db.commit()
                domain_id = domain_uuid
                # Can't persist asn in older schema; return it anyway for UI consistency
            except Exception as sql_e:
                try:
                    db.rollback()
                except Exception:
                    pass
                raise HTTPException(status_code=500, detail=f"Database error: {str(sql_e)}")
        else:
            raise HTTPException(status_code=500, detail=f"Error creating domain: {str(e)}")

    data = {"domain_name":domain_name,
            "id": domain_id,
            "asn": asn,
            "tags":tags, 
            "created_at":created_at, 
            "created_by":created_by, 
            "updated_at":updated_at, 
            "updated_by":updated_by
        }

    return data

        
       

@router.get("/domain")
def get_domain(
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    try:
        tenant_users = get_tenant_usernames(db, claims)
        if not tenant_users:
            return []
        stmt = (
            Select(Domain)
            .options(selectinload(Domain.subdomains))
            .filter(Domain.created_by.in_(tenant_users))
        )

        domains = db.execute(stmt).scalars().all()

        result = []
        for domain in domains:
            # Safely get discovery_source, default to 'manual' if column doesn't exist
            # (All existing domains were added manually)
            try:
                discovery_source = getattr(domain, 'discovery_source', 'manual')
            except:
                discovery_source = 'manual'
            
            result.append({
                "id": str(domain.id),
                "domain_name": domain.domain_name,
                "asn": getattr(domain, "asn", None),
                "tags": domain.tags,
                "discovery_source": discovery_source,
                "is_reachable": getattr(domain, "is_reachable", True),
                "is_active": getattr(domain, "is_active", True),
                "is_archived": getattr(domain, "is_archived", False),
                "created_at": domain.created_at,
                "subdomains": [
                    sub.subdomain_name
                    for sub in domain.subdomains
                ],
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
    except Exception as e:
        
        # Rollback the failed transaction
        try:
            db.rollback()
        except:
            pass  # Ignore rollback errors if connection is already lost
        
        # If column doesn't exist, use raw SQL to query without it
        error_str = str(e).lower()
        if "discovery_source" in error_str or "undefinedcolumn" in error_str:
            try:
                # Query without discovery_source column
                if not tenant_users:
                    return []
                result = db.execute(text("""
                    SELECT id, domain_name, tags, created_at, updated_at, created_by, updated_by
                    FROM domains
                    WHERE created_by = ANY(:tenant_users)
                """), {"tenant_users": tenant_users})
                
                # Get subdomains separately
                domains_data = []
                for row in result:
                    domain_id = str(row[0])
                    
                    # Get subdomains for this domain
                    subdomains_result = db.execute(text("""
                        SELECT id, subdomain_name, created_at
                        FROM subdomains
                        WHERE domain_id = :domain_id
                    """), {"domain_id": domain_id})
                    
                    subdomains = [
                        {
                            "id": str(sub[0]),
                            "subdomain_name": sub[1],
                            "created_at": sub[2],
                        }
                        for sub in subdomains_result
                    ]
                    
                    domains_data.append({
                        "id": domain_id,
                        "domain_name": row[1],
                        "asn": None,
                        "tags": row[2],
                        "discovery_source": "manual",  # Default for existing domains (they were added manually)
                        # Columns may not exist in older schemas; default sensibly
                        "is_reachable": True,
                        "is_active": True,
                        "is_archived": False,
                        "created_at": row[3],
                        "subdomains": subdomains,
                    })
                
                return domains_data
            except Exception as sql_error:
                try:
                    db.rollback()
                except:
                    pass
                raise HTTPException(status_code=500, detail=f"Database error: {str(sql_error)}")
        raise HTTPException(status_code=500, detail=f"Error fetching domains: {str(e)}")


    # domain = db.query(Domain).all()
    # return domain
    
@router.get("/domain/{domain_id}")
def get_domain_by_id(
    domain_id,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    try:
        tenant_users = get_tenant_usernames(db, claims)
        stmt = (
            Select(Domain)
            .filter(Domain.id == domain_id)
            .filter(Domain.created_by.in_(tenant_users))
            .options(selectinload(Domain.subdomains))
        )
        domain = db.execute(stmt).scalars().first()
        if not domain:
            raise HTTPException(status_code=404, detail="Domain with specific Id does not Exist.")

        return {
            "message": "Success",
            "data": {
                "id": str(domain.id),
                "domain_name": domain.domain_name,
                "asn": getattr(domain, "asn", None),
                "tags": domain.tags,
                "discovery_source": getattr(domain, "discovery_source", "auto_discovered"),
                "is_reachable": getattr(domain, "is_reachable", True),
                "is_active": getattr(domain, "is_active", True),
                "is_archived": getattr(domain, "is_archived", False),
                "created_at": domain.created_at,
                "subdomains": [
                    {
                        "id": str(s.id),
                        "subdomain_name": s.subdomain_name,
                    }
                    for s in (domain.subdomains or [])
                ],
            },
        }
    except OperationalError as e:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(
            status_code=503,
            detail=f"Database connection failed. Please ensure PostgreSQL is running. Error: {str(e)}",
        )
    except Exception as e:
        # Backward-compatible fallback: if newly added columns are missing, query a minimal set via SQL.
        try:
            db.rollback()
        except Exception:
            pass
        err = str(e).lower()
        if "undefinedcolumn" in err or "does not exist" in err:
            row = db.execute(
                text(
                    """
                    SELECT id, domain_name, tags, created_at
                    FROM domains
                    WHERE id = :domain_id
                      AND created_by = ANY(:tenant_users)
                    """
                ),
                {"domain_id": str(domain_id), "tenant_users": get_tenant_usernames(db, claims)},
            ).first()
            if not row:
                raise HTTPException(status_code=404, detail="Domain with specific Id does not Exist.")

            subs = db.execute(
                text(
                    """
                    SELECT id, subdomain_name
                    FROM subdomains
                    WHERE domain_id = :domain_id
                    """
                ),
                {"domain_id": str(domain_id)},
            ).fetchall()

            return {
                "message": "Success",
                "data": {
                    "id": str(row[0]),
                    "domain_name": row[1],
                    "asn": None,
                    "tags": row[2],
                    "discovery_source": "manual",
                    "is_reachable": True,
                    "is_active": True,
                    "is_archived": False,
                    "created_at": row[3],
                    "subdomains": [{"id": str(s[0]), "subdomain_name": s[1]} for s in subs],
                },
            }
        raise HTTPException(status_code=500, detail=f"Error fetching domain: {str(e)}")


@router.get("/ip-addresses")
def list_ip_addresses(
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """
    List IP addresses with their associated domain_name.
    """
    try:
        tenant_users = get_tenant_usernames(db, claims)
        if not tenant_users:
            return []
        stmt = (
            Select(IPAddress)
            .options(selectinload(IPAddress.domain))
            .join(Domain, IPAddress.domain_id == Domain.id)
            .filter(Domain.created_by.in_(tenant_users))
        )
        ips = db.execute(stmt).scalars().all()

        return [
            {
                "id": str(ip.id),
                "ipaddress_name": ip.ipaddress_name,
                "tags": ip.tags,
                "domain_id": str(ip.domain_id),
                "domain_name": getattr(ip.domain, "domain_name", None),
                "created_at": ip.created_at,
                "created_by": getattr(ip, "created_by", None),
                "updated_at": ip.updated_at,
                "updated_by": getattr(ip, "updated_by", None),
            }
            for ip in ips
        ]
    except OperationalError as e:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(status_code=503, detail=f"Database connection failed. Error: {str(e)}")


@router.post("/ip-addresses")
def create_ip_address(
    db: Session = Depends(get_db),
    request_body: IPAddressRequestBody = Body(...),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """
    Create an IP address entry connected to a domain.
    """
    try:
        body = request_body.model_dump()
        domain_id = body.get("domain_id")
        ipaddress_name = (body.get("ipaddress_name") or "").strip()
        tags = body.get("tags") or []

        if not domain_id:
            raise HTTPException(status_code=400, detail="domain_id is required")
        if not ipaddress_name:
            raise HTTPException(status_code=400, detail="ipaddress_name is required")

        tenant_users = get_tenant_usernames(db, claims)
        valid_domain = (
            db.query(Domain)
            .filter(Domain.id == domain_id, Domain.created_by.in_(tenant_users))
            .first()
        )
        if not valid_domain:
            raise HTTPException(status_code=400, detail="Invalid domain_id")

        created_by = updated_by = str(claims.get("sub") or claims.get("username") or "manual").strip()
        created_at = updated_at = datetime.utcnow()

        ip = IPAddress(
            domain_id=domain_id,
            ipaddress_name=ipaddress_name,
            tags=tags,
            created_at=created_at,
            updated_at=updated_at,
            created_by=created_by,
            updated_by=updated_by,
        )

        db.add(ip)
        db.commit()
        db.refresh(ip)

        return {
            "id": str(ip.id),
            "ipaddress_name": ip.ipaddress_name,
            "tags": ip.tags,
            "domain_id": str(ip.domain_id),
            "domain_name": getattr(valid_domain, "domain_name", None),
            "created_at": ip.created_at,
            "created_by": ip.created_by,
            "updated_at": ip.updated_at,
            "updated_by": ip.updated_by,
        }
    except OperationalError as e:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(status_code=503, detail=f"Database connection failed. Error: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/urls")
def list_urls(
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """
    List URLs with their associated domain_name.
    If the `urls` table hasn't been created yet, returns an empty list.
    """
    try:
        tenant_users = get_tenant_usernames(db, claims)
        if not tenant_users:
            return []
        stmt = (
            Select(URLAsset)
            .options(selectinload(URLAsset.domain))
            .join(Domain, URLAsset.domain_id == Domain.id)
            .filter(Domain.created_by.in_(tenant_users))
        )
        urls = db.execute(stmt).scalars().all()

        return [
            {
                "id": str(u.id),
                "url_name": u.url_name,
                "tags": u.tags,
                "domain_id": str(u.domain_id),
                "domain_name": getattr(u.domain, "domain_name", None),
                "created_at": u.created_at,
                "created_by": getattr(u, "created_by", None),
                "updated_at": u.updated_at,
                "updated_by": getattr(u, "updated_by", None),
            }
            for u in urls
        ]
    except ProgrammingError:
        # Most likely: table doesn't exist yet.
        return []
    except OperationalError as e:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(status_code=503, detail=f"Database connection failed. Error: {str(e)}")


@router.post("/urls")
def create_url(
    db: Session = Depends(get_db),
    request_body: URLRequestBody = Body(...),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """
    Create a URL entry connected to a domain.
    If the `urls` table hasn't been created yet, returns 400 with guidance.
    """
    try:
        body = request_body.model_dump()
        domain_id = body.get("domain_id")
        url_name = (body.get("url_name") or "").strip()
        tags = body.get("tags") or []

        if not domain_id:
            raise HTTPException(status_code=400, detail="domain_id is required")
        if not url_name:
            raise HTTPException(status_code=400, detail="url_name is required")

        tenant_users = get_tenant_usernames(db, claims)
        valid_domain = (
            db.query(Domain)
            .filter(Domain.id == domain_id, Domain.created_by.in_(tenant_users))
            .first()
        )
        if not valid_domain:
            raise HTTPException(status_code=400, detail="Invalid domain_id")

        created_by = updated_by = str(claims.get("sub") or claims.get("username") or "manual").strip()
        created_at = updated_at = datetime.utcnow()

        u = URLAsset(
            domain_id=domain_id,
            url_name=url_name,
            tags=tags,
            created_at=created_at,
            updated_at=updated_at,
            created_by=created_by,
            updated_by=updated_by,
        )
        db.add(u)
        db.commit()
        db.refresh(u)

        return {
            "id": str(u.id),
            "url_name": u.url_name,
            "tags": u.tags,
            "domain_id": str(u.domain_id),
            "domain_name": getattr(valid_domain, "domain_name", None),
            "created_at": u.created_at,
            "created_by": u.created_by,
            "updated_at": u.updated_at,
            "updated_by": u.updated_by,
        }
    except ProgrammingError:
        raise HTTPException(
            status_code=400,
            detail="URLs table does not exist yet. Run your DB schema migration / create_tables script first.",
        )
    except OperationalError as e:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(status_code=503, detail=f"Database connection failed. Error: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        try:
            db.rollback()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/domain/{domain_id}")
def update_domain_by_id(
    domain_id,
    request_body : DomainUpdateRequestBody = Body(...),
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    body = request_body.model_dump()

    tags = body.get("tags", None)
    asn = body.get("asn", None)

    try:
        tenant_users = get_tenant_usernames(db, claims)
        stmt = Select(Domain).filter(Domain.id == domain_id, Domain.created_by.in_(tenant_users))
        domain = db.execute(stmt).scalars().first()
        if not domain:
            raise HTTPException(status_code=400,detail="Domain with specific Id does not Exist.")

        if tags is not None:
            domain.tags = tags
        if asn is not None:
            domain.asn = asn
        db.commit()
        db.refresh(domain)
        return {
            "message": "Domain updated successfully",
            "data": {
                "id": str(domain.id),
                "domain_name": domain.domain_name,
                "asn": getattr(domain, "asn", None),
                "tags": domain.tags,
                "updated_at": domain.updated_at,
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        # Backward-compatible fallback for older DB schemas.
        try:
            db.rollback()
        except Exception:
            pass
        err = str(e).lower()
        if "undefinedcolumn" in err or "does not exist" in err:
            # Try tags update
            if tags is not None:
                db.execute(
                    text("UPDATE domains SET tags = :tags WHERE id = :domain_id"),
                    {"tags": tags, "domain_id": str(domain_id)},
                )
            # Try ASN update (may fail if column doesn't exist; ignore)
            if asn is not None:
                try:
                    db.execute(
                        text("UPDATE domains SET asn = :asn WHERE id = :domain_id"),
                        {"asn": asn, "domain_id": str(domain_id)},
                    )
                except Exception:
                    pass
            db.commit()
            return {"message": "Domain updated successfully", "data": {"id": str(domain_id)}}
        raise HTTPException(status_code=500, detail=f"Error updating domain: {str(e)}")

@router.delete("/domain/{domain_id}")
def delete_domain(
    domain_id,
    db: Session = Depends(get_db)
):
    stmt = Select(Domain).filter(Domain.id == domain_id)
    domain = db.execute(stmt).scalars().first()
    assert domain, "Domain with specific Id does not Exist."

    db.delete(domain)
    db.commit()

#----------------------------------------------------------------
# Subdomain
#----------------------------------------------------------------

@router.get("/subdomain")
def get_subdomain(
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    try:
        tenant_users = get_tenant_usernames(db, claims)
        if not tenant_users:
            return []
        stmt = (
            Select(Subdomain)
            .join(Domain, Subdomain.domain_id == Domain.id)
            .filter(Domain.created_by.in_(tenant_users))
        )
        subdomains = db.execute(stmt).scalars().all()
        result = []
        for subdomain in subdomains:
            result.append(
                {   "id":str(subdomain.id),
                    "subdomain_name":subdomain.subdomain_name,
                }
            )
        return result

    except Exception as ex:
        db.rollback()
        print(ex)

