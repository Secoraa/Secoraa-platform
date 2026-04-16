"""Helpers to prevent duplicate asset names within the same ownership / domain scope."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.models import Domain, Subdomain, IPAddress, URLAsset, AssetGroup, IPBlock


def normalize_domain_label(name: str) -> str:
    return (name or "").strip().lower().rstrip(".")


def normalize_url_asset(url: str) -> str:
    """Comparable key for URL / API base entries (scheme + host + path, case-insensitive host)."""
    raw = (url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").rstrip("/")
        if path == "/":
            path = ""
        path = path.lower()
        return f"{host}{path}"
    except Exception:
        return raw.lower().rstrip("/")


def normalize_ip_label(ip: str) -> str:
    return (ip or "").strip().lower()


def domain_name_exists_for_user(db: Session, created_by: str, domain_name: str) -> bool:
    key = normalize_domain_label(domain_name)
    if not key:
        return False
    row = db.execute(
        select(Domain.id).where(
            Domain.created_by == created_by,
            func.lower(Domain.domain_name) == key,
        )
    ).first()
    return row is not None


def subdomain_name_exists_for_domain(
    db: Session, domain_id, subdomain_name: str
) -> bool:
    key = (subdomain_name or "").strip().lower()
    if not key:
        return False
    row = db.execute(
        select(Subdomain.id).where(
            Subdomain.domain_id == domain_id,
            func.lower(Subdomain.subdomain_name) == key,
        )
    ).first()
    return row is not None


def ip_exists_for_domain(db: Session, domain_id, ipaddress_name: str) -> bool:
    key = normalize_ip_label(ipaddress_name)
    if not key:
        return False
    row = db.execute(
        select(IPAddress.id).where(
            IPAddress.domain_id == domain_id,
            func.lower(IPAddress.ipaddress_name) == key,
        )
    ).first()
    return row is not None


def url_exists_for_domain(db: Session, domain_id, url_name: str) -> bool:
    want = normalize_url_asset(url_name)
    if not want:
        return False
    rows = db.execute(select(URLAsset.url_name).where(URLAsset.domain_id == domain_id)).scalars().all()
    for existing in rows:
        if normalize_url_asset(existing) == want:
            return True
    return False


def asset_group_name_exists_for_domain(
    db: Session, domain_id, name: str, exclude_group_id: Optional[str] = None
) -> bool:
    key = (name or "").strip().lower()
    if not key:
        return False
    q = select(AssetGroup.id).where(
        AssetGroup.domain_id == domain_id,
        func.lower(AssetGroup.name) == key,
    )
    if exclude_group_id:
        q = q.where(AssetGroup.id != exclude_group_id)
    return db.execute(q).first() is not None


def ip_block_name_exists_for_domain(
    db: Session, domain_id, name: str, exclude_block_id: Optional[str] = None
) -> bool:
    key = (name or "").strip().lower()
    if not key:
        return False
    q = select(IPBlock.id).where(
        IPBlock.domain_id == domain_id,
        func.lower(IPBlock.name) == key,
    )
    if exclude_block_id:
        q = q.where(IPBlock.id != exclude_block_id)
    return db.execute(q).first() is not None
