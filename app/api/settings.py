"""
Settings API — API key generation, listing, and revocation.

API keys are used for CI/CD integrations (GitHub Actions) where a user
cannot do an interactive login. The full key is shown exactly once at
creation time; we store only the argon2 hash.
"""
from __future__ import annotations

import secrets
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from argon2 import PasswordHasher

from app.database.models import APIKey, User
from app.database.session import get_db
from app.api.auth import get_token_claims

router = APIRouter(prefix="/settings", tags=["Settings"])
ph = PasswordHasher()
logger = logging.getLogger(__name__)

KEY_LENGTH = 48  # 48 random bytes → 64-char hex string


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class CreateAPIKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Label for the key")
    scopes: List[str] = Field(default=["ci"], description="Allowed scopes")
    expires_in_days: Optional[int] = Field(default=None, description="Days until expiry (null = never)")


class APIKeyCreatedResponse(BaseModel):
    id: str
    name: str
    key: str           # Full key — shown only once
    key_prefix: str
    scopes: List[str]
    expires_at: Optional[str]
    created_at: str


class APIKeyListItem(BaseModel):
    id: str
    name: str
    key_prefix: str
    scopes: List[str]
    is_active: bool
    last_used_at: Optional[str]
    expires_at: Optional[str]
    created_at: str


class UserProfileResponse(BaseModel):
    id: str
    username: str
    tenant: str
    is_active: bool
    created_at: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/profile", response_model=UserProfileResponse)
def get_profile(
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """Return the current user's profile."""
    username = claims.get("sub") or claims.get("username")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserProfileResponse(
        id=str(user.id),
        username=user.username,
        tenant=user.tenant or "default",
        is_active=user.is_active,
        created_at=str(user.created_at),
    )


@router.post("/api-keys", response_model=APIKeyCreatedResponse, status_code=201)
def create_api_key(
    body: CreateAPIKeyRequest,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """Generate a new API key. The full key is returned only in this response."""
    username = claims.get("sub") or claims.get("username")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate a cryptographically random key
    raw_key = secrets.token_hex(KEY_LENGTH)         # 96 hex chars
    full_key = f"sec_{raw_key}"                     # prefix for easy identification
    prefix = raw_key[:8]                             # first 8 hex chars

    expires_at = None
    if body.expires_in_days and body.expires_in_days > 0:
        from datetime import timedelta
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    api_key = APIKey(
        user_id=user.id,
        name=body.name.strip(),
        key_prefix=prefix,
        key_hash=ph.hash(full_key),
        scopes=body.scopes or ["ci"],
        is_active=True,
        expires_at=expires_at,
    )

    try:
        db.add(api_key)
        db.commit()
        db.refresh(api_key)
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to create API key")
        raise HTTPException(status_code=500, detail=str(exc))

    return APIKeyCreatedResponse(
        id=str(api_key.id),
        name=api_key.name,
        key=full_key,
        key_prefix=prefix,
        scopes=api_key.scopes or ["ci"],
        expires_at=str(api_key.expires_at) if api_key.expires_at else None,
        created_at=str(api_key.created_at),
    )


@router.get("/api-keys", response_model=List[APIKeyListItem])
def list_api_keys(
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """List all API keys for the current user (never exposes the full key)."""
    username = claims.get("sub") or claims.get("username")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    keys = (
        db.query(APIKey)
        .filter(APIKey.user_id == user.id)
        .order_by(APIKey.created_at.desc())
        .all()
    )
    return [
        APIKeyListItem(
            id=str(k.id),
            name=k.name,
            key_prefix=k.key_prefix,
            scopes=k.scopes or [],
            is_active=k.is_active,
            last_used_at=str(k.last_used_at) if k.last_used_at else None,
            expires_at=str(k.expires_at) if k.expires_at else None,
            created_at=str(k.created_at),
        )
        for k in keys
    ]


@router.delete("/api-keys/{key_id}")
def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """Revoke (deactivate) an API key."""
    username = claims.get("sub") or claims.get("username")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    import uuid as _uuid
    try:
        key_uuid = _uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key ID")

    api_key = (
        db.query(APIKey)
        .filter(APIKey.id == key_uuid, APIKey.user_id == user.id)
        .first()
    )
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_active = False
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(exc))

    return {"message": "API key revoked", "id": key_id}
