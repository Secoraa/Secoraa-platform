from __future__ import annotations

import uuid as uuid_lib
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.auth import get_tenant_usernames, get_token_claims
from app.database.models import PtaasRequest
from app.database.session import get_db

router = APIRouter(prefix="/ptaas", tags=["PTAAS"])


class CreatePtaasRequestBody(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    target_type: str = Field(..., description="DOMAIN|SUBDOMAIN|IP|URL|API")
    target_value: str = Field(..., min_length=1, max_length=500)
    scope_notes: Optional[str] = Field(default=None, max_length=2000)
    timeline: Optional[str] = Field(default=None, max_length=200)


class PtaasRequestRow(BaseModel):
    id: str
    title: str
    target_type: str
    target_value: str
    scope_notes: Optional[str] = None
    timeline: Optional[str] = None
    status: str
    created_by: str
    updated_by: str
    created_at: str
    updated_at: str


def _normalize_target_type(value: str) -> str:
    normalized = str(value or "").strip().upper()
    allowed = {"DOMAIN", "SUBDOMAIN", "IP", "URL", "API"}
    if normalized not in allowed:
        raise HTTPException(status_code=400, detail="Invalid target_type. Use DOMAIN, SUBDOMAIN, IP, URL, or API.")
    return normalized


def _to_row(item: PtaasRequest) -> PtaasRequestRow:
    return PtaasRequestRow(
        id=str(item.id),
        title=item.title,
        target_type=item.target_type,
        target_value=item.target_value,
        scope_notes=item.scope_notes,
        timeline=item.timeline,
        status=item.status,
        created_by=item.created_by,
        updated_by=item.updated_by,
        created_at=str(item.created_at),
        updated_at=str(item.updated_at),
    )


@router.post("/requests", response_model=PtaasRequestRow, status_code=201)
def create_ptaas_request(
    body: CreatePtaasRequestBody,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    username = str(claims.get("sub") or claims.get("username") or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="Invalid user context")

    now = datetime.utcnow()
    rec = PtaasRequest(
        title=body.title.strip(),
        target_type=_normalize_target_type(body.target_type),
        target_value=body.target_value.strip(),
        scope_notes=(body.scope_notes.strip() if body.scope_notes else None),
        timeline=(body.timeline.strip() if body.timeline else None),
        status="REQUESTED",
        created_by=username,
        updated_by=username,
        created_at=now,
        updated_at=now,
    )
    try:
        db.add(rec)
        db.commit()
        db.refresh(rec)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(exc))

    return _to_row(rec)


@router.get("/requests")
def list_ptaas_requests(
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    tenant_users = get_tenant_usernames(db, claims)
    rows = (
        db.query(PtaasRequest)
        .filter(PtaasRequest.created_by.in_(tenant_users))
        .order_by(PtaasRequest.created_at.desc())
        .all()
    )
    return {"data": [_to_row(r) for r in rows]}


@router.get("/requests/{request_id}", response_model=PtaasRequestRow)
def get_ptaas_request(
    request_id: str,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    tenant_users = get_tenant_usernames(db, claims)
    try:
        request_uuid = uuid_lib.UUID(request_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request id")

    row = (
        db.query(PtaasRequest)
        .filter(PtaasRequest.id == request_uuid, PtaasRequest.created_by.in_(tenant_users))
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="PTAAS request not found")
    return _to_row(row)
