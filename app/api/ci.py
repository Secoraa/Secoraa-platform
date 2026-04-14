"""
CI/CD Scan Sync API — receives scan results from the GitHub Action / CLI
and stores them in the platform for centralized history and trending.

Auth: API key (``Authorization: Bearer sec_...``)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.models import Scan, ApiScanReport, Vulnerability, Domain
from app.database.session import get_db
from app.api.auth import verify_api_key, get_token_claims

router = APIRouter(prefix="/api/v1/ci", tags=["CI/CD"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class CIFinding(BaseModel):
    title: str
    severity: str = "INFORMATIONAL"
    owasp_category: Optional[str] = None
    endpoint: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    confidence: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None


class CISyncRequest(BaseModel):
    scan_name: str = Field(..., min_length=1)
    scan_type: str = Field(default="API_SECURITY")
    base_url: str = Field(..., min_length=1)
    scan_mode: Optional[str] = "active"

    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None

    total_endpoints: Optional[int] = 0
    total_findings: Optional[int] = 0

    severity_counts: Optional[Dict[str, int]] = None
    findings: List[CIFinding] = []

    # Gate result from CLI
    gate_passed: Optional[bool] = None
    gate_threshold: Optional[str] = None

    # Optional: link to GitHub PR/commit
    git_repo: Optional[str] = None
    git_ref: Optional[str] = None
    git_sha: Optional[str] = None
    pr_number: Optional[int] = None


class CISyncResponse(BaseModel):
    scan_id: str
    findings_synced: int
    message: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/sync", response_model=CISyncResponse, status_code=201)
def sync_ci_scan(
    body: CISyncRequest,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(verify_api_key),
):
    """
    Receive a CI/CD scan report and persist it.

    Creates:
    - A ``Scan`` row (status=Completed, type=ci_api / ci_subdomain)
    - An ``ApiScanReport`` row with the full JSON
    - ``Vulnerability`` rows for each finding (linked to domain if found)
    """
    username = claims.get("sub", "ci")
    tenant = claims.get("tenant", "default")

    # --- 1. Create scan record -------------------------------------------
    scan_type = f"ci_{body.scan_type.lower().replace(' ', '_')}"
    scan = Scan(
        scan_name=body.scan_name,
        scan_type=scan_type,
        status="Completed",
        created_by=username,
        progress=100,
        current_phase="COMPLETED",
        findings_count=len(body.findings),
        endpoints_total=body.total_endpoints or 0,
        endpoints_scanned=body.total_endpoints or 0,
    )
    db.add(scan)
    db.flush()  # get scan.id

    # --- 2. Store full report JSON ----------------------------------------
    report_json = body.model_dump(mode="json")
    report_json["git"] = {
        "repo": body.git_repo,
        "ref": body.git_ref,
        "sha": body.git_sha,
        "pr": body.pr_number,
    }
    report_json["ci_metadata"] = {
        "synced_by": username,
        "tenant": tenant,
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "auth_method": "api_key",
        "key_id": claims.get("key_id"),
    }

    api_report = ApiScanReport(
        scan_id=scan.id,
        asset_url=body.base_url,
        report_json=json.dumps(report_json),
    )
    db.add(api_report)

    # --- 3. Resolve domain (best-effort) ----------------------------------
    domain = _resolve_domain(db, body.base_url)

    # --- 4. Create vulnerability records ----------------------------------
    synced = 0
    for f in body.findings:
        sev = f.severity.upper() if f.severity else "INFORMATIONAL"
        vuln = Vulnerability(
            vuln_name=f.title,
            description=f.description,
            severity=sev,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            recommendation=f.remediation,
            reference="; ".join(f.references) if f.references else None,
            domain_id=domain.id if domain else None,
            created_by=username,
        )
        db.add(vuln)
        synced += 1

    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception("CI sync commit failed")
        raise HTTPException(status_code=500, detail=f"Failed to persist scan: {exc}")

    logger.info(
        "CI scan synced: scan_id=%s findings=%d user=%s",
        scan.id, synced, username,
    )

    return CISyncResponse(
        scan_id=str(scan.id),
        findings_synced=synced,
        message="Scan synced successfully",
    )


@router.get("/scans")
def list_ci_scans(
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(verify_api_key),
):
    """List CI/CD scans (API key auth — for CLI/CI usage)."""
    return _query_ci_scans(db, claims)


def _query_ci_scans(db: Session, claims: Dict[str, Any]):
    """Shared query for CI scan listing."""
    from app.api.auth import get_tenant_usernames
    from sqlalchemy import or_

    tenant_users = get_tenant_usernames(db, claims)
    scans = (
        db.query(Scan)
        .filter(
            Scan.scan_type.like("ci_%"),
            or_(
                Scan.created_by.in_(tenant_users),
                Scan.created_by.is_(None),
            ),
        )
        .order_by(Scan.created_at.desc())
        .limit(100)
        .all()
    )

    return [
        {
            "id": str(s.id),
            "scan_name": s.scan_name,
            "scan_type": s.scan_type,
            "status": s.status,
            "findings_count": s.findings_count or 0,
            "created_by": s.created_by,
            "created_at": str(s.created_at),
        }
        for s in scans
    ]


# ---------------------------------------------------------------------------
# Dashboard endpoint (JWT auth — for frontend)
# ---------------------------------------------------------------------------
@router.get("/dashboard/scans")
def list_ci_scans_dashboard(
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """List CI/CD scans (JWT auth — for the frontend dashboard)."""
    return _query_ci_scans(db, claims)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _resolve_domain(db: Session, url: str) -> Optional[Domain]:
    """Try to match a base_url to an existing domain in the asset inventory."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            return None
        # Strip www. prefix for matching
        bare = host.lower().removeprefix("www.")
        domain = (
            db.query(Domain)
            .filter(Domain.domain_name.ilike(f"%{bare}%"))
            .first()
        )
        return domain
    except Exception:
        return None
