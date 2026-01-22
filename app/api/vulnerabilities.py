from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import get_token_claims
from app.database.models import ApiScanReport, Scan, Vulnerability, Domain, Subdomain
from app.database.session import get_db
from app.storage.minio_client import download_json


router = APIRouter(
    prefix="/vulnerabilities",
    tags=["Vulnerabilities"],
    dependencies=[Depends(get_token_claims)],
)


def _extract_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Support both shapes:
    - MinIO wrapper: { ..., "result": { ..., "findings": [...] } }
    - DB raw report: { ..., "findings": [...] }
    """
    if isinstance(report.get("result"), dict):
        findings = report["result"].get("findings")
        return findings if isinstance(findings, list) else []
    findings = report.get("findings")
    return findings if isinstance(findings, list) else []


@router.get("/api-findings")
def list_api_findings(
    db: Session = Depends(get_db),
    severity: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Flatten API scan findings so frontend can render them in Vulnerability section.
    """
    q = (
        db.query(Scan, ApiScanReport)
        .join(ApiScanReport, ApiScanReport.scan_id == Scan.id)
        .filter(Scan.scan_type == "api")
        .order_by(Scan.created_at.desc())
    )

    if scan_id:
        q = q.filter(Scan.id == scan_id)

    rows = q.all()
    out: List[Dict[str, Any]] = []

    for scan, api_report in rows:
        report_obj: Optional[Dict[str, Any]] = None

        # Prefer MinIO (DD-style)
        object_name = getattr(api_report, "minio_object_name", None)
        if object_name:
            try:
                report_obj = download_json(object_name)
            except Exception:
                report_obj = None

        # Fallback to DB JSON
        if report_obj is None:
            try:
                report_obj = json.loads(api_report.report_json or "{}")
            except Exception:
                report_obj = {}

        findings = _extract_findings(report_obj or {})
        asset_url = (
            getattr(api_report, "asset_url", None)
            or (report_obj or {}).get("asset_url")
            or None
        )

        # Backfill DB so URL is not empty next time (MinIO wrapper has it)
        if not getattr(api_report, "asset_url", None) and asset_url:
            try:
                api_report.asset_url = asset_url
                db.add(api_report)
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass

        for f in findings:
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity") or "").upper()
            if severity and sev != str(severity).upper():
                continue
            out.append(
                {
                    "scan_id": str(scan.id),
                    "asset_url": asset_url,
                    "scan_type": scan.scan_type,
                    "created_at": scan.created_at,
                    "issue": f.get("issue") or f.get("name"),
                    "severity": sev or None,
                    "endpoint": f.get("endpoint"),
                    "evidence": f.get("evidence"),
                }
            )

    return {"message": "Success", "total": len(out), "data": out}


@router.get("/findings")
def list_all_findings(
    db: Session = Depends(get_db),
    severity: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Unified Vulnerability feed:
    - API scan findings (from MinIO/DB report)
    - Subdomain scan findings (from `vulnerabilities` table)
    """
    out: List[Dict[str, Any]] = []

    # 1) API findings (reuse existing logic)
    api_resp = list_api_findings(db=db, severity=severity, scan_id=None)
    api_items = api_resp.get("data") if isinstance(api_resp, dict) else []
    if isinstance(api_items, list):
        # Normalize API findings to a richer shape (fields may be null for API)
        for item in api_items:
            if not isinstance(item, dict):
                continue
            out.append(
                {
                    **item,
                    "name": item.get("issue"),
                    "description": item.get("evidence"),
                    "cvss_score": None,
                    "cvss_vector": None,
                    "recommendation": None,
                    "reference": None,
                }
            )

    # 2) Subdomain/Domain vulnerabilities from DB
    # Try a rich select; if schema is missing columns, fall back to minimal columns.
    def _query_rich():
        return (
            db.query(
                Vulnerability.id,
                Vulnerability.domain_id,
                Vulnerability.subdomain_id,
                Vulnerability.vuln_name,
                Vulnerability.description,
                Vulnerability.cvss_score,
                Vulnerability.cvss_vectore,
                Vulnerability.recommendation,
                Vulnerability.reference,
                Vulnerability.severity,
                Vulnerability.created_at,
                Domain.domain_name,
                Subdomain.subdomain_name,
            )
            .outerjoin(Domain, Vulnerability.domain_id == Domain.id)
            .outerjoin(Subdomain, Vulnerability.subdomain_id == Subdomain.id)
            .order_by(Vulnerability.id.desc())
        )

    def _query_minimal():
        return (
            db.query(
                Vulnerability.id,
                Vulnerability.domain_id,
                Vulnerability.subdomain_id,
                Vulnerability.vuln_name,
                Vulnerability.severity,
                Domain.domain_name,
                Subdomain.subdomain_name,
            )
            .outerjoin(Domain, Vulnerability.domain_id == Domain.id)
            .outerjoin(Subdomain, Vulnerability.subdomain_id == Subdomain.id)
            .order_by(Vulnerability.id.desc())
        )

    try:
        rows = _query_rich().all()
        for (
            v_id,
            v_domain_id,
            v_subdomain_id,
            v_name,
            v_desc,
            v_cvss,
            v_vec,
            v_rec,
            v_ref,
            v_sev,
            v_created,
            domain_name,
            subdomain_name,
        ) in rows:
            sev = str(v_sev or "").upper()
            if severity and sev != str(severity).upper():
                continue
            out.append(
                {
                    "scan_id": None,
                    "scan_type": "subdomain" if v_subdomain_id else "dd",
                    "created_at": v_created,
                    "issue": v_name,  # backward compat
                    "name": v_name,
                    "description": v_desc,
                    "cvss_score": v_cvss,
                    "cvss_vector": v_vec,
                    "recommendation": v_rec,
                    "reference": v_ref,
                    "endpoint": domain_name,
                    "asset_url": subdomain_name or domain_name,
                    "severity": sev or None,
                    "evidence": None,
                }
            )
    except Exception:
        rows = _query_minimal().all()
        for (
            v_id,
            v_domain_id,
            v_subdomain_id,
            v_name,
            v_sev,
            domain_name,
            subdomain_name,
        ) in rows:
            sev = str(v_sev or "").upper()
            if severity and sev != str(severity).upper():
                continue
            out.append(
                {
                    "scan_id": None,
                    "scan_type": "subdomain" if v_subdomain_id else "dd",
                    "created_at": None,
                    "issue": v_name,
                    "name": v_name,
                    "description": None,
                    "cvss_score": None,
                    "cvss_vector": None,
                    "recommendation": None,
                    "reference": None,
                    "endpoint": domain_name,
                    "asset_url": subdomain_name or domain_name,
                    "severity": sev or None,
                    "evidence": None,
                }
            )

    return {"message": "Success", "total": len(out), "data": out}

