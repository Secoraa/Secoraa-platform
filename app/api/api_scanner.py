import json
import logging
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from app.api.auth import get_token_claims
from app.database.models import ApiScanReport, Scan
from app.database.session import get_db
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/scanner",
    tags=["API Scanner"],
    dependencies=[Depends(get_token_claims)],
)


class AuthConfig(BaseModel):
    type: str = Field(default="none", description="Auth type: bearer | api_key | api_key_query | basic | none")
    token: Optional[str] = Field(default=None, description="Bearer token (JWT or opaque)")
    header_name: Optional[str] = Field(default=None, description="Header name for API key auth")
    param_name: Optional[str] = Field(default=None, description="Query param name for API key auth")
    value: Optional[str] = Field(default=None, description="API key value")
    username: Optional[str] = Field(default=None, description="Username for Basic auth")
    password: Optional[str] = Field(default=None, description="Password for Basic auth")


class ApiScanRequest(BaseModel):
    scan_name: str = Field(..., min_length=1)
    asset_url: str = Field(..., min_length=1, description="Base URL of the target API, e.g. https://api.example.com")
    postman_collection: Optional[Dict[str, Any]] = Field(default=None, description="Postman collection JSON")
    endpoints: Optional[List[Dict[str, Any]]] = Field(default=None, description="Selected endpoints list")
    openapi_spec: Optional[Any] = Field(default=None, description="OpenAPI 3.x / Swagger 2.0 spec (JSON dict or YAML string)")
    auth_config: Optional[AuthConfig] = Field(default=None, description="Authentication configuration")
    secondary_auth_config: Optional[AuthConfig] = Field(default=None, description="Secondary auth for privilege escalation testing")
    scan_mode: str = Field(default="active", description="Scan mode: active | passive")


def _celery_available() -> bool:
    """Check if Celery + Redis broker is reachable."""
    try:
        from app.worker.celery_app import celery_app
        conn = celery_app.connection()
        conn.connect()
        conn.close()
        return True
    except Exception:
        return False


@router.get("/api/{scan_id}/status")
async def get_api_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """Get the current status and progress of an API scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": str(scan.id),
        "scan_name": scan.scan_name,
        "status": scan.status,
        "progress": scan.progress or 0,
        "current_phase": scan.current_phase,
        "findings_count": scan.findings_count or 0,
        "endpoints_total": scan.endpoints_total or 0,
        "endpoints_scanned": scan.endpoints_scanned or 0,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


@router.post("/api/{scan_id}/cancel")
async def cancel_api_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """Cancel a running API scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "IN_PROGRESS":
        raise HTTPException(status_code=400, detail="Scan is not in progress")
    scan.status = "CANCELLED"
    db.commit()
    return {"scan_id": str(scan.id), "status": "CANCELLED"}


@router.post("/api")
async def start_api_scan(
    body: ApiScanRequest,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """
    Run the API APT scanner against provided endpoints.
    If Celery + Redis are available, the scan runs in a background worker (returns 202).
    Otherwise, falls back to synchronous execution.
    """
    if not body.postman_collection and not body.endpoints and not body.openapi_spec:
        raise HTTPException(status_code=400, detail="Provide postman_collection, openapi_spec, or endpoints")

    created_by = str(claims.get("sub") or "")

    scan = Scan(
        scan_name=body.scan_name,
        scan_type="api",
        status="IN_PROGRESS",
        created_at=datetime.utcnow(),
        created_by=created_by or None,
    )
    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)
    except IntegrityError:
        try:
            db.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=409, detail="Scan name already exists. Please choose a different scan name.")

    auth_dict = body.auth_config.model_dump() if body.auth_config else None
    secondary_auth_dict = body.secondary_auth_config.model_dump() if body.secondary_auth_config else None
    scan_id = str(scan.id)

    # ── Try Celery (background worker) ─────────────────────────────
    if _celery_available():
        try:
            from app.worker.tasks import run_api_scan_task

            run_api_scan_task.delay(
                scan_id=scan_id,
                scan_name=body.scan_name,
                asset_url=body.asset_url,
                endpoints=body.endpoints,
                openapi_spec=body.openapi_spec,
                postman_collection=body.postman_collection,
                auth_config=auth_dict,
                secondary_auth_config=secondary_auth_dict,
                scan_mode=body.scan_mode,
            )

            logger.info("API scan '%s' queued to Celery worker", body.scan_name)
            return JSONResponse(
                status_code=202,
                content={
                    "scan_id": scan_id,
                    "scan_name": body.scan_name,
                    "status": "IN_PROGRESS",
                    "message": "Scan queued. Poll /scanner/api/{scan_id}/status for progress.",
                },
            )
        except Exception as exc:
            logger.warning("Celery dispatch failed, falling back to sync: %s", exc)

    # ── Fallback: synchronous execution ────────────────────────────
    try:
        from app.scanners.api_scanner.main import run_api_scan
        from app.storage.file_storage import save_scan_result
        from app.storage.minio_client import MINIO_BUCKET, upload_file_to_minio

        report = await run_api_scan(
            scan_name=body.scan_name,
            asset_url=body.asset_url,
            postman_collection=body.postman_collection,
            endpoints=body.endpoints,
            openapi_spec=body.openapi_spec,
            auth_config=auth_dict,
            secondary_auth_config=secondary_auth_dict,
            scan_mode=body.scan_mode,
            db=db,
            scan_id=scan_id,
        )

        final_result = {
            "scan_id": scan_id,
            "scan_name": scan.scan_name,
            "scan_type": scan.scan_type,
            "status": "completed",
            "created_at": datetime.utcnow().isoformat(),
            "asset_url": body.asset_url,
            "result": report,
        }
        file_path = save_scan_result(
            scan_name=scan.scan_name,
            scan_id=scan_id,
            scan_type="api",
            data=final_result,
        )

        object_name = Path(file_path).name
        try:
            upload_file_to_minio(file_path, object_name)
        except Exception:
            object_name = None

        api_report = ApiScanReport(
            scan_id=scan.id,
            asset_url=body.asset_url,
            minio_bucket=MINIO_BUCKET if object_name else None,
            minio_object_name=object_name,
            report_json=json.dumps(report),
        )
        db.add(api_report)
        scan.status = "COMPLETED"
        scan.progress = 100
        scan.current_phase = "COMPLETED"
        db.commit()

        logger.info("API scan '%s' completed (sync) — %d findings", body.scan_name, report.get("total_findings", 0))
        return {"scan_id": scan_id, **report}

    except HTTPException:
        scan.status = "FAILED"
        db.commit()
        raise
    except Exception as e:
        logger.error("API scan '%s' failed: %s", body.scan_name, e)
        scan.status = "FAILED"
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))
