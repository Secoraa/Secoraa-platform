import json
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from app.api.auth import get_token_claims
from app.scanners.api_scanner.main import run_api_scan
from app.database.models import ApiScanReport, Scan
from app.database.session import get_db
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.storage.file_storage import save_scan_result
from app.storage.minio_client import MINIO_BUCKET, upload_file_to_minio


router = APIRouter(
    prefix="/scanner",
    tags=["API Scanner"],
    dependencies=[Depends(get_token_claims)],
)


class ApiScanRequest(BaseModel):
    scan_name: str = Field(..., min_length=1)
    asset_url: str = Field(..., min_length=1, description="Base URL of the target API, e.g. https://api.example.com")
    # Backwards-compatible: either provide a full postman collection OR pre-extracted endpoints
    postman_collection: Optional[Dict[str, Any]] = Field(default=None, description="Postman collection JSON (optional)")
    endpoints: Optional[List[Dict[str, Any]]] = Field(default=None, description="Selected endpoints list (optional)")


@router.post("/api")
async def start_api_scan(
    body: ApiScanRequest,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    """
    Run the API scanner using a Postman collection provided as JSON.
    (No multipart upload needed.)
    """
    if not body.postman_collection and not body.endpoints:
        raise HTTPException(status_code=400, detail="Provide either postman_collection or endpoints")

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

    try:
        report = await run_api_scan(
            scan_name=body.scan_name,
            asset_url=body.asset_url,
            postman_collection=body.postman_collection,
            endpoints=body.endpoints,
        )

        # Save JSON locally (same as DD flow)
        final_result = {
            "scan_id": str(scan.id),
            "scan_name": scan.scan_name,
            "scan_type": scan.scan_type,
            "status": "completed",
            "created_at": datetime.utcnow().isoformat(),
            "asset_url": body.asset_url,
            "result": report,
        }
        file_path = save_scan_result(
            scan_name=scan.scan_name,
            scan_id=str(scan.id),
            scan_type="api",
            data=final_result,
        )

        # Upload to MinIO (same as DD flow)
        object_name = Path(file_path).name
        try:
            upload_file_to_minio(file_path, object_name)
        except Exception:
            # Don't fail scan if MinIO upload fails (matches DD behavior)
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
        db.commit()
        return {"scan_id": str(scan.id), **report}
    except HTTPException:
        scan.status = "FAILED"
        db.commit()
        raise
    except Exception as e:
        scan.status = "FAILED"
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))
