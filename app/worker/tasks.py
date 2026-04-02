from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_db_session():
    """Create a standalone DB session for the Celery worker."""
    from app.database.session import SessionLocal
    if SessionLocal is None:
        raise RuntimeError("Database not configured")
    return SessionLocal()


@celery_app.task(bind=True, name="app.worker.tasks.run_api_scan_task")
def run_api_scan_task(
    self,
    scan_id: str,
    scan_name: str,
    asset_url: str,
    endpoints: Optional[List[Dict[str, Any]]] = None,
    openapi_spec: Optional[Any] = None,
    postman_collection: Optional[Dict[str, Any]] = None,
    auth_config: Optional[Dict[str, Any]] = None,
    secondary_auth_config: Optional[Dict[str, Any]] = None,
    scan_mode: str = "active",
):
    """
    Celery task that runs the API APT scan in a worker process.
    This runs asynchronously — the API endpoint returns immediately.
    """
    db = _get_db_session()

    try:
        from app.scanners.api_scanner.main import run_api_scan
        from app.database.models import ApiScanReport, Scan
        from app.storage.file_storage import save_scan_result
        from app.storage.minio_client import MINIO_BUCKET, upload_file_to_minio

        logger.info("Celery worker starting API scan '%s' (id=%s)", scan_name, scan_id)

        # Run the async scan in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            report = loop.run_until_complete(
                run_api_scan(
                    scan_name=scan_name,
                    asset_url=asset_url,
                    endpoints=endpoints,
                    openapi_spec=openapi_spec,
                    postman_collection=postman_collection,
                    auth_config=auth_config,
                    secondary_auth_config=secondary_auth_config,
                    scan_mode=scan_mode,
                    db=db,
                    scan_id=scan_id,
                )
            )
        finally:
            loop.close()

        # Save JSON locally
        final_result = {
            "scan_id": scan_id,
            "scan_name": scan_name,
            "scan_type": "api",
            "status": "completed",
            "created_at": datetime.utcnow().isoformat(),
            "asset_url": asset_url,
            "result": report,
        }
        file_path = save_scan_result(
            scan_name=scan_name,
            scan_id=scan_id,
            scan_type="api",
            data=final_result,
        )

        # Upload to MinIO
        object_name = Path(file_path).name
        try:
            upload_file_to_minio(file_path, object_name)
        except Exception:
            object_name = None

        # Save report to DB
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            api_report = ApiScanReport(
                scan_id=scan.id,
                asset_url=asset_url,
                minio_bucket=MINIO_BUCKET if object_name else None,
                minio_object_name=object_name,
                report_json=json.dumps(report),
            )
            db.add(api_report)
            scan.status = "COMPLETED"
            scan.progress = 100
            scan.current_phase = "COMPLETED"
            scan.findings_count = report.get("total_findings", 0)
            db.commit()

        logger.info(
            "API scan '%s' completed — %d findings",
            scan_name, report.get("total_findings", 0),
        )
        return {"scan_id": scan_id, "status": "COMPLETED", "total_findings": report.get("total_findings", 0)}

    except Exception as e:
        logger.error("API scan '%s' failed in Celery worker: %s", scan_name, e)
        try:
            from app.database.models import Scan
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "FAILED"
                scan.current_phase = "FAILED"
                db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise
    finally:
        db.close()
