from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends
from uuid import uuid4, UUID
from datetime import datetime, timezone
import logging
import threading
import os

from app.schemas.scan import CreateScanRequest
from app.scanners.registry import SCANNERS
from app.storage.file_storage import save_scan_result
from app.storage.minio_client import upload_file_to_minio
from app.database.session import SessionLocal
import json
import asyncio
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional, List

from app.database.models import Scan, ScanResult, Domain, Subdomain, ApiScanReport, Vulnerability, ScheduledScan
from app.storage.minio_client import download_json, object_exists
from sqlalchemy import Select
from app.api.auth import get_token_claims, get_tenant_usernames
from app.scanners.api_scanner.main import run_api_scan
from app.storage.minio_client import MINIO_BUCKET
from app.database.session import get_db
from sqlalchemy.orm import Session
from app.scanners.subdomain_scanner.discovery.bruteforce import bruteforce_subdomains
from app.scanners.subdomain_scanner.discovery.passive import fetch_from_crtsh
from app.scanners.subdomain_scanner.validation.dns_check import validate_dns

router = APIRouter(
    prefix="/scans",
    tags=["Run-Scans"],
    dependencies=[Depends(get_token_claims)],
)
logger = logging.getLogger(__name__)

# Global dictionary to track running scans
# Format: {scan_id: {"thread": thread_obj, "pause_event": threading.Event()}}
running_scans = {}
scan_lock = threading.Lock()


class CreateScheduledScanRequest(BaseModel):
    scan_name: str = Field(..., min_length=1)
    scan_type: str = Field(..., min_length=1)
    scheduled_for: datetime
    payload: Dict[str, Any] = Field(default_factory=dict)


class UpdateScheduledScanRequest(BaseModel):
    scheduled_for: datetime


def _create_scan_record_and_start_thread(db: SessionLocal, scan_name: str, scan_type: str, payload_dict: dict, created_by: str):
    """
    Shared helper used by both the HTTP endpoint and the scheduler worker.
    Creates Scan row and starts background processing for dd/subdomain scans.
    """
    scanner = SCANNERS.get(scan_type)
    if not scanner:
        raise HTTPException(status_code=400, detail="Invalid scan type")

    # Make scan_name unique if needed
    try:
        scan = Scan(
            scan_name=scan_name,
            scan_type=scan_type,
            status="IN_PROGRESS",
            created_at=datetime.utcnow(),
            created_by=created_by,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
    except Exception as db_error:
        if "unique" in str(db_error).lower() or "duplicate" in str(db_error).lower():
            scan_name = f"{scan_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            scan = Scan(
                scan_name=scan_name,
                scan_type=scan_type,
                status="IN_PROGRESS",
                created_at=datetime.utcnow(),
                created_by=created_by,
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
        else:
            raise

    thread = threading.Thread(
        target=process_scan_background,
        args=(str(scan.id), scan_name, scan_type, payload_dict, created_by),
        daemon=True,
    )
    thread.start()
    return scan, scan_name


def _run_api_scan_and_persist(db: Session, scan_name: str, asset_url: str, endpoints: Optional[List[Dict[str, Any]]], created_by: str):
    """
    Run API scan synchronously (same behavior as /scanner/api) and persist to Scan + ApiScanReport.
    Returns scan_id (uuid string).
    """
    scan = Scan(
        scan_name=scan_name,
        scan_type="api",
        status="IN_PROGRESS",
        created_at=datetime.utcnow(),
        created_by=created_by or None,
    )
    db.add(scan)
    try:
        db.commit()
        db.refresh(scan)
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            scan.scan_name = f"{scan_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            db.add(scan)
            db.commit()
            db.refresh(scan)
        else:
            raise

    try:
        report = asyncio.run(
            run_api_scan(
                scan_name=scan.scan_name,
                asset_url=asset_url,
                postman_collection=None,
                endpoints=endpoints,
            )
        )

        final_result = {
            "scan_id": str(scan.id),
            "scan_name": scan.scan_name,
            "scan_type": scan.scan_type,
            "status": "completed",
            "created_at": datetime.utcnow().isoformat(),
            "asset_url": asset_url,
            "result": report,
        }
        file_path = save_scan_result(
            scan_name=scan.scan_name,
            scan_id=str(scan.id),
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
            asset_url=asset_url,
            minio_bucket=MINIO_BUCKET if object_name else None,
            minio_object_name=object_name,
            report_json=json.dumps(report),
        )
        db.add(api_report)
        scan.status = "COMPLETED"
        db.commit()
        return str(scan.id)
    except Exception as e:
        scan.status = "FAILED"
        db.commit()
        raise


_schedule_worker_started = False
_schedule_worker_stop = threading.Event()
_schedule_worker_thread: Optional[threading.Thread] = None


def start_schedule_worker():
    """
    Start a lightweight background worker that polls `scheduled_scans` and triggers due scans.
    Safe to call multiple times (starts only once).
    """
    global _schedule_worker_started, _schedule_worker_thread
    if _schedule_worker_started:
        return
    _schedule_worker_started = True

    def _loop():
        logger.info("🕒 Scheduled scan worker started")
        while not _schedule_worker_stop.is_set():
            db = SessionLocal()
            try:
                # 1) Update status of already-triggered schedules based on the underlying Scan status
                in_progress = (
                    db.query(ScheduledScan)
                    .filter(
                        ScheduledScan.triggered_scan_id.isnot(None),
                        ScheduledScan.status.in_(["TRIGGERING", "TRIGGERED", "IN_PROGRESS"]),
                    )
                    .order_by(ScheduledScan.scheduled_for.asc())
                    .limit(50)
                    .all()
                )
                for sched in in_progress:
                    try:
                        scan = None
                        try:
                            scan = db.query(Scan).filter(Scan.id == sched.triggered_scan_id).first()
                        except Exception:
                            scan = None
                        if not scan:
                            continue
                        st = str(getattr(scan, "status", "") or "").upper()
                        if st == "COMPLETED":
                            sched.status = "COMPLETED"
                            db.commit()
                        elif st in {"FAILED", "TERMINATED"}:
                            sched.status = "FAILED"
                            db.commit()
                        elif st in {"IN_PROGRESS", "PAUSED"}:
                            # Normalize legacy TRIGGERED/TRIGGERING to IN_PROGRESS while running.
                            if sched.status != "IN_PROGRESS":
                                sched.status = "IN_PROGRESS"
                                db.commit()
                    except Exception:
                        try:
                            db.rollback()
                        except Exception:
                            pass

                now = datetime.utcnow()
                due = (
                    db.query(ScheduledScan)
                    .filter(ScheduledScan.status == "PENDING", ScheduledScan.scheduled_for <= now)
                    .order_by(ScheduledScan.scheduled_for.asc())
                    .limit(20)
                    .all()
                )
                for sched in due:
                    try:
                        # Mark as TRIGGERING to avoid double-trigger
                        sched.status = "TRIGGERING"
                        db.commit()

                        payload = {}
                        try:
                            payload = json.loads(sched.payload_json or "{}")
                        except Exception:
                            payload = {}

                        created_by = sched.created_by or "scheduler"

                        if sched.scan_type == "api":
                            asset_url = payload.get("asset_url") or payload.get("assetUrl")
                            endpoints = payload.get("endpoints")
                            if not asset_url:
                                raise ValueError("asset_url is required for api scheduled scan")
                            if not isinstance(endpoints, list) or not endpoints:
                                raise ValueError("endpoints list is required for api scheduled scan")
                            scan_id = _run_api_scan_and_persist(db, sched.scan_name, asset_url, endpoints, created_by)
                            # API scan is run synchronously here, so mark schedule as COMPLETED.
                            sched.status = "COMPLETED"
                        else:
                            scan, _final_name = _create_scan_record_and_start_thread(
                                db, sched.scan_name, sched.scan_type, payload, created_by
                            )
                            scan_id = str(scan.id)
                            # DD/Subdomain scans run async; reflect that in schedule history.
                            sched.status = "IN_PROGRESS"
                        try:
                            sched.triggered_scan_id = UUID(scan_id)
                        except Exception:
                            sched.triggered_scan_id = None
                        sched.triggered_at = datetime.utcnow()
                        sched.error = None
                        db.commit()
                    except Exception as e:
                        try:
                            db.rollback()
                        except Exception:
                            pass
                        try:
                            sched.status = "FAILED"
                            sched.error = str(e)
                            db.commit()
                        except Exception:
                            pass
            except Exception as e:
                logger.error(f"Scheduled scan worker error: {e}", exc_info=True)
                try:
                    db.rollback()
                except Exception:
                    pass
            finally:
                db.close()

            _schedule_worker_stop.wait(2.0)

        logger.info("🕒 Scheduled scan worker stopped")

    _schedule_worker_thread = threading.Thread(target=_loop, daemon=True)
    _schedule_worker_thread.start()


def stop_schedule_worker():
    _schedule_worker_stop.set()


def run_scan_with_control(scan_id: str, scan_type: str, payload_dict: dict, pause_event: threading.Event):
    """Run scan with process control (pause/terminate support)"""
    if scan_type != "dd":
        # For other scan types, use the regular scanner
        scanner = SCANNERS.get(scan_type)
        if not scanner:
            raise ValueError(f"Invalid scan type: {scan_type}")
        return scanner.run(payload_dict)
    
    # For dd scanner, use Popen for control
    domain = payload_dict.get("domain")
    if not domain:
        raise ValueError("Domain is required")

    def _check_terminated():
        with scan_lock:
            scan_info = running_scans.get(scan_id)
            if scan_info and scan_info.get("terminated"):
                raise InterruptedError("Scan was terminated")

    def _wait_if_paused():
        import time
        while pause_event.is_set():
            _check_terminated()
            time.sleep(0.5)

    _check_terminated()
    _wait_if_paused()
    passive = fetch_from_crtsh(domain)

    _check_terminated()
    _wait_if_paused()
    brute = bruteforce_subdomains(domain)
    discovered = list(set(passive).union(brute))

    _check_terminated()
    _wait_if_paused()
    resolved = validate_dns(discovered)
    all_subdomains = list(set(resolved))

    # Filter wildcards (simplified - using scanner's filter if available)
    scanner = SCANNERS.get(scan_type)
    if scanner and hasattr(scanner, '_filter_wildcards'):
        valid_subdomains = scanner._filter_wildcards(all_subdomains, domain)
    else:
        valid_subdomains = [s for s in all_subdomains if s.strip()]

    return {
        "scan_type": scan_type,
        "domain": domain,
        "subdomains": valid_subdomains,
        "total_found": len(valid_subdomains),
        "total_before_filtering": len(all_subdomains)
    }


def process_scan_background(scan_id: str, scan_name: str, scan_type: str, payload_dict: dict, created_by: str):
    """Background function to process scan and update status"""
    db = SessionLocal()
    
    # Register scan in running_scans
    pause_event = threading.Event()
    with scan_lock:
        running_scans[scan_id] = {
            "pause_event": pause_event,
            "terminated": False
        }
    
    try:
        # Get the scan record
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        try:
            # Check if terminated before starting
            with scan_lock:
                if running_scans.get(scan_id, {}).get("terminated"):
                    scan.status = "TERMINATED"
                    db.commit()
                    return
            
            # 1️⃣ Run scan with control
            logger.info(f"Running scan: {scan_name}, type: {scan_type}, domain: {payload_dict.get('domain')}")
            
            # Check for pause before running
            while pause_event.is_set():
                scan.status = "PAUSED"
                db.commit()
                # Wait until resumed, but check for termination periodically
                import time
                for _ in range(20):  # Wait up to 10 seconds (20 * 0.5s)
                    if not pause_event.is_set():
                        break
                    with scan_lock:
                        if running_scans.get(scan_id, {}).get("terminated"):
                            scan.status = "TERMINATED"
                            db.commit()
                            return
                    time.sleep(0.5)
                if pause_event.is_set():
                    pause_event.wait(timeout=0.5)
            
            scan.status = "IN_PROGRESS"
            db.commit()
            
            scan_output = run_scan_with_control(scan_id, scan_type, payload_dict, pause_event)
            logger.info(f"Scan completed. Found {len(scan_output.get('subdomains', []))} subdomains")
            
            # Check if terminated after scan
            with scan_lock:
                if running_scans.get(scan_id, {}).get("terminated"):
                    scan.status = "TERMINATED"
                    db.commit()
                    return
            
            # Check for pause before processing results
            while pause_event.is_set():
                scan.status = "PAUSED"
                db.commit()
                import time
                for _ in range(20):  # Wait up to 10 seconds
                    if not pause_event.is_set():
                        break
                    with scan_lock:
                        if running_scans.get(scan_id, {}).get("terminated"):
                            scan.status = "TERMINATED"
                            db.commit()
                            return
                    time.sleep(0.5)
                if pause_event.is_set():
                    pause_event.wait(timeout=0.5)
            
            scan.status = "IN_PROGRESS"
            db.commit()

            # 2️⃣ Update scan status to COMPLETED (if not terminated)
            with scan_lock:
                if not running_scans.get(scan_id, {}).get("terminated"):
                    scan.status = "COMPLETED"
                    db.commit()
                    db.refresh(scan)
                else:
                    scan.status = "TERMINATED"
                    db.commit()
                    return

            # 3️⃣ SAVE SUBDOMAINS TO DB
            subdomains = scan_output.get("subdomains", [])
            domain_name = scan_output.get("domain", "").strip().lower() if scan_output.get("domain") else ""
            saved_count = 0
            subdomain_saved_count = 0

            # Network scan: store target IP in ScanResult for history asset column
            if str(scan_type or "").lower() == "network":
                target_ip = (scan_output.get("target") or payload_dict.get("target_ip") or "").strip()
                if target_ip:
                    try:
                        result = ScanResult(
                            scan_id=scan.id,
                            domain=target_ip,
                            subdomain="",
                        )
                        db.add(result)
                        db.commit()
                    except Exception as e:
                        logger.error(f"Error saving network scan result for {target_ip}: {e}")
                        try:
                            db.rollback()
                        except Exception:
                            pass
            
            if subdomains and domain_name:
                logger.info(f"Saving {len(subdomains)} subdomains to database for domain: {domain_name}")
                
                # 3a. Get or create Domain record (normalize domain name for lookup)
                stmt = Select(Domain).filter(Domain.domain_name == domain_name)
                domain = db.execute(stmt).scalars().first()
                
                if not domain:
                    # Create domain if it doesn't exist (auto-discovered from scan)
                    domain = Domain(
                        domain_name=domain_name,
                        discovery_source="auto_discovered",
                        created_by=created_by,
                        updated_by=created_by
                    )
                    db.add(domain)
                    db.commit()
                    db.refresh(domain)
                    logger.info(f"Created new domain: {domain_name} (ID: {domain.id})")
                else:
                    logger.info(f"Found existing domain: {domain_name} (ID: {domain.id})")
                
                # Verify domain was found/created
                if not domain or not domain.id:
                    raise ValueError(f"Failed to get or create domain: {domain_name}")
                
                # 3b. Get existing subdomains for this domain in one query (more efficient)
                existing_subdomain_stmt = Select(Subdomain.subdomain_name).filter(
                    Subdomain.domain_id == domain.id
                )
                existing_subdomains_set = set(
                    db.execute(existing_subdomain_stmt).scalars().all()
                )
                logger.info(f"Found {len(existing_subdomains_set)} existing subdomains for domain {domain_name}")
                
                # 3c. Save subdomains to both ScanResult (for scan history) and Subdomain (for UI)
                new_subdomains_to_add = []
                
                for subdomain_name in subdomains:
                    if not subdomain_name or not subdomain_name.strip():
                        continue
                    
                    subdomain_name = subdomain_name.strip()
                    
                    try:
                        # Save to ScanResult table (for scan history)
                        result = ScanResult(
                            scan_id=scan.id,
                            domain=domain_name,
                            subdomain=subdomain_name,
                        )
                        db.add(result)
                        saved_count += 1
                        
                        # Check if subdomain already exists (using in-memory set for efficiency)
                        if subdomain_name not in existing_subdomains_set:
                            # Mark as existing to avoid duplicates in this batch
                            existing_subdomains_set.add(subdomain_name)
                            new_subdomains_to_add.append(subdomain_name)
                        
                    except Exception as e:
                        logger.error(f"Error adding subdomain {subdomain_name} to ScanResult: {e}")
                        continue
                
                # 3d. Batch insert new subdomains
                if new_subdomains_to_add:
                    logger.info(f"Adding {len(new_subdomains_to_add)} new subdomains to Subdomain table")
                    for subdomain_name in new_subdomains_to_add:
                        try:
                            subdomain = Subdomain(
                                domain_id=domain.id,
                                subdomain_name=subdomain_name,
                                created_by=created_by,
                                updated_by=created_by
                            )
                            db.add(subdomain)
                            subdomain_saved_count += 1
                        except Exception as e:
                            logger.error(f"Error adding subdomain {subdomain_name} to Subdomain table: {e}")
                            # Continue with other subdomains even if one fails
                            continue
                
                # 3e. Commit all changes
                if saved_count > 0 or subdomain_saved_count > 0:
                    try:
                        db.commit()
                        logger.info(
                            f"✅ Successfully saved {saved_count} scan results and "
                            f"{subdomain_saved_count} new subdomains to database for domain {domain_name}"
                        )
                    except Exception as e:
                        logger.error(f"❌ Error committing subdomains to database: {e}")
                        db.rollback()
                        raise
                else:
                    logger.warning(f"No new subdomains to save for domain {domain_name} (all may already exist)")

                # 3f. Persist vulnerabilities for Subdomain scans (so they show in Vulnerability page)
                if scan_type == "subdomain":
                    try:
                        report = scan_output.get("report") or {}
                        per_sub = report.get("subdomains") if isinstance(report, dict) else None
                        if isinstance(per_sub, dict) and per_sub:
                            # Build a map of subdomain_name -> Subdomain row for FK
                            sub_stmt = Select(Subdomain).filter(
                                Subdomain.domain_id == domain.id,
                                Subdomain.subdomain_name.in_(list(per_sub.keys())),
                            )
                            sub_rows = db.execute(sub_stmt).scalars().all()
                            sub_map = {s.subdomain_name: s for s in sub_rows}

                            created_at = datetime.utcnow()
                            added = 0

                            for sub_name, sub_data in per_sub.items():
                                if not isinstance(sub_data, dict):
                                    continue
                                vulns = sub_data.get("vulnerabilities") if isinstance(sub_data.get("vulnerabilities"), dict) else {}
                                exposure = vulns.get("exposure") if isinstance(vulns.get("exposure"), list) else []
                                misconfig = vulns.get("misconfiguration") if isinstance(vulns.get("misconfiguration"), dict) else {}
                                takeover = vulns.get("takeover")

                                sub_row = sub_map.get(sub_name)
                                sub_id = getattr(sub_row, "id", None) if sub_row else None

                                # Exposure: one vuln per exposed item
                                for item in exposure:
                                    name = str(item).strip()
                                    if not name:
                                        continue
                                    db.add(
                                        Vulnerability(
                                            domain_id=domain.id,
                                            subdomain_id=sub_id,
                                            vuln_name=f"Exposure: {name}",
                                            description=f"Exposed resource detected on {sub_name}: {name}",
                                            recommendation=f"Exposed resource detected on {sub_name}: {name}",
                                            severity="MEDIUM",
                                            cvss_score=None,
                                            created_at=created_at,
                                            updated_at=created_at,
                                            created_by=created_by,
                                            updated_by=created_by,
                                        )
                                    )
                                    added += 1

                                # Misconfig: single record if present
                                if misconfig:
                                    db.add(
                                        Vulnerability(
                                            domain_id=domain.id,
                                            subdomain_id=sub_id,
                                            vuln_name="Security Misconfiguration",
                                            description="Missing recommended security headers or insecure server configuration.",
                                            recommendation=json.dumps(misconfig, indent=2, default=str),
                                            severity="MEDIUM",
                                            cvss_score=None,
                                            created_at=created_at,
                                            updated_at=created_at,
                                            created_by=created_by,
                                            updated_by=created_by,
                                        )
                                    )
                                    added += 1

                                # Takeover: single record if provider present
                                if takeover:
                                    provider = str(takeover).strip()
                                    db.add(
                                        Vulnerability(
                                            domain_id=domain.id,
                                            subdomain_id=sub_id,
                                            vuln_name=f"Potential Subdomain Takeover ({provider})",
                                            description=f"Potential takeover fingerprint detected for {sub_name}: {provider}",
                                            recommendation=f"Potential takeover fingerprint detected for {sub_name}: {provider}",
                                            severity="HIGH",
                                            cvss_score=None,
                                            created_at=created_at,
                                            updated_at=created_at,
                                            created_by=created_by,
                                            updated_by=created_by,
                                        )
                                    )
                                    added += 1

                            if added:
                                try:
                                    db.commit()
                                    logger.info(f"✅ Persisted {added} vulnerability row(s) for subdomain scan {scan.id}")
                                except Exception as e:
                                    # Older DB schemas may not have the optional columns yet.
                                    logger.error(f"❌ Failed to commit vulnerabilities (schema mismatch?): {e}", exc_info=True)
                                    try:
                                        db.rollback()
                                    except Exception:
                                        pass
                                    # Fallback: insert only minimal columns that are likely to exist.
                                    try:
                                        minimal_added = 0
                                        for sub_name, sub_data in per_sub.items():
                                            if not isinstance(sub_data, dict):
                                                continue
                                            vulns = sub_data.get("vulnerabilities") if isinstance(sub_data.get("vulnerabilities"), dict) else {}
                                            exposure = vulns.get("exposure") if isinstance(vulns.get("exposure"), list) else []
                                            misconfig = vulns.get("misconfiguration") if isinstance(vulns.get("misconfiguration"), dict) else {}
                                            takeover = vulns.get("takeover")

                                            sub_row = sub_map.get(sub_name)
                                            sub_id = getattr(sub_row, "id", None) if sub_row else None

                                            for item in exposure:
                                                name = str(item).strip()
                                                if not name:
                                                    continue
                                                db.add(
                                                    Vulnerability(
                                                        domain_id=domain.id,
                                                        subdomain_id=sub_id,
                                                        vuln_name=f"Exposure: {name}",
                                                        severity="MEDIUM",
                                                    )
                                                )
                                                minimal_added += 1

                                            if misconfig:
                                                db.add(
                                                    Vulnerability(
                                                        domain_id=domain.id,
                                                        subdomain_id=sub_id,
                                                        vuln_name="Security Misconfiguration",
                                                        severity="MEDIUM",
                                                    )
                                                )
                                                minimal_added += 1

                                            if takeover:
                                                provider = str(takeover).strip()
                                                db.add(
                                                    Vulnerability(
                                                        domain_id=domain.id,
                                                        subdomain_id=sub_id,
                                                        vuln_name=f"Potential Subdomain Takeover ({provider})",
                                                        severity="HIGH",
                                                    )
                                                )
                                                minimal_added += 1

                                        if minimal_added:
                                            db.commit()
                                            logger.info(f"✅ Persisted {minimal_added} vulnerability row(s) (minimal schema) for subdomain scan {scan.id}")
                                    except Exception as e2:
                                        logger.error(f"❌ Fallback minimal vulnerability insert failed: {e2}", exc_info=True)
                                        try:
                                            db.rollback()
                                        except Exception:
                                            pass
                        else:
                            logger.info("No per-subdomain vulnerabilities found to persist for subdomain scan")
                    except Exception as e:
                        logger.error(f"❌ Failed to persist subdomain vulnerabilities: {e}", exc_info=True)
                        try:
                            db.rollback()
                        except Exception:
                            pass
            else:
                if not domain_name:
                    logger.warning("No domain name found in scan output")
                if not subdomains:
                    logger.warning("No subdomains found in scan output")

            # 4️⃣ Build final JSON
            final_result = {
                "scan_id": str(scan.id),
                "scan_name": scan.scan_name,
                "scan_type": scan_type,
                "status": "completed",
                "created_at": datetime.utcnow().isoformat(),
                "result": scan_output,
            }

            # 5️⃣ Save JSON locally
            file_path = save_scan_result(
                scan_name=scan.scan_name,
                scan_id=str(scan.id),
                scan_type=scan_type,
                data=final_result,
            )

            # 6️⃣ Upload to MinIO
            object_name = Path(file_path).name
            try:
                upload_file_to_minio(file_path, object_name)
                logger.info(f"✅ Successfully uploaded {object_name} to MinIO")
            except Exception as upload_error:
                logger.error(f"❌ Failed to upload {object_name} to MinIO: {upload_error}")
                # Don't roll back the database transaction for upload failures

        except InterruptedError as exc:
            # Scan was terminated - check if it's still marked as terminated
            with scan_lock:
                if running_scans.get(scan_id, {}).get("terminated"):
                    scan.status = "TERMINATED"
                    db.commit()
                    logger.info(f"Scan {scan_id} was terminated")
                else:
                    # If not marked as terminated, it might have been a different interruption
                    scan.status = "FAILED"
                    db.commit()
                    logger.error(f"Scan {scan_id} was interrupted: {exc}")
        except Exception as exc:
            # Check if scan was terminated before setting to FAILED
            with scan_lock:
                if running_scans.get(scan_id, {}).get("terminated"):
                    scan.status = "TERMINATED"
                    db.commit()
                    logger.info(f"Scan {scan_id} was terminated")
                else:
                    # Update scan status to FAILED only if not terminated
                    scan.status = "FAILED"
                    db.commit()
                    logger.error(f"Error processing scan {scan_id}: {exc}", exc_info=True)

    except Exception as e:
        logger.error(f"Error in background scan processing: {e}", exc_info=True)
    finally:
        # Clean up running_scans
        with scan_lock:
            running_scans.pop(scan_id, None)
        db.close()


@router.post("/")
def create_scan(
    request: CreateScanRequest,
    claims: Dict[str, Any] = Depends(get_token_claims),
):

    db = SessionLocal()

    scan_name = request.scan_name
    scan_type = request.scan_type
    created_by = str(claims.get("sub") or claims.get("username") or "manual").strip()
    payload_dict = request.payload.model_dump()

    try:
        scan, final_scan_name = _create_scan_record_and_start_thread(db, scan_name, scan_type, payload_dict, created_by)
        logger.info(f"Started background thread for scan {scan.id}")

        # 3️⃣ Return immediately with scan info
        return {
            "scan_id": str(scan.id),
            "scan_name": final_scan_name,
            "status": "IN_PROGRESS",
            "message": "Scan started successfully"
        }

    except Exception as exc:
        db.rollback()
        logger.error(f"Error creating scan: {exc}", exc_info=True)
        import traceback
        error_detail = f"{str(exc)}\n\nTraceback:\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=error_detail)

    finally:
        db.close()


@router.post("/schedule")
def create_scheduled_scan(
    body: CreateScheduledScanRequest,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    created_by = str(claims.get("sub") or "") or None
    # Normalize time: store UTC-naive datetime
    scheduled_for = body.scheduled_for
    if scheduled_for.tzinfo is not None:
        scheduled_for = scheduled_for.astimezone(timezone.utc).replace(tzinfo=None)

    if scheduled_for < datetime.utcnow():
        raise HTTPException(status_code=400, detail="scheduled_for must be in the future")

    payload_json = json.dumps(body.payload or {}, default=str)
    sched = ScheduledScan(
        scan_name=body.scan_name,
        scan_type=body.scan_type,
        payload_json=payload_json,
        scheduled_for=scheduled_for,
        status="PENDING",
        created_by=created_by,
        created_at=datetime.utcnow(),
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return {
        "id": str(sched.id),
        "scan_name": sched.scan_name,
        "scan_type": sched.scan_type,
        "scheduled_for": sched.scheduled_for,
        "status": sched.status,
    }


@router.get("/schedule")
def list_scheduled_scans(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    tenant_users = get_tenant_usernames(db, claims)
    q = (
        db.query(ScheduledScan)
        .filter(ScheduledScan.created_by.in_(tenant_users))
        .order_by(ScheduledScan.scheduled_for.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = q.all()
    return {
        "total": len(rows),
        "data": [
            {
                "id": str(r.id),
                "scan_name": r.scan_name,
                "scan_type": r.scan_type,
                "scheduled_for": r.scheduled_for,
                # Normalize legacy values for UI (old rows may still be TRIGGERED/TRIGGERING)
                "status": (
                    "COMPLETED"
                    if str(r.status or "").upper() == "TRIGGERED"
                    else "IN_PROGRESS"
                    if str(r.status or "").upper() == "TRIGGERING"
                    else r.status
                ),
                "triggered_scan_id": str(r.triggered_scan_id) if r.triggered_scan_id else None,
                "triggered_at": r.triggered_at,
                "error": r.error,
                "created_at": r.created_at,
                "created_by": r.created_by,
            }
            for r in rows
        ],
    }


@router.post("/schedule/{schedule_id}/cancel")
def cancel_scheduled_scan(
    schedule_id: str,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    try:
        sid = UUID(schedule_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid schedule id")
    tenant_users = get_tenant_usernames(db, claims)
    sched = (
        db.query(ScheduledScan)
        .filter(ScheduledScan.id == sid, ScheduledScan.created_by.in_(tenant_users))
        .first()
    )
    if not sched:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    if sched.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Cannot cancel scheduled scan in status {sched.status}")
    sched.status = "CANCELLED"
    db.commit()
    return {"message": "Cancelled", "id": schedule_id, "status": sched.status}


@router.put("/schedule/{schedule_id}")
def update_scheduled_scan(
    schedule_id: str,
    body: UpdateScheduledScanRequest,
    db: Session = Depends(get_db),
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    try:
        sid = UUID(schedule_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid schedule id")
    tenant_users = get_tenant_usernames(db, claims)
    sched = (
        db.query(ScheduledScan)
        .filter(ScheduledScan.id == sid, ScheduledScan.created_by.in_(tenant_users))
        .first()
    )
    if not sched:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    if sched.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Cannot edit scheduled scan in status {sched.status}")

    scheduled_for = body.scheduled_for
    if scheduled_for.tzinfo is not None:
        scheduled_for = scheduled_for.astimezone(timezone.utc).replace(tzinfo=None)
    if scheduled_for < datetime.utcnow():
        raise HTTPException(status_code=400, detail="scheduled_for must be in the future")

    sched.scheduled_for = scheduled_for
    db.commit()
    return {
        "message": "Updated",
        "id": schedule_id,
        "scheduled_for": sched.scheduled_for,
        "status": sched.status,
    }


@router.get("/scan")
def get_all_scans(
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    db = SessionLocal()
    try:
        tenant_users = get_tenant_usernames(db, claims)
        scans = (
            db.query(Scan)
            .filter(Scan.created_by.in_(tenant_users))
            .order_by(Scan.created_at.desc())
            .all()
        )
        scan_ids = [s.id for s in scans]
        api_assets = {}
        if scan_ids:
            api_reports = db.query(ApiScanReport).filter(ApiScanReport.scan_id.in_(scan_ids)).all()
            for r in api_reports:
                asset_url = getattr(r, "asset_url", None)
                if not asset_url:
                    try:
                        report_obj = json.loads(r.report_json or "{}")
                        asset_url = report_obj.get("asset_url")
                    except Exception:
                        asset_url = None
                api_assets[r.scan_id] = asset_url

        scan_assets = {}
        if scan_ids:
            results = db.query(ScanResult).filter(ScanResult.scan_id.in_(scan_ids)).all()
            for r in results:
                if r.scan_id not in scan_assets:
                    scan_assets[r.scan_id] = {
                        "domain": getattr(r, "domain", None),
                        "subdomain": getattr(r, "subdomain", None),
                    }

        data = [
            {
                "scan_id": str(scan.id),
                "scan_name": scan.scan_name,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "created_at": scan.created_at,
                "created_by": getattr(scan, 'created_by', None),
                "asset_url": api_assets.get(scan.id),
                "asset_name": (
                    api_assets.get(scan.id)
                    if str(scan.scan_type or "").lower() == "api"
                    else (scan_assets.get(scan.id, {}) or {}).get("subdomain")
                    if str(scan.scan_type or "").lower() == "subdomain"
                    else (scan_assets.get(scan.id, {}) or {}).get("domain")
                ),
            }
            for scan in scans
        ]
        result = {'message':'Success','total':len(data), 'data': data}
        return result

    finally:
        db.close()


@router.get("/scan/{scan_id}")
def get_scan_by_id(
    scan_id: str,
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    db = SessionLocal()

    tenant_users = get_tenant_usernames(db, claims)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.created_by.in_(tenant_users)).first()
    assert scan, "Scan with id does not exist."

    result = {'message':'Success', 'data':scan}
    
    return result


@router.post("/{scan_id}/pause")
def pause_scan(scan_id: str):
    """Pause a running scan"""
    db = SessionLocal()
    try:
        # Convert scan_id string to UUID
        try:
            scan_uuid = UUID(scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid scan ID format: {scan_id}")
        
        scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan not found with ID: {scan_id}")
        
        if scan.status not in ["IN_PROGRESS"]:
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot pause scan with status: {scan.status}"
            )
        
        with scan_lock:
            # Use the UUID's string representation for consistency
            scan_id_str = str(scan_uuid)
            if scan_id_str in running_scans:
                running_scans[scan_id_str]["pause_event"].set()
                scan.status = "PAUSED"
                db.commit()
                return {"message": "Scan paused successfully", "scan_id": scan_id_str, "status": "PAUSED"}
            else:
                raise HTTPException(status_code=404, detail="Scan is not running")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error pausing scan {scan_id}: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error pausing scan: {str(e)}")
    finally:
        db.close()


@router.post("/{scan_id}/resume")
def resume_scan(scan_id: str):
    """Resume a paused scan"""
    db = SessionLocal()
    try:
        # Convert scan_id string to UUID
        try:
            scan_uuid = UUID(scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid scan ID format: {scan_id}")
        
        scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan not found with ID: {scan_id}")
        
        if scan.status != "PAUSED":
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot resume scan with status: {scan.status}"
            )
        
        with scan_lock:
            # Use the UUID's string representation for consistency
            scan_id_str = str(scan_uuid)
            if scan_id_str in running_scans:
                running_scans[scan_id_str]["pause_event"].clear()
                scan.status = "IN_PROGRESS"
                db.commit()
                return {"message": "Scan resumed successfully", "scan_id": scan_id_str, "status": "IN_PROGRESS"}
            else:
                raise HTTPException(status_code=404, detail="Scan is not running")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resuming scan {scan_id}: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error resuming scan: {str(e)}")
    finally:
        db.close()


@router.post("/{scan_id}/terminate")
def terminate_scan(scan_id: str):
    """Terminate a running scan"""
    db = SessionLocal()
    try:
        # Convert scan_id string to UUID
        try:
            scan_uuid = UUID(scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid scan ID format: {scan_id}")
        
        scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan not found with ID: {scan_id}")
        
        if scan.status not in ["IN_PROGRESS", "PAUSED"]:
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot terminate scan with status: {scan.status}"
            )
        
        with scan_lock:
            # Use the UUID's string representation for consistency
            scan_id_str = str(scan_uuid)
            if scan_id_str in running_scans:
                scan_info = running_scans[scan_id_str]
                # Mark as terminated
                scan_info["terminated"] = True
                
                # Update scan status
                scan.status = "TERMINATED"
                db.commit()
                
                return {"message": "Scan terminated successfully", "scan_id": scan_id_str, "status": "TERMINATED"}
            else:
                # Scan might have finished, just update status
                scan.status = "TERMINATED"
                db.commit()
                return {"message": "Scan marked as terminated", "scan_id": scan_id_str, "status": "TERMINATED"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error terminating scan {scan_id}: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error terminating scan: {str(e)}")
    finally:
        db.close()


@router.get("/{scan_id}/results")
def get_scan_results(
    scan_id: str,
    claims: Dict[str, Any] = Depends(get_token_claims),
):
    db = SessionLocal()

    try:
        tenant_users = get_tenant_usernames(db, claims)
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.created_by.in_(tenant_users)).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.scan_type == "api":
            api_report = db.query(ApiScanReport).filter(ApiScanReport.scan_id == scan.id).first()
            if not api_report:
                raise HTTPException(status_code=404, detail="API scan report not found")
            report = None
            # Prefer MinIO (DD-style)
            if getattr(api_report, "minio_object_name", None):
                try:
                    report = download_json(api_report.minio_object_name)
                except Exception:
                    report = None
            # Fallback to DB copy
            if report is None:
                try:
                    report = json.loads(api_report.report_json or "{}")
                except Exception:
                    report = {"raw": api_report.report_json}
            return {
                "scan_id": scan_id,
                "scan_name": scan.scan_name,
                "scan_type": scan.scan_type,
                "asset_url": getattr(api_report, "asset_url", None) or (report or {}).get("asset_url"),
                "report": report,
            }

        results = (
            db.query(ScanResult)
            .filter(ScanResult.scan_id == scan_id)
            .all()
        )

        base = {
            "scan_id": scan_id,
            "scan_name": scan.scan_name,
            "scan_type": scan.scan_type,
            "domain": results[0].domain if results else None,
            "total_subdomains": len(results),
            "subdomains": [r.subdomain for r in results],
        }

        # For subdomain scan, also return the detailed report (includes vulnerabilities)
        if scan.scan_type == "subdomain":
            object_name = f"{scan.scan_type}_{scan.scan_name}_{scan_id}.json"
            report_obj = None
            try:
                if object_exists(object_name):
                    wrapper = download_json(object_name) or {}
                    # wrapper shape: { ..., "result": { "report": {...} } }
                    if isinstance(wrapper.get("result"), dict):
                        report_obj = wrapper["result"].get("report") or wrapper["result"]
                    else:
                        report_obj = wrapper
            except Exception:
                report_obj = None

            if report_obj is not None:
                base["report"] = report_obj

        return base

    finally:
        db.close()
