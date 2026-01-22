from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from app.api.auth import get_token_claims
from app.endpoints.request_body import SubdomainScanRequest
from app.scanners.subdomain_scanner.scan import run_subdomain_scan
from app.scanners.subdomain_scanner.reporter.exporter import export_json, export_pdf

scan_router = APIRouter(
    prefix="/scan/subdomain",
    tags=["Subdomain Scanner"],
    dependencies=[Depends(get_token_claims)],
)


@scan_router.post("/run")
async def run_scan(
    payload: SubdomainScanRequest,
    background_tasks: BackgroundTasks,
):
    try:
        report = run_subdomain_scan(payload.domain, payload.subdomains)

        if payload.export_json:
            background_tasks.add_task(export_json, report)

        if payload.export_pdf:
            background_tasks.add_task(export_pdf, report)

        return {
            "status": "completed",
            "data": report
        }

    except Exception as ex:
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(ex)}"
        )
