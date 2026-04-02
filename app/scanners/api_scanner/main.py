from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.scanners.api_scanner.engine.auth_handler import build_auth_headers
from app.scanners.api_scanner.engine.oob_server import OOBTracker, get_callback_server, DEFAULT_OOB_BASE
from app.scanners.api_scanner.engine.rate_limiter import throttle
from app.scanners.api_scanner.parser.postman_parser import parse_postman
from app.scanners.api_scanner.parser.openapi_parser import parse_openapi
from app.scanners.api_scanner.reporter.report_generator import generate_report
from app.scanners.api_scanner.tests import reset_finding_counters, make_finding

# ── Per-endpoint test modules ─────────────────────────────────────────
from app.scanners.api_scanner.tests.auth_tests import run_auth_tests
from app.scanners.api_scanner.tests.bola_tests import run_bola_tests
from app.scanners.api_scanner.tests.injection_tests import run_nosql_injection_tests
from app.scanners.api_scanner.tests.sqli_tests import run_sqli_tests
from app.scanners.api_scanner.tests.command_injection_tests import run_command_injection_tests
from app.scanners.api_scanner.tests.ssrf_tests import run_ssrf_tests
from app.scanners.api_scanner.tests.ssti_tests import run_ssti_tests
from app.scanners.api_scanner.tests.xxe_tests import run_xxe_tests
from app.scanners.api_scanner.tests.mass_assignment_tests import run_mass_assignment_tests
from app.scanners.api_scanner.tests.bfla_tests import run_bfla_tests
from app.scanners.api_scanner.tests.info_disclosure_tests import run_info_disclosure_tests

# ── Global test modules (run once per scan) ───────────────────────────
from app.scanners.api_scanner.tests.headers_tests import run_headers_tests
from app.scanners.api_scanner.tests.cors_tests import run_cors_tests
from app.scanners.api_scanner.tests.rate_limit_tests import run_rate_limit_tests
from app.scanners.api_scanner.tests.jwt_tests import run_jwt_tests
from app.scanners.api_scanner.tests.bfla_tests import run_admin_path_tests
from app.scanners.api_scanner.tests.version_discovery_tests import run_version_discovery_tests

logger = logging.getLogger(__name__)


def _update_progress(
    db,  # type: Optional[Session]
    scan_id,  # type: Optional[str]
    progress,  # type: int
    phase,  # type: str
    findings_count=0,  # type: int
    endpoints_scanned=0,  # type: int
    endpoints_total=0,  # type: int
):
    """Update scan progress in DB. No-op if db/scan_id not provided."""
    if not db or not scan_id:
        return
    try:
        from app.database.models import Scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.progress = progress
            scan.current_phase = phase
            scan.findings_count = findings_count
            scan.endpoints_scanned = endpoints_scanned
            scan.endpoints_total = endpoints_total
            db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def _is_cancelled(db, scan_id):
    # type: (Optional[Session], Optional[str]) -> bool
    """Check if scan has been cancelled."""
    if not db or not scan_id:
        return False
    try:
        from app.database.models import Scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        return scan is not None and scan.status == "CANCELLED"
    except Exception:
        return False


# Per-endpoint checks — each receives (endpoint, base_url, auth_headers, query_params)
PER_ENDPOINT_CHECKS = [
    ("Authentication", run_auth_tests),
    ("BOLA", run_bola_tests),
    ("NoSQL Injection", run_nosql_injection_tests),
    ("SQL Injection", run_sqli_tests),
    ("Command Injection", run_command_injection_tests),
    ("SSRF", run_ssrf_tests),
    ("SSTI", run_ssti_tests),
    ("XXE", run_xxe_tests),
    ("Mass Assignment", run_mass_assignment_tests),
    ("BFLA / Method Tampering", run_bfla_tests),
    ("Information Disclosure", run_info_disclosure_tests),
]

# Checks that support two-token privilege escalation testing
TWOTOKEN_CHECKS = {"Authentication", "BOLA", "BFLA / Method Tampering"}

# Checks that accept oob_tracker parameter
OOB_CHECKS = {"SQL Injection", "Command Injection", "SSRF", "XXE"}

# Max endpoints to scan concurrently
MAX_CONCURRENT_ENDPOINTS = 5


def _deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate findings (same title + same endpoint)."""
    seen: set = set()
    unique: List[Dict[str, Any]] = []
    for f in findings:
        key = (f.get("title", ""), f.get("endpoint", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


async def _run_global_check(name: str, coro):
    """Run a single global check and return (name, findings)."""
    try:
        result = await coro
        logger.info("%s check: %d findings", name, len(result))
        return result
    except Exception as exc:
        logger.warning("%s check failed: %s", name, exc)
        return []


async def _scan_single_endpoint(
    endpoint: Dict[str, Any],
    idx: int,
    total: int,
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
    semaphore: asyncio.Semaphore,
    secondary_headers: Optional[Dict[str, str]] = None,
    secondary_qp: Optional[Dict[str, str]] = None,
    oob_tracker: Optional[OOBTracker] = None,
) -> List[Dict[str, Any]]:
    """Run all checks against a single endpoint (with concurrency limit)."""
    async with semaphore:
        ep_label = f"{endpoint.get('method', '?')} {endpoint.get('path', '?')}"
        logger.info("Scanning endpoint %d/%d: %s", idx, total, ep_label)

        await throttle()

        # Run all checks for this endpoint in parallel
        async def _run_check(check_name, check_fn):
            try:
                if check_name in TWOTOKEN_CHECKS and secondary_headers:
                    result = await check_fn(
                        endpoint, base_url, auth_headers, query_params,
                        secondary_headers, secondary_qp,
                    )
                elif check_name in OOB_CHECKS and oob_tracker:
                    result = await check_fn(
                        endpoint, base_url, auth_headers, query_params,
                        oob_tracker,
                    )
                else:
                    result = await check_fn(endpoint, base_url, auth_headers, query_params)
                if result:
                    logger.info("  [%s] %d findings on %s", check_name, len(result), ep_label)
                return result
            except Exception as exc:
                logger.warning("  [%s] failed on %s: %s", check_name, ep_label, exc)
                return []

        check_tasks = [_run_check(name, fn) for name, fn in PER_ENDPOINT_CHECKS]
        check_results = await asyncio.gather(*check_tasks)

        findings = []
        for result in check_results:
            findings.extend(result)
        return findings


async def run_api_scan(
    *,
    scan_name: str,
    asset_url: str,
    postman_collection: Optional[Dict[str, Any]] = None,
    endpoints: Optional[List[Dict[str, Any]]] = None,
    openapi_spec: Optional[Any] = None,
    auth_config: Optional[Dict[str, Any]] = None,
    secondary_auth_config: Optional[Dict[str, Any]] = None,
    scan_mode: str = "active",
    db: Optional[Session] = None,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run the full API APT scan.

    Accepts endpoints from: Postman collection, OpenAPI spec, or raw endpoint list.
    """
    started_at = datetime.utcnow()
    reset_finding_counters()

    # ── 1. Parse endpoints ────────────────────────────────────────────
    if endpoints is None:
        if openapi_spec:
            endpoints = parse_openapi(openapi_spec)
        elif postman_collection:
            endpoints = parse_postman(postman_collection)
        else:
            raise ValueError("Provide endpoints, postman_collection, or openapi_spec")

    if not endpoints:
        raise ValueError("No endpoints found to scan")

    _update_progress(db, scan_id, 5, "PARSING", 0, 0, len(endpoints))

    logger.info("API APT scan '%s' starting — %d endpoints, mode=%s", scan_name, len(endpoints), scan_mode)

    # ── 2. Build auth context ─────────────────────────────────────────
    auth_headers, query_params = build_auth_headers(auth_config)
    secondary_headers, secondary_qp = build_auth_headers(secondary_auth_config)

    # ── 2b. Initialize OOB tracker for blind vulnerability detection ───
    oob_tracker: Optional[OOBTracker] = None
    if DEFAULT_OOB_BASE:
        try:
            callback_server = await get_callback_server()
            oob_tracker = OOBTracker(
                scan_id=scan_id or "no-id",
                oob_base_url=DEFAULT_OOB_BASE,
                callback_server=callback_server,
            )
            logger.info("OOB detection enabled — callback URL: %s", DEFAULT_OOB_BASE)
        except Exception as exc:
            logger.warning("Failed to start OOB server: %s — blind tests disabled", exc)
    else:
        oob_tracker = OOBTracker(scan_id=scan_id or "no-id")

    findings: List[Dict[str, Any]] = []

    # ── 3. Global checks (run in parallel) ─────────────────────────────
    logger.info("Running global checks on %s", asset_url)

    global_tasks = [
        _run_global_check("Headers", run_headers_tests(asset_url, auth_headers, query_params)),
        _run_global_check("CORS", run_cors_tests(asset_url, auth_headers, query_params)),
        _run_global_check("Rate limit", run_rate_limit_tests(asset_url, auth_headers, query_params, endpoints)),
        _run_global_check("Admin/debug path", run_admin_path_tests(asset_url, auth_headers, query_params)),
        _run_global_check("Version discovery", run_version_discovery_tests(endpoints, asset_url, auth_headers, query_params)),
    ]
    global_results = await asyncio.gather(*global_tasks)
    for result in global_results:
        findings.extend(result)

    _update_progress(db, scan_id, 20, "GLOBAL_CHECKS", len(findings), 0, len(endpoints))

    # ── 4. JWT analysis (if Bearer token provided) ────────────────────
    if auth_config and auth_config.get("type") == "bearer" and auth_config.get("token"):
        token = auth_config["token"]
        test_url = asset_url
        for ep in endpoints:
            if ep.get("auth_required", True):
                from app.scanners.api_scanner.tests import build_url
                test_url = build_url(asset_url, ep.get("path", "/"), query_params)
                break
        try:
            jwt_findings = await run_jwt_tests(token, test_url, auth_headers)
            findings.extend(jwt_findings)
            logger.info("JWT analysis: %d findings", len(jwt_findings))
        except Exception as exc:
            logger.warning("JWT analysis failed: %s", exc)

    # ── 5. Per-endpoint checks (concurrent with semaphore) ─────────────
    total_endpoints = len(endpoints)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_ENDPOINTS)

    _update_progress(db, scan_id, 20, "ENDPOINT_SCANNING", len(findings), 0, total_endpoints)

    # Process endpoints in batches for progress reporting & cancellation
    scanned_count = 0
    for batch_start in range(0, total_endpoints, MAX_CONCURRENT_ENDPOINTS):
        # Check for cancellation before each batch
        if _is_cancelled(db, scan_id):
            logger.info("Scan '%s' cancelled by user at endpoint %d/%d", scan_name, scanned_count, total_endpoints)
            break

        batch_end = min(batch_start + MAX_CONCURRENT_ENDPOINTS, total_endpoints)
        batch = endpoints[batch_start:batch_end]

        endpoint_tasks = [
            _scan_single_endpoint(
                ep, batch_start + i + 1, total_endpoints, asset_url,
                auth_headers, query_params, semaphore,
                secondary_headers, secondary_qp, oob_tracker,
            )
            for i, ep in enumerate(batch)
        ]
        batch_results = await asyncio.gather(*endpoint_tasks)
        for result in batch_results:
            findings.extend(result)

        scanned_count += len(batch)
        # Progress: 20% to 90% proportional to endpoints scanned
        progress_pct = 20 + int(70 * scanned_count / total_endpoints)
        _update_progress(db, scan_id, progress_pct, "ENDPOINT_SCANNING", len(findings), scanned_count, total_endpoints)

    # ── 6. Check OOB interactions (blind vulnerability results) ────────
    if oob_tracker and oob_tracker.enabled:
        # Wait briefly for any delayed callbacks
        await asyncio.sleep(3)
        try:
            oob_interactions = await oob_tracker.check_for_interactions()
            if oob_interactions:
                logger.info("OOB: %d blind vulnerability callbacks received!", len(oob_interactions))
                for interaction in oob_interactions:
                    _owasp = {
                        "ssrf": "API7:2023",
                        "xxe": "Injection",
                        "cmdi": "Injection",
                        "sqli": "Injection",
                    }.get(interaction.test_type, "Injection")
                    _cvss = {
                        "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "cmdi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }.get(interaction.test_type, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                    _title = {
                        "ssrf": "Blind SSRF (OOB Callback)",
                        "xxe": "Blind XXE (OOB Callback)",
                        "cmdi": "Blind OS Command Injection (OOB Callback)",
                        "sqli": "Blind SQL Injection (OOB Callback)",
                    }.get(interaction.test_type, f"Blind {interaction.test_type} (OOB Callback)")
                    findings.append(make_finding(
                        owasp_category=_owasp,
                        title=_title,
                        cvss_vector=_cvss,
                        endpoint=interaction.endpoint or "unknown",
                        description=(
                            f"The target made an outbound HTTP request to the OOB callback server, "
                            f"confirming a blind {interaction.test_type.upper()} vulnerability. "
                            f"Callback from {interaction.source_ip} at {interaction.timestamp}."
                        ),
                        evidence={
                            "oob_callback": {
                                "token": interaction.token,
                                "source_ip": interaction.source_ip,
                                "timestamp": interaction.timestamp,
                                "method": interaction.method,
                                "path": interaction.path,
                            },
                        },
                        impact="Confirmed blind vulnerability — the server can be forced to make outbound requests or execute commands.",
                        remediation="Validate and sanitize all user input. Block outbound network connections from the application server where not required.",
                    ))
            else:
                logger.info("OOB: no blind vulnerability callbacks received (%d tokens sent)", oob_tracker.get_token_count())
        except Exception as exc:
            logger.warning("OOB interaction check failed: %s", exc)

    # ── 7. Deduplicate ────────────────────────────────────────────────
    findings = _deduplicate(findings)

    _update_progress(db, scan_id, 95, "REPORT_GENERATION", len(findings), total_endpoints, total_endpoints)

    completed_at = datetime.utcnow()
    duration = (completed_at - started_at).total_seconds()
    logger.info(
        "API APT scan '%s' complete — %d findings in %.1fs",
        scan_name, len(findings), duration,
    )

    # ── 8. Generate report ────────────────────────────────────────────
    _update_progress(db, scan_id, 100, "COMPLETED", len(findings), total_endpoints, total_endpoints)

    return generate_report(
        scan_name=scan_name,
        base_url=asset_url,
        scan_mode=scan_mode,
        endpoints=endpoints,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
    )
