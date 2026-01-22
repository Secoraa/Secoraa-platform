from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.scanners.api_scanner.engine.rate_limiter import throttle
from app.scanners.api_scanner.parser.postman_parser import parse_postman
from app.scanners.api_scanner.reporter.report_generator import generate_report
from app.scanners.api_scanner.tests.auth_tests import test_missing_auth
from app.scanners.api_scanner.tests.bola_tests import test_bola
from app.scanners.api_scanner.tests.injection_tests import test_nosql_injection


async def run_api_scan(
    *,
    scan_name: str,
    asset_url: str,
    postman_collection: Optional[Dict[str, Any]] = None,
    endpoints: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Run a basic API scan from a Postman collection JSON.
    """
    if endpoints is None:
        if not postman_collection:
            raise ValueError("Either endpoints or postman_collection must be provided")
        endpoints = parse_postman(postman_collection)

    findings: List[Dict[str, Any]] = []
    tests = [test_missing_auth, test_bola, test_nosql_injection]

    for endpoint in endpoints:
        await throttle()
        for test in tests:
            result = await test(endpoint, asset_url)
            if result:
                findings.append(result)

    return generate_report(scan_name, endpoints, findings)

