"""
End-to-end scanner validation against the intentionally vulnerable test API.

Starts a local FastAPI server, runs the full API APT scanner, and asserts
that known vulnerabilities are actually detected.
"""
from __future__ import annotations

import asyncio
import multiprocessing
import time

import pytest
import uvicorn

from app.scanners.api_scanner.main import run_api_scan


VULN_HOST = "127.0.0.1"
VULN_PORT = 9876
VULN_URL = f"http://{VULN_HOST}:{VULN_PORT}"

# Manually defined endpoints matching the vulnerable API
ENDPOINTS = [
    {
        "method": "GET",
        "path": "/users",
        "parameters": [
            {"name": "search", "in": "query", "type": "string"},
        ],
    },
    {
        "method": "GET",
        "path": "/users/{id}",
        "parameters": [
            {"name": "id", "in": "path", "type": "integer"},
        ],
    },
    {
        "method": "POST",
        "path": "/users",
        "parameters": [],
        "body": {"username": "testuser", "email": "test@test.com"},
    },
    {
        "method": "GET",
        "path": "/ping",
        "parameters": [
            {"name": "host", "in": "query", "type": "string"},
        ],
    },
    {
        "method": "GET",
        "path": "/fetch",
        "parameters": [
            {"name": "url", "in": "query", "type": "string"},
        ],
    },
    {
        "method": "POST",
        "path": "/render",
        "parameters": [],
        "body": {"template": "Hello {{name}}", "name": "World"},
    },
    {
        "method": "POST",
        "path": "/upload",
        "parameters": [],
        "body": {"data": "<root>test</root>"},
    },
    {
        "method": "POST",
        "path": "/login",
        "parameters": [],
        "body": {"username": "admin", "password": "test"},
        "auth_required": False,
    },
    {
        "method": "GET",
        "path": "/admin",
        "parameters": [],
    },
    {
        "method": "GET",
        "path": "/debug",
        "parameters": [],
    },
]


def _run_vuln_server():
    """Run the vulnerable API in a separate process."""
    from tests.vulnerable_api import app
    uvicorn.run(app, host=VULN_HOST, port=VULN_PORT, log_level="error")


@pytest.fixture(scope="module")
def vuln_server():
    """Start the vulnerable API server for the duration of this test module."""
    proc = multiprocessing.Process(target=_run_vuln_server, daemon=True)
    proc.start()

    # Wait for server to be ready
    import requests
    for _ in range(30):
        try:
            r = requests.get(f"{VULN_URL}/users", timeout=1)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.5)
    else:
        proc.terminate()
        pytest.fail("Vulnerable API server did not start in time")

    yield proc

    proc.terminate()
    proc.join(timeout=5)


@pytest.mark.asyncio
@pytest.mark.e2e
class TestEndToEndScan:

    async def test_full_scan_finds_vulnerabilities(self, vuln_server):
        """Run the full scanner and verify it catches the planted vulns."""
        report = await run_api_scan(
            scan_name="E2E Validation",
            asset_url=VULN_URL,
            endpoints=ENDPOINTS,
            auth_config=None,
            scan_mode="active",
        )

        assert report is not None
        assert "findings" in report

        findings = report["findings"]
        titles = [f["title"] for f in findings]

        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE — {len(findings)} findings")
        print(f"{'='*60}")
        for i, f in enumerate(findings, 1):
            severity = f.get("severity", "?")
            print(f"  {i:2d}. [{severity:8s}] {f['title']}")
        print(f"{'='*60}\n")

        # ── Assert critical vulns were found ──────────────────────────
        # At minimum, the scanner MUST find these:

        # 1. CORS misconfiguration (origin reflection)
        cors_found = any("CORS" in t for t in titles)
        assert cors_found, f"CORS vuln not detected. Findings: {titles}"

        # 2. Missing security headers
        header_found = any("header" in t.lower() or "Header" in t for t in titles)
        assert header_found, f"Missing headers not detected. Findings: {titles}"

        # 3. SQL injection (the /users?search= endpoint is trivially injectable)
        sqli_found = any("SQL" in t for t in titles)
        assert sqli_found, f"SQL injection not detected. Findings: {titles}"

        # 4. Command injection (the /ping?host= endpoint)
        cmdi_found = any("Command" in t for t in titles)
        assert cmdi_found, f"Command injection not detected. Findings: {titles}"

        # 5. Server version disclosure
        server_found = any("Server" in t or "Version" in t or "Powered" in t for t in titles)
        assert server_found, f"Server version disclosure not detected. Findings: {titles}"

        # Total findings should be meaningful (not 0, not 500)
        assert len(findings) >= 5, f"Too few findings: {len(findings)}"
        assert len(findings) <= 100, f"Suspiciously many findings ({len(findings)}) — likely false positives"

    async def test_scan_report_structure(self, vuln_server):
        """Verify the report has the expected structure."""
        report = await run_api_scan(
            scan_name="Structure Check",
            asset_url=VULN_URL,
            endpoints=ENDPOINTS[:3],  # Just a few endpoints
            auth_config=None,
            scan_mode="active",
        )

        # Top-level report keys
        assert "scan_name" in report
        assert "findings" in report
        assert "severity_counts" in report
        assert "total_endpoints" in report
        assert "total_findings" in report
        assert "base_url" in report
        assert "scan_mode" in report

        # Severity counts
        sc = report["severity_counts"]
        assert "CRITICAL" in sc
        assert "HIGH" in sc
        assert "MEDIUM" in sc
        assert "LOW" in sc

        # total_findings matches actual findings length
        assert report["total_findings"] == len(report["findings"])

        # Each finding should have required fields
        for f in report["findings"]:
            assert "finding_id" in f
            assert "title" in f
            assert "severity" in f
            assert "endpoint" in f
            assert "description" in f
