"""Tests for headers_tests — security header detection."""
import pytest
import responses

from app.scanners.api_scanner.tests import reset_finding_counters
from app.scanners.api_scanner.tests.headers_tests import run_headers_tests


BASE = "https://api.test"


@pytest.fixture(autouse=True)
def _reset():
    reset_finding_counters()
    yield
    reset_finding_counters()


@pytest.mark.asyncio
class TestHeadersChecks:
    @responses.activate
    async def test_all_headers_missing(self):
        """Response with no security headers should flag all missing headers."""
        responses.add(responses.GET, BASE, json={}, status=200, headers={})
        findings = await run_headers_tests(BASE, {}, {})
        titles = [f["title"] for f in findings]
        assert any("Strict-Transport-Security" in t for t in titles)
        assert any("X-Content-Type-Options" in t for t in titles)
        assert any("X-Frame-Options" in t for t in titles)
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("Cache-Control" in t for t in titles)
        assert any("Referrer-Policy" in t for t in titles)

    @responses.activate
    async def test_all_headers_present(self):
        """Response with all security headers should produce no missing header findings."""
        good_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Cache-Control": "no-store",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        responses.add(responses.GET, BASE, json={}, status=200, headers=good_headers)
        findings = await run_headers_tests(BASE, {}, {})
        titles = [f["title"] for f in findings]
        assert not any("Missing Security Header" in t for t in titles)

    @responses.activate
    async def test_server_version_disclosure(self):
        """Server header with version number should be flagged."""
        responses.add(
            responses.GET, BASE, json={}, status=200,
            headers={"Server": "Apache/2.4.51"},
        )
        findings = await run_headers_tests(BASE, {}, {})
        titles = [f["title"] for f in findings]
        assert "Server Version Disclosure" in titles

    @responses.activate
    async def test_server_no_version_no_finding(self):
        """Server header without version number should NOT be flagged."""
        responses.add(
            responses.GET, BASE, json={}, status=200,
            headers={"Server": "nginx"},
        )
        findings = await run_headers_tests(BASE, {}, {})
        titles = [f["title"] for f in findings]
        assert "Server Version Disclosure" not in titles

    @responses.activate
    async def test_x_powered_by_disclosure(self):
        """X-Powered-By header should be flagged."""
        responses.add(
            responses.GET, BASE, json={}, status=200,
            headers={"X-Powered-By": "Express"},
        )
        findings = await run_headers_tests(BASE, {}, {})
        titles = [f["title"] for f in findings]
        assert "Technology Disclosure via X-Powered-By" in titles

    @responses.activate
    async def test_null_response_no_crash(self):
        """Connection failure should return empty findings without crashing."""
        import requests as req_lib
        responses.add(
            responses.GET, BASE,
            body=req_lib.exceptions.ConnectionError("down"),
        )
        findings = await run_headers_tests(BASE, {}, {})
        assert findings == []

    @responses.activate
    async def test_auth_headers_forwarded(self):
        """Auth headers should be included in the request."""
        responses.add(responses.GET, BASE, json={}, status=200)
        await run_headers_tests(BASE, {"X-API-Key": "test123"}, {})
        assert "X-API-Key" in responses.calls[0].request.headers
