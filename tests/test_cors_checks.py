"""Tests for cors_tests — CORS misconfiguration detection."""
import pytest
import responses

from app.scanners.api_scanner.tests import reset_finding_counters
from app.scanners.api_scanner.tests.cors_tests import run_cors_tests


BASE = "https://api.test"


@pytest.fixture(autouse=True)
def _reset():
    reset_finding_counters()
    yield
    reset_finding_counters()


@pytest.mark.asyncio
class TestCorsChecks:
    @responses.activate
    async def test_wildcard_cors(self):
        """Wildcard ACAO should be flagged."""
        responses.add(
            responses.GET, BASE, json={}, status=200,
            headers={"Access-Control-Allow-Origin": "*"},
        )
        # Null origin check
        responses.add(responses.GET, BASE, json={}, status=200, headers={})
        findings = await run_cors_tests(BASE, {}, {})
        titles = [f["title"] for f in findings]
        assert "CORS Allows Any Origin (Wildcard)" in titles

    @responses.activate
    async def test_wildcard_with_credentials(self):
        """Wildcard ACAO + credentials = most dangerous combo."""
        responses.add(
            responses.GET, BASE, json={}, status=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        responses.add(responses.GET, BASE, json={}, status=200, headers={})
        findings = await run_cors_tests(BASE, {}, {})
        titles = [f["title"] for f in findings]
        assert "CORS Wildcard with Credentials" in titles

    @responses.activate
    async def test_origin_reflection(self):
        """Reflecting arbitrary origin should be flagged."""
        def _reflect_origin(request):
            origin = request.headers.get("Origin", "")
            return (200, {"Access-Control-Allow-Origin": origin}, "{}")

        responses.add_callback(responses.GET, BASE, callback=_reflect_origin)
        responses.add(responses.GET, BASE, json={}, status=200, headers={})
        findings = await run_cors_tests(BASE, {}, {})
        titles = [f["title"] for f in findings]
        assert "CORS Reflects Arbitrary Origin" in titles

    @responses.activate
    async def test_null_origin_allowed(self):
        """Allowing null origin should be flagged."""
        # First request (evil origin) — no CORS issue
        responses.add(responses.GET, BASE, json={}, status=200, headers={})
        # Second request (null origin) — reflects null
        responses.add(
            responses.GET, BASE, json={}, status=200,
            headers={"Access-Control-Allow-Origin": "null"},
        )
        findings = await run_cors_tests(BASE, {}, {})
        titles = [f["title"] for f in findings]
        assert "CORS Allows Null Origin" in titles

    @responses.activate
    async def test_no_cors_headers_no_findings(self):
        """No CORS headers = no CORS findings."""
        responses.add(responses.GET, BASE, json={}, status=200, headers={})
        responses.add(responses.GET, BASE, json={}, status=200, headers={})
        findings = await run_cors_tests(BASE, {}, {})
        assert findings == []

    @responses.activate
    async def test_proper_cors_no_findings(self):
        """Specific allowed origin (not evil) should not trigger."""
        responses.add(
            responses.GET, BASE, json={}, status=200,
            headers={"Access-Control-Allow-Origin": "https://app.secoraa.com"},
        )
        responses.add(responses.GET, BASE, json={}, status=200, headers={})
        findings = await run_cors_tests(BASE, {}, {})
        assert findings == []
