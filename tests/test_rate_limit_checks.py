"""Tests for rate_limit_tests — rate limiting detection."""
import re
import pytest
import responses

from app.scanners.api_scanner.tests import reset_finding_counters
from app.scanners.api_scanner.tests.rate_limit_tests import run_rate_limit_tests, RAPID_REQUEST_COUNT


BASE = "https://api.test"
# Catch-all for any POST to base domain (auth endpoint probes)
ANY_POST = re.compile(r"https://api\.test/.*")


@pytest.fixture(autouse=True)
def _reset():
    reset_finding_counters()
    yield
    reset_finding_counters()


@pytest.mark.asyncio
class TestRateLimitChecks:
    @responses.activate
    async def test_no_rate_limiting(self):
        """No 429 and no rate headers after rapid requests = finding."""
        for _ in range(RAPID_REQUEST_COUNT):
            responses.add(responses.GET, f"{BASE}/items", json={}, status=200)
        # Auth endpoint probes — all 404
        for _ in range(20):
            responses.add(responses.POST, ANY_POST, status=404)

        endpoints = [{"method": "GET", "path": "/items", "name": "listItems"}]
        findings = await run_rate_limit_tests(BASE, {}, {}, endpoints)
        titles = [f["title"] for f in findings]
        assert "No Rate Limiting Detected" in titles

    @responses.activate
    async def test_429_returned_no_finding(self):
        """Getting 429 response = rate limiting works, no finding."""
        for i in range(RAPID_REQUEST_COUNT):
            if i < 10:
                responses.add(responses.GET, f"{BASE}/items", json={}, status=200)
            else:
                responses.add(responses.GET, f"{BASE}/items", status=429)

        endpoints = [{"method": "GET", "path": "/items", "name": "listItems"}]
        findings = await run_rate_limit_tests(BASE, {}, {}, endpoints)
        titles = [f["title"] for f in findings]
        assert "No Rate Limiting Detected" not in titles

    @responses.activate
    async def test_rate_headers_present_not_enforced(self):
        """Rate limit headers without 429 = headers present but not enforced."""
        for _ in range(RAPID_REQUEST_COUNT):
            responses.add(
                responses.GET, f"{BASE}/items", json={}, status=200,
                headers={"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "90"},
            )
        for _ in range(20):
            responses.add(responses.POST, ANY_POST, status=404)

        endpoints = [{"method": "GET", "path": "/items", "name": "listItems"}]
        findings = await run_rate_limit_tests(BASE, {}, {}, endpoints)
        titles = [f["title"] for f in findings]
        assert "Rate Limit Headers Present But Not Enforced" in titles

    @responses.activate
    async def test_brute_force_on_auth_endpoint(self):
        """Auth endpoint allowing 15+ failed logins = no brute force protection."""
        # Regular rate limit test
        for _ in range(RAPID_REQUEST_COUNT):
            responses.add(responses.GET, f"{BASE}/items", json={}, status=200)
        # /login exists and responds 401 (initial probe + 15 brute force attempts)
        for _ in range(20):
            responses.add(responses.POST, f"{BASE}/login", status=401)
        # Other auth endpoints — 404
        for _ in range(20):
            responses.add(responses.POST, ANY_POST, status=404)

        endpoints = [{"method": "GET", "path": "/items"}]
        findings = await run_rate_limit_tests(BASE, {}, {}, endpoints)
        titles = [f["title"] for f in findings]
        assert any("Brute Force" in t for t in titles)

    @responses.activate
    async def test_empty_endpoints_uses_root(self):
        """Empty endpoint list falls back to /."""
        for _ in range(RAPID_REQUEST_COUNT):
            responses.add(responses.GET, re.compile(r"https://api\.test/"), json={}, status=200)
        for _ in range(20):
            responses.add(responses.POST, ANY_POST, status=404)

        findings = await run_rate_limit_tests(BASE, {}, {}, [])
        # Should still run without error
        assert isinstance(findings, list)
