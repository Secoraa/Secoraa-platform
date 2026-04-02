"""Tests for auth_tests — authentication bypass detection.

This is the most critical test file — covers the false positive bug
where Bearer bypass was tested on API key auth endpoints.
"""
import pytest
import responses

from app.scanners.api_scanner.tests import reset_finding_counters
from app.scanners.api_scanner.tests.auth_tests import (
    run_auth_tests,
    _detect_auth_type,
)


BASE = "https://api.test"


@pytest.fixture(autouse=True)
def _reset():
    reset_finding_counters()
    yield
    reset_finding_counters()


class TestDetectAuthType:
    def test_bearer(self):
        assert _detect_auth_type({"Authorization": "Bearer token123"}, {}) == "bearer"

    def test_basic(self):
        assert _detect_auth_type({"Authorization": "Basic dXNlcjpwYXNz"}, {}) == "basic"

    def test_api_key_header(self):
        assert _detect_auth_type({"X-API-Key": "abc123"}, {}) == "api_key"

    def test_api_key_query(self):
        assert _detect_auth_type({}, {"api_key": "abc123"}) == "api_key_query"

    def test_no_auth(self):
        assert _detect_auth_type({}, {}) == "none"

    def test_custom_header_detected_as_api_key(self):
        assert _detect_auth_type({"api_key": "special-key"}, {}) == "api_key"


@pytest.mark.asyncio
class TestAuthChecks:
    @responses.activate
    async def test_missing_auth_detected(self):
        """Endpoint returning same data with/without auth = missing auth."""
        body = '{"users": [{"id": 1}]}'
        # Authenticated request
        responses.add(responses.GET, f"{BASE}/users", body=body, status=200)
        # Unauthenticated request — same response
        responses.add(responses.GET, f"{BASE}/users", body=body, status=200)

        findings = await run_auth_tests(
            {"method": "GET", "path": "/users", "name": "listUsers"},
            BASE, {"X-API-Key": "valid-key"}, {},
        )
        titles = [f["title"] for f in findings]
        assert "Missing Authentication" in titles

    @responses.activate
    async def test_auth_enforced_no_finding(self):
        """Endpoint returning 401 without auth = properly protected."""
        responses.add(responses.GET, f"{BASE}/users", json={"users": []}, status=200)
        responses.add(responses.GET, f"{BASE}/users", status=401)
        # API key bypass test (wrong key)
        responses.add(responses.GET, f"{BASE}/users", status=403)
        # API key bypass test (empty key)
        responses.add(responses.GET, f"{BASE}/users", status=403)

        findings = await run_auth_tests(
            {"method": "GET", "path": "/users", "name": "listUsers"},
            BASE, {"X-API-Key": "valid-key"}, {},
        )
        titles = [f["title"] for f in findings]
        assert "Missing Authentication" not in titles

    @responses.activate
    async def test_bearer_bypass_empty_token(self):
        """Empty Bearer token returning same data = bypass detected."""
        body = '{"secret": "data"}'
        # Baseline (authenticated)
        responses.add(responses.GET, f"{BASE}/data", body=body, status=200)
        # No-auth request — rejected
        responses.add(responses.GET, f"{BASE}/data", status=401)
        # Empty Bearer — same as baseline (bypass!)
        responses.add(responses.GET, f"{BASE}/data", body=body, status=200)
        # Invalid Bearer — rejected
        responses.add(responses.GET, f"{BASE}/data", status=401)

        findings = await run_auth_tests(
            {"method": "GET", "path": "/data", "name": "getData"},
            BASE, {"Authorization": "Bearer valid-jwt"}, {},
        )
        titles = [f["title"] for f in findings]
        assert "Empty Bearer Token Accepted" in titles

    @responses.activate
    async def test_api_key_bypass_wrong_key(self):
        """Wrong API key returning same data = bypass detected."""
        body = '{"items": [1, 2, 3]}'
        # Baseline
        responses.add(responses.GET, f"{BASE}/items", body=body, status=200)
        # No-auth — rejected
        responses.add(responses.GET, f"{BASE}/items", status=401)
        # Wrong API key — same as baseline (bypass!)
        responses.add(responses.GET, f"{BASE}/items", body=body, status=200)
        # Empty API key
        responses.add(responses.GET, f"{BASE}/items", status=403)

        findings = await run_auth_tests(
            {"method": "GET", "path": "/items", "name": "listItems"},
            BASE, {"X-API-Key": "valid-key"}, {},
        )
        titles = [f["title"] for f in findings]
        assert "Invalid API Key Accepted" in titles

    @responses.activate
    async def test_api_key_no_bearer_test(self):
        """When API key auth is used, Bearer bypass should NOT be tested.
        This was the bug that caused 30 false CRITICAL findings.
        """
        body = '{"items": [1, 2, 3]}'
        # Baseline
        responses.add(responses.GET, f"{BASE}/items", body=body, status=200)
        # No-auth
        responses.add(responses.GET, f"{BASE}/items", status=401)
        # Wrong API key — rejected
        responses.add(responses.GET, f"{BASE}/items", status=403)
        # Empty API key — rejected
        responses.add(responses.GET, f"{BASE}/items", status=403)

        findings = await run_auth_tests(
            {"method": "GET", "path": "/items", "name": "listItems"},
            BASE, {"api_key": "special-key"}, {},
        )
        titles = [f["title"] for f in findings]
        # Should NOT have Bearer-related findings when using API key auth
        assert "Empty Bearer Token Accepted" not in titles
        assert "Invalid Token Accepted" not in titles

    @responses.activate
    async def test_partial_auth_bypass(self):
        """Endpoint returns 200 with less data without auth = partial bypass."""
        # Authenticated — full response
        responses.add(
            responses.GET, f"{BASE}/profile", status=200,
            body='{"id": 1, "name": "admin", "email": "a@b.com", "ssn": "123-45-6789"}',
        )
        # Unauthenticated — partial response (different body, same status 200)
        responses.add(
            responses.GET, f"{BASE}/profile", status=200,
            body='{"id": 1, "name": "admin"}',
        )
        # API key bypass (wrong key) — rejected
        responses.add(responses.GET, f"{BASE}/profile", status=403)
        # API key bypass (empty key) — rejected
        responses.add(responses.GET, f"{BASE}/profile", status=403)

        findings = await run_auth_tests(
            {"method": "GET", "path": "/profile", "name": "getProfile"},
            BASE, {"X-API-Key": "valid"}, {},
        )
        titles = [f["title"] for f in findings]
        assert "Partial Authentication Bypass" in titles

    @responses.activate
    async def test_sensitive_param_in_url(self):
        """Endpoint with api_key query parameter should be flagged."""
        responses.add(responses.GET, f"{BASE}/data", status=200, body="ok")
        responses.add(responses.GET, f"{BASE}/data", status=401)

        findings = await run_auth_tests(
            {
                "method": "GET", "path": "/data", "name": "getData",
                "parameters": [{"name": "api_key", "in": "query"}],
            },
            BASE, {}, {},
        )
        titles = [f["title"] for f in findings]
        assert "Sensitive Credential in URL Query String" in titles

    @responses.activate
    async def test_no_auth_no_baseline(self):
        """No auth headers provided — low confidence finding."""
        responses.add(
            responses.GET, f"{BASE}/public", status=200,
            body='{"data": "public info here"}',
        )

        findings = await run_auth_tests(
            {"method": "GET", "path": "/public", "name": "getPublic"},
            BASE, {}, {},
        )
        # Should flag with LOW confidence
        low_conf = [f for f in findings if f.get("confidence") == "LOW"]
        assert len(low_conf) >= 1
