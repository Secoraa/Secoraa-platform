"""Tests for bola_tests — BOLA/IDOR detection."""
import re
import pytest
import responses

from app.scanners.api_scanner.tests import reset_finding_counters
from app.scanners.api_scanner.tests.bola_tests import run_bola_tests


BASE = "https://api.test"


@pytest.fixture(autouse=True)
def _reset():
    reset_finding_counters()
    yield
    reset_finding_counters()


@pytest.mark.asyncio
class TestBolaChecks:
    @responses.activate
    async def test_no_id_param_skipped(self):
        """Endpoints without ID path params should produce no findings."""
        findings = await run_bola_tests(
            {"method": "GET", "path": "/items", "name": "listItems"},
            BASE, {"X-API-Key": "key"}, {},
        )
        assert findings == []

    @responses.activate
    async def test_unauthenticated_bola(self):
        """Same response with and without auth on ID endpoint = BOLA."""
        body = '{"id": 1, "name": "User One", "email": "user1@test.com"}'
        url_pattern = re.compile(r"https://api\.test/users/1")
        # Baseline (authenticated, id=1)
        responses.add(responses.GET, url_pattern, body=body, status=200)
        # Unauthenticated — same response (BOLA!)
        responses.add(responses.GET, url_pattern, body=body, status=200)

        findings = await run_bola_tests(
            {"method": "GET", "path": "/users/{userId}", "name": "getUser"},
            BASE, {"X-API-Key": "key"}, {},
        )
        titles = [f["title"] for f in findings]
        assert any("Unauthenticated Access" in t for t in titles)

    @responses.activate
    async def test_two_token_bola(self):
        """Two different users seeing same resource = cross-user BOLA."""
        body = '{"id": 1, "name": "Private Data", "secret": "abc"}'
        url_pattern = re.compile(r"https://api\.test/accounts/1")
        # Baseline (user A)
        responses.add(responses.GET, url_pattern, body=body, status=200)
        # Unauthenticated — rejected (no unauth BOLA)
        responses.add(responses.GET, url_pattern, status=401)
        # Secondary user (user B) — same response as user A
        # NOTE: registered BEFORE enum responses because BOLA code runs
        # two-token check (step 4) before enumeration (step 5)
        responses.add(responses.GET, url_pattern, body=body, status=200)
        # ID enumeration — 5 test IDs (2,100,0,-1,999999) all rejected
        enum_pattern = re.compile(r"https://api\.test/accounts/.*")
        for _ in range(5):
            responses.add(responses.GET, enum_pattern, status=401)

        findings = await run_bola_tests(
            {"method": "GET", "path": "/accounts/{accountId}", "name": "getAccount"},
            BASE, {"Authorization": "Bearer userA-token"}, {},
            secondary_auth_headers={"Authorization": "Bearer userB-token"},
        )
        titles = [f["title"] for f in findings]
        assert any("Two-Token" in t for t in titles)

    @responses.activate
    async def test_proper_auth_required(self):
        """401 without auth = properly protected, no BOLA finding."""
        body = '{"id": 1, "name": "User One"}'
        url_pattern = re.compile(r"https://api\.test/users/1")
        # Baseline
        responses.add(responses.GET, url_pattern, body=body, status=200)
        # Unauthenticated — rejected
        responses.add(responses.GET, url_pattern, status=401)
        # ID enumeration tests — all rejected (catch-all pattern)
        enum_pattern = re.compile(r"https://api\.test/users/.*")
        for _ in range(6):
            responses.add(responses.GET, enum_pattern, status=401)

        findings = await run_bola_tests(
            {"method": "GET", "path": "/users/{userId}", "name": "getUser"},
            BASE, {"X-API-Key": "key"}, {},
        )
        titles = [f["title"] for f in findings]
        assert not any("BOLA" in t or "IDOR" in t for t in titles)

    @responses.activate
    async def test_id_enumeration_detected(self):
        """Different ID returning data with similar structure = IDOR enumeration."""
        url1 = re.compile(r"https://api\.test/orders/1")
        # Baseline (id=1)
        responses.add(responses.GET, url1, body='{"id": 1, "total": 50}', status=200)
        # Unauthenticated baseline — rejected (no unauth BOLA)
        responses.add(responses.GET, url1, status=401)
        # ID=2 — returns data (IDOR!)
        enum_pattern = re.compile(r"https://api\.test/orders/.*")
        responses.add(responses.GET, enum_pattern, body='{"id": 2, "total": 75}', status=200)

        findings = await run_bola_tests(
            {"method": "GET", "path": "/orders/{orderId}", "name": "getOrder"},
            BASE, {"X-API-Key": "key"}, {},
        )
        titles = [f["title"] for f in findings]
        assert any("IDOR" in t or "Enumeration" in t for t in titles)

    @responses.activate
    async def test_enumeration_all_rejected_no_finding(self):
        """All enumeration attempts returning 401/403 = no IDOR finding."""
        url1 = re.compile(r"https://api\.test/items/1")
        responses.add(responses.GET, url1, body='{"id": 1}', status=200)
        responses.add(responses.GET, url1, status=401)
        # All enumeration — rejected
        enum_pattern = re.compile(r"https://api\.test/items/.*")
        for _ in range(6):
            responses.add(responses.GET, enum_pattern, status=403)

        findings = await run_bola_tests(
            {"method": "GET", "path": "/items/{itemId}", "name": "getItem"},
            BASE, {"X-API-Key": "key"}, {},
        )
        titles = [f["title"] for f in findings]
        assert not any("IDOR" in t for t in titles)

    @responses.activate
    async def test_baseline_failure_skips(self):
        """If baseline request fails, BOLA tests should be skipped."""
        import requests as req_lib
        responses.add(
            responses.GET, f"{BASE}/items/1",
            body=req_lib.exceptions.ConnectionError("down"),
        )
        findings = await run_bola_tests(
            {"method": "GET", "path": "/items/{itemId}", "name": "getItem"},
            BASE, {"X-API-Key": "key"}, {},
        )
        assert findings == []

    @responses.activate
    async def test_no_auth_headers_skips_unauth_test(self):
        """No auth headers provided = unauth BOLA test is skipped."""
        url_pattern = re.compile(r"https://api\.test/users/.*")
        responses.add(responses.GET, url_pattern, body='{"id": 1}', status=200)
        # Enumeration
        for _ in range(6):
            responses.add(responses.GET, url_pattern, status=404)

        findings = await run_bola_tests(
            {"method": "GET", "path": "/users/{userId}", "name": "getUser"},
            BASE, {}, {},
        )
        # No unauth BOLA finding since there's no auth to compare against
        titles = [f["title"] for f in findings]
        assert not any("Unauthenticated Access" in t for t in titles)
