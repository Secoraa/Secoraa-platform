"""Tests for scanner __init__ utilities — make_finding, build_url, ID counters."""
import pytest

from app.scanners.api_scanner.tests import (
    reset_finding_counters,
    make_finding,
    build_url,
    _next_id,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_finding_counters()
    yield
    reset_finding_counters()


class TestNextId:
    def test_sequential(self):
        assert _next_id("AUTH") == "AUTH-001"
        assert _next_id("AUTH") == "AUTH-002"
        assert _next_id("AUTH") == "AUTH-003"

    def test_separate_prefixes(self):
        assert _next_id("AUTH") == "AUTH-001"
        assert _next_id("CORS") == "CORS-001"
        assert _next_id("AUTH") == "AUTH-002"

    def test_reset_clears(self):
        _next_id("TEST")
        _next_id("TEST")
        reset_finding_counters()
        assert _next_id("TEST") == "TEST-001"


class TestBuildUrl:
    def test_simple(self):
        assert build_url("https://api.test", "/users") == "https://api.test/users"

    def test_trailing_slash(self):
        url = build_url("https://api.test/", "/users")
        assert url == "https://api.test/users"

    def test_query_params(self):
        url = build_url("https://api.test", "/items", {"page": "1", "limit": "10"})
        assert "page=1" in url
        assert "limit=10" in url
        assert "?" in url

    def test_no_query_params(self):
        url = build_url("https://api.test", "/items")
        assert "?" not in url

    def test_empty_query_dict(self):
        url = build_url("https://api.test", "/items", {})
        assert "?" not in url


class TestMakeFinding:
    def test_basic_finding(self):
        f = make_finding(
            owasp_category="API2:2023",
            title="Test Finding",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            endpoint="GET /users",
            description="Test description",
            evidence={"request": {}, "response": {}},
            impact="Test impact",
            remediation="Test fix",
        )
        assert f["title"] == "Test Finding"
        assert f["owasp_category"] == "API2:2023"
        assert f["finding_id"].startswith("API2")
        assert f["confidence"] == "HIGH"
        assert f["references"] == []
        assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
        assert f["cvss_score"] >= 0.0

    def test_sequential_ids(self):
        f1 = make_finding(
            owasp_category="API8:2023", title="A",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            endpoint="GET /a", description="", evidence={},
            impact="", remediation="",
        )
        f2 = make_finding(
            owasp_category="API8:2023", title="B",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            endpoint="GET /b", description="", evidence={},
            impact="", remediation="",
        )
        assert f1["finding_id"] != f2["finding_id"]

    def test_custom_confidence(self):
        f = make_finding(
            owasp_category="API1:2023", title="X",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            endpoint="GET /x", description="", evidence={},
            impact="", remediation="", confidence="LOW",
        )
        assert f["confidence"] == "LOW"

    def test_references_included(self):
        f = make_finding(
            owasp_category="API1:2023", title="X",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            endpoint="GET /x", description="", evidence={},
            impact="", remediation="",
            references=["https://owasp.org"],
        )
        assert f["references"] == ["https://owasp.org"]
