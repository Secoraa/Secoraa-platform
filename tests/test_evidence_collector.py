"""Tests for evidence_collector — evidence building and header sanitization."""
import pytest
from unittest.mock import MagicMock
from requests import Response

from app.scanners.api_scanner.engine.evidence_collector import (
    _truncate,
    _sanitize_headers,
    build_evidence,
    MAX_BODY_SIZE,
)


class TestTruncate:
    def test_none(self):
        assert _truncate(None) is None

    def test_short_text(self):
        assert _truncate("hello") == "hello"

    def test_exact_limit(self):
        text = "x" * MAX_BODY_SIZE
        assert _truncate(text) == text

    def test_over_limit(self):
        text = "x" * (MAX_BODY_SIZE + 100)
        result = _truncate(text)
        assert result.endswith("... [truncated]")
        assert len(result) < len(text)

    def test_custom_limit(self):
        result = _truncate("hello world", limit=5)
        assert result == "hello... [truncated]"


class TestSanitizeHeaders:
    def test_none(self):
        assert _sanitize_headers(None) == {}

    def test_empty(self):
        assert _sanitize_headers({}) == {}

    def test_non_sensitive_preserved(self):
        headers = {"Content-Type": "application/json", "Accept": "text/html"}
        result = _sanitize_headers(headers)
        assert result == headers

    def test_authorization_masked(self):
        headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.long_token"}
        result = _sanitize_headers(headers)
        val = result["Authorization"]
        assert val.startswith("Bearer eyJhb")
        assert val.endswith("...oken")
        assert len(val) < len(headers["Authorization"])

    def test_api_key_masked(self):
        headers = {"X-API-Key": "sk-1234567890abcdef"}
        result = _sanitize_headers(headers)
        val = result["X-API-Key"]
        assert val.startswith("sk-123456789")
        assert "..." in val

    def test_cookie_masked(self):
        headers = {"Cookie": "session=abc123def456ghi789"}
        result = _sanitize_headers(headers)
        assert "..." in result["Cookie"]

    def test_short_sensitive_not_masked(self):
        # Values <= 12 chars are NOT masked
        headers = {"Authorization": "short"}
        result = _sanitize_headers(headers)
        assert result["Authorization"] == "short"


class TestBuildEvidence:
    def test_basic_no_response(self):
        ev = build_evidence("GET", "https://api.test/users")
        assert ev["request"]["method"] == "GET"
        assert ev["request"]["url"] == "https://api.test/users"
        assert ev["response"]["status_code"] is None

    def test_with_response(self):
        resp = MagicMock(spec=Response)
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        resp.text = '{"id": 1}'

        ev = build_evidence("POST", "https://api.test/items", response=resp)
        assert ev["response"]["status_code"] == 200
        assert ev["response"]["body_snippet"] == '{"id": 1}'

    def test_headers_sanitized(self):
        ev = build_evidence(
            "GET", "https://api.test/users",
            request_headers={"Authorization": "Bearer long_token_value_here"},
        )
        assert "..." in ev["request"]["headers"]["Authorization"]

    def test_request_body_included(self):
        ev = build_evidence(
            "POST", "https://api.test/items",
            request_body={"name": "test"},
        )
        assert ev["request"]["body"] is not None
        assert "test" in ev["request"]["body"]

    def test_no_body_when_none(self):
        ev = build_evidence("GET", "https://api.test/items")
        assert ev["request"]["body"] is None
