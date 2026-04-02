"""Tests for request_executor — async HTTP execution with evidence."""
import pytest
import responses
from unittest.mock import patch

from app.scanners.api_scanner.engine.request_executor import execute_request


@pytest.mark.asyncio
class TestExecuteRequest:
    @responses.activate
    async def test_successful_get(self):
        responses.add(responses.GET, "https://api.test/items", json={"items": []}, status=200)
        resp, evidence = await execute_request("GET", "https://api.test/items")
        assert resp is not None
        assert resp.status_code == 200
        assert evidence["request"]["method"] == "GET"
        assert evidence["response"]["status_code"] == 200

    @responses.activate
    async def test_post_with_body(self):
        responses.add(responses.POST, "https://api.test/items", json={"id": 1}, status=201)
        resp, evidence = await execute_request(
            "POST", "https://api.test/items",
            headers={"Content-Type": "application/json"},
            body={"name": "test"},
        )
        assert resp is not None
        assert resp.status_code == 201

    @responses.activate
    async def test_custom_headers_sent(self):
        responses.add(responses.GET, "https://api.test/items", json={}, status=200)
        resp, evidence = await execute_request(
            "GET", "https://api.test/items",
            headers={"X-API-Key": "test-key"},
        )
        assert resp is not None
        # Verify header was in the request
        assert "X-API-Key" in responses.calls[0].request.headers

    @responses.activate
    async def test_timeout_returns_none(self):
        """Connection timeout produces None response with evidence."""
        import requests as req_lib
        responses.add(
            responses.GET, "https://api.test/slow",
            body=req_lib.exceptions.Timeout("timed out"),
        )
        resp, evidence = await execute_request("GET", "https://api.test/slow")
        assert resp is None
        assert evidence["response"]["status_code"] is None

    @responses.activate
    async def test_connection_error_returns_none(self):
        import requests as req_lib
        responses.add(
            responses.GET, "https://api.test/down",
            body=req_lib.exceptions.ConnectionError("refused"),
        )
        resp, evidence = await execute_request("GET", "https://api.test/down")
        assert resp is None
        assert evidence["request"]["url"] == "https://api.test/down"

    @responses.activate
    async def test_evidence_always_returned(self):
        """Evidence is returned even when request fails."""
        import requests as req_lib
        responses.add(
            responses.GET, "https://api.test/fail",
            body=req_lib.exceptions.ConnectionError("fail"),
        )
        resp, evidence = await execute_request("GET", "https://api.test/fail")
        assert evidence is not None
        assert "request" in evidence
        assert "response" in evidence

    @responses.activate
    async def test_404_response(self):
        responses.add(responses.GET, "https://api.test/missing", status=404)
        resp, evidence = await execute_request("GET", "https://api.test/missing")
        assert resp is not None
        assert resp.status_code == 404
        assert evidence["response"]["status_code"] == 404
