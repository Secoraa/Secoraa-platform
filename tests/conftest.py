"""Shared fixtures for API APT scanner tests."""
from __future__ import annotations

import pytest
import responses
from unittest.mock import MagicMock
from requests import Response

from app.scanners.api_scanner.tests import reset_finding_counters


BASE_URL = "https://test-api.example.com/api/v1"


@pytest.fixture(autouse=True)
def _reset_counters():
    """Reset finding ID counters before each test."""
    reset_finding_counters()
    yield
    reset_finding_counters()


@pytest.fixture
def base_url():
    return BASE_URL


@pytest.fixture
def auth_headers():
    return {"api_key": "test-key-123"}


@pytest.fixture
def bearer_headers():
    return {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"}


@pytest.fixture
def no_auth_headers():
    return {}


@pytest.fixture
def query_params():
    return {}


@pytest.fixture
def sample_endpoint():
    return {"method": "GET", "path": "/users/{userId}", "name": "getUser"}


@pytest.fixture
def sample_get_endpoint():
    return {"method": "GET", "path": "/items", "name": "listItems"}


@pytest.fixture
def sample_post_endpoint():
    return {"method": "POST", "path": "/items", "name": "createItem"}


@pytest.fixture
def sample_delete_endpoint():
    return {"method": "DELETE", "path": "/items/{itemId}", "name": "deleteItem"}


@pytest.fixture
def endpoints_list():
    return [
        {"method": "GET", "path": "/items", "name": "listItems"},
        {"method": "POST", "path": "/items", "name": "createItem"},
        {"method": "GET", "path": "/items/{itemId}", "name": "getItem"},
        {"method": "PUT", "path": "/items/{itemId}", "name": "updateItem"},
        {"method": "DELETE", "path": "/items/{itemId}", "name": "deleteItem"},
        {"method": "GET", "path": "/users/{userId}", "name": "getUser"},
    ]


def make_mock_response(status_code=200, body="", headers=None, json_data=None):
    """Create a mock requests.Response object."""
    resp = MagicMock(spec=Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    if json_data is not None:
        import json
        body = json.dumps(json_data)
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("No JSON")
    resp.text = body
    resp.content = body.encode("utf-8") if body else b""
    return resp
