"""Tests for auth_handler — building auth headers from config."""
import pytest
from app.scanners.api_scanner.engine.auth_handler import build_auth_headers


class TestBuildAuthHeaders:
    def test_none_config(self):
        h, q = build_auth_headers(None)
        assert h == {}
        assert q == {}

    def test_empty_dict(self):
        h, q = build_auth_headers({})
        assert h == {}
        assert q == {}

    def test_type_none(self):
        h, q = build_auth_headers({"type": "none"})
        assert h == {}
        assert q == {}

    def test_bearer(self):
        h, q = build_auth_headers({"type": "bearer", "token": "my-jwt-token"})
        assert h == {"Authorization": "Bearer my-jwt-token"}
        assert q == {}

    def test_bearer_empty_token_treated_as_no_auth(self):
        h, q = build_auth_headers({"type": "bearer", "token": ""})
        assert h == {}
        assert q == {}

    def test_bearer_whitespace_token_treated_as_no_auth(self):
        h, q = build_auth_headers({"type": "bearer", "token": "   "})
        assert h == {}
        assert q == {}

    def test_api_key_header(self):
        h, q = build_auth_headers({"type": "api_key", "header_name": "X-API-Key", "value": "abc123"})
        assert h == {"X-API-Key": "abc123"}
        assert q == {}

    def test_api_key_empty_header_name_treated_as_no_auth(self):
        h, q = build_auth_headers({"type": "api_key", "header_name": "", "value": "abc123"})
        assert h == {}
        assert q == {}

    def test_api_key_empty_value_treated_as_no_auth(self):
        h, q = build_auth_headers({"type": "api_key", "header_name": "api_key", "value": ""})
        assert h == {}
        assert q == {}

    def test_api_key_both_empty_treated_as_no_auth(self):
        """Reproduces the bug where frontend sent empty strings."""
        h, q = build_auth_headers({
            "type": "api_key", "header_name": "", "value": "",
            "token": "", "username": "", "password": "", "param_name": "",
        })
        assert h == {}
        assert q == {}

    def test_api_key_query(self):
        h, q = build_auth_headers({"type": "api_key_query", "param_name": "key", "value": "abc123"})
        assert h == {}
        assert q == {"key": "abc123"}

    def test_api_key_query_empty_treated_as_no_auth(self):
        h, q = build_auth_headers({"type": "api_key_query", "param_name": "", "value": ""})
        assert h == {}
        assert q == {}

    def test_basic_auth(self):
        h, q = build_auth_headers({"type": "basic", "username": "admin", "password": "secret"})
        assert "Authorization" in h
        assert h["Authorization"].startswith("Basic ")
        assert q == {}

    def test_basic_auth_empty_username_treated_as_no_auth(self):
        h, q = build_auth_headers({"type": "basic", "username": "", "password": "secret"})
        assert h == {}
        assert q == {}

    def test_unknown_type(self):
        h, q = build_auth_headers({"type": "oauth2"})
        assert h == {}
        assert q == {}
