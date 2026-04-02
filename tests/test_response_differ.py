"""Tests for response_differ — similarity scoring and comparison logic."""
import pytest
from unittest.mock import MagicMock
from requests import Response

from app.scanners.api_scanner.engine.response_differ import (
    DiffResult,
    compare_responses,
    responses_are_same,
    has_new_content,
    _body_hash,
    _normalize_body,
    _compute_body_length_ratio,
    _compute_similarity,
    _verdict_from_score,
)


def _resp(status=200, text="", json_data=None):
    """Create a minimal mock Response."""
    r = MagicMock(spec=Response)
    r.status_code = status
    r.text = text
    if json_data is not None:
        import json
        r.text = json.dumps(json_data)
        r.json.return_value = json_data
    else:
        r.json.side_effect = ValueError("No JSON")
    return r


class TestComputeBodyLengthRatio:
    def test_both_zero(self):
        assert _compute_body_length_ratio(0, 0) == 1.0

    def test_baseline_zero_test_nonzero(self):
        assert _compute_body_length_ratio(0, 50) == 50.0

    def test_equal_lengths(self):
        assert _compute_body_length_ratio(100, 100) == 1.0

    def test_half_length(self):
        assert _compute_body_length_ratio(100, 50) == 0.5


class TestComputeSimilarity:
    def test_identical(self):
        score = _compute_similarity(True, True, 1.0, 1.0)
        assert score == 1.0  # 0.30 + 0.70

    def test_completely_different(self):
        score = _compute_similarity(False, False, 0.0, 0.0)
        assert score == 0.0

    def test_same_status_different_body(self):
        score = _compute_similarity(True, False, 1.0, None)
        # 0.30 (status) + 0.20 * 1.0 (length) = 0.50
        assert score == 0.50

    def test_same_hash_different_status(self):
        score = _compute_similarity(False, True, 1.0, None)
        assert score == 0.70  # 0.0 + 0.70


class TestVerdictFromScore:
    def test_same(self):
        assert _verdict_from_score(0.95) == "SAME"

    def test_similar(self):
        assert _verdict_from_score(0.75) == "SIMILAR"

    def test_different(self):
        assert _verdict_from_score(0.30) == "DIFFERENT"

    def test_boundary_same(self):
        assert _verdict_from_score(0.90) == "SAME"

    def test_boundary_similar(self):
        assert _verdict_from_score(0.60) == "SIMILAR"

    def test_boundary_different(self):
        assert _verdict_from_score(0.59) == "DIFFERENT"


class TestCompareResponses:
    def test_both_none(self):
        result = compare_responses(None, None)
        assert result.verdict == "SAME"
        assert result.similarity_score == 1.0

    def test_baseline_none(self):
        result = compare_responses(None, _resp())
        assert result.verdict == "DIFFERENT"
        assert result.similarity_score == 0.0

    def test_test_none(self):
        result = compare_responses(_resp(), None)
        assert result.verdict == "DIFFERENT"

    def test_identical_responses(self):
        """Identical responses score 1.0 (status 0.30 + hash 0.70) → SAME."""
        body = '{"id": 1, "name": "test"}'
        r1 = _resp(200, body, {"id": 1, "name": "test"})
        r2 = _resp(200, body, {"id": 1, "name": "test"})
        result = compare_responses(r1, r2)
        assert result.similarity_score == 1.0
        assert result.verdict == "SAME"
        assert result.status_changed is False

    def test_different_status_codes(self):
        r1 = _resp(200, "ok")
        r2 = _resp(401, "unauthorized")
        result = compare_responses(r1, r2)
        assert result.status_changed is True
        assert result.similarity_score < 0.5

    def test_same_status_different_body(self):
        r1 = _resp(200, "response A")
        r2 = _resp(200, "completely different response body here")
        result = compare_responses(r1, r2)
        assert result.status_changed is False
        assert result.verdict in ("SIMILAR", "DIFFERENT")

    def test_json_key_overlap(self):
        r1 = _resp(200, json_data={"id": 1, "name": "a", "email": "a@b.com"})
        r2 = _resp(200, json_data={"id": 2, "name": "b", "phone": "123"})
        result = compare_responses(r1, r2)
        # Some overlap (id, name) but not all (email vs phone)
        assert result.similarity_score > 0.0

    def test_keywords_found_in_test_only(self):
        r1 = _resp(200, "normal response")
        r2 = _resp(200, "error: stack trace at line 42")
        result = compare_responses(r1, r2, keywords=["stack trace"])
        assert "stack trace" in result.new_keywords

    def test_keywords_in_both_not_reported(self):
        r1 = _resp(200, "has stack trace")
        r2 = _resp(200, "also has stack trace")
        result = compare_responses(r1, r2, keywords=["stack trace"])
        assert result.new_keywords == []


class TestResponsesAreSame:
    def test_both_none(self):
        assert responses_are_same(None, None) is True

    def test_one_none(self):
        assert responses_are_same(_resp(), None) is False
        assert responses_are_same(None, _resp()) is False

    def test_identical(self):
        r1 = _resp(200, "same body")
        r2 = _resp(200, "same body")
        assert responses_are_same(r1, r2) is True

    def test_different_status(self):
        r1 = _resp(200, "body")
        r2 = _resp(401, "body")
        assert responses_are_same(r1, r2) is False

    def test_different_body(self):
        r1 = _resp(200, "body A")
        r2 = _resp(200, "body B")
        assert responses_are_same(r1, r2) is False


class TestHasNewContent:
    def test_empty_keywords(self):
        assert has_new_content(_resp(200, "abc"), _resp(200, "xyz")) == []

    def test_keyword_only_in_test(self):
        r1 = _resp(200, "normal output")
        r2 = _resp(200, "error: sql syntax error near")
        assert has_new_content(r1, r2, ["sql syntax"]) == ["sql syntax"]

    def test_keyword_in_both(self):
        r1 = _resp(200, "sql syntax in baseline")
        r2 = _resp(200, "sql syntax in test")
        assert has_new_content(r1, r2, ["sql syntax"]) == []

    def test_case_insensitive(self):
        r1 = _resp(200, "normal")
        r2 = _resp(200, "SQL SYNTAX ERROR")
        assert has_new_content(r1, r2, ["sql syntax"]) == ["sql syntax"]

    def test_none_responses(self):
        assert has_new_content(None, _resp(200, "error"), ["error"]) == ["error"]
        assert has_new_content(_resp(200, "ok"), None, ["error"]) == []


class TestNormalizeBody:
    def test_strips_uuids(self):
        text = "user id=550e8400-e29b-41d4-a716-446655440000 found"
        assert "550e8400" not in _normalize_body(text)

    def test_strips_iso_timestamps(self):
        text = "created at 2025-03-22T14:30:00.123Z ok"
        assert "2025-03-22" not in _normalize_body(text)

    def test_strips_unix_timestamps(self):
        text = "ts=1679500000 done"
        assert "1679500000" not in _normalize_body(text)

    def test_strips_hex_tokens(self):
        text = "csrf=abcdef0123456789abcdef end"
        assert "abcdef0123456789abcdef" not in _normalize_body(text)

    def test_replaces_dynamic_fields(self):
        text = '"session": "a1b2c3d4e5f6g7h8i9j0"'
        result = _normalize_body(text)
        assert "<DYNAMIC>" in result
        assert "a1b2c3d4e5f6g7h8i9j0" not in result

    def test_collapses_whitespace(self):
        text = "hello   world\t\nfoo"
        assert _normalize_body(text) == "hello world foo"

    def test_strips_leading_trailing(self):
        assert _normalize_body("  hello  ") == "hello"

    def test_preserves_meaningful_content(self):
        text = "error: access denied for user admin"
        assert _normalize_body(text) == text


class TestBodyHashNormalization:
    def test_normalize_on_by_default(self):
        # Bodies that differ only by UUID should hash the same
        t1 = "user 550e8400-e29b-41d4-a716-446655440000 ok"
        t2 = "user a1234567-b234-c345-d456-e12345678901 ok"
        assert _body_hash(t1) == _body_hash(t2)

    def test_normalize_false_preserves_raw(self):
        t1 = "user 550e8400-e29b-41d4-a716-446655440000 ok"
        t2 = "user a1234567-b234-c345-d456-e12345678901 ok"
        assert _body_hash(t1, normalize=False) != _body_hash(t2, normalize=False)


class TestNormalizationInCompareResponses:
    def test_responses_differing_only_in_uuid_are_same(self):
        body1 = '{"request_id": "550e8400-e29b-41d4-a716-446655440000", "status": "ok"}'
        body2 = '{"request_id": "a1234567-b234-c345-d456-e12345678901", "status": "ok"}'
        r1 = _resp(200, body1)
        r2 = _resp(200, body2)
        result = compare_responses(r1, r2)
        assert result.verdict == "SAME"

    def test_responses_differing_only_in_timestamp_are_same(self):
        body1 = "created: 2025-03-22T10:00:00Z data here"
        body2 = "created: 2026-01-15T23:59:59Z data here"
        r1 = _resp(200, body1)
        r2 = _resp(200, body2)
        result = compare_responses(r1, r2)
        assert result.verdict == "SAME"

    def test_keywords_still_detected_on_raw_text(self):
        """Keyword detection uses raw text, not normalized."""
        body1 = "ok 550e8400-e29b-41d4-a716-446655440000"
        body2 = "error: sql injection 550e8400-e29b-41d4-a716-446655440000"
        r1 = _resp(200, body1)
        r2 = _resp(200, body2)
        result = compare_responses(r1, r2, keywords=["sql injection"])
        assert "sql injection" in result.new_keywords

    def test_responses_are_same_with_dynamic_content(self):
        body1 = "token=abcdef0123456789abcdef result ok"
        body2 = "token=99887766554433221100aa result ok"
        r1 = _resp(200, body1)
        r2 = _resp(200, body2)
        assert responses_are_same(r1, r2) is True
