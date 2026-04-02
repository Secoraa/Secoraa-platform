from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

from requests import Response


# --- Normalization patterns for stripping dynamic content -------------------

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\dZ+\-]*")
_UNIX_TS_RE = re.compile(r"\b1[6-9]\d{8}\b")
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-f]{20,}\b", re.IGNORECASE)
_DYNAMIC_FIELD_RE = re.compile(
    r'"(id|token|session|nonce|csrf|request_id|trace_id|correlation_id)"\s*:\s*"[^"]{8,}"'
)
_MULTI_WS_RE = re.compile(r"\s+")


@dataclass
class DiffResult:
    similarity_score: float  # 0.0 = completely different, 1.0 = identical
    status_changed: bool
    body_length_ratio: float  # test_len / baseline_len
    new_keywords: List[str]  # keywords found in test but not baseline
    verdict: str  # "SAME", "SIMILAR", "DIFFERENT"


def _body_text(resp: Optional[Response]) -> str:
    """Safely extract response body text."""
    if resp is None:
        return ""
    try:
        return resp.text or ""
    except Exception:
        return ""


def _normalize_body(text: str) -> str:
    """Strip dynamic content (UUIDs, timestamps, tokens, etc.) before comparison."""
    text = _UUID_RE.sub("", text)
    text = _ISO_TS_RE.sub("", text)
    text = _UNIX_TS_RE.sub("", text)
    text = _HEX_TOKEN_RE.sub("", text)
    text = _DYNAMIC_FIELD_RE.sub(lambda m: f'"{m.group(1)}": "<DYNAMIC>"', text)
    text = _MULTI_WS_RE.sub(" ", text)
    return text.strip()


def _body_hash(text: str, normalize: bool = True) -> str:
    if normalize:
        text = _normalize_body(text)
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()


def _json_keys(resp: Optional[Response]) -> Optional[set]:
    """Try to parse JSON and return the top-level key set, or None."""
    if resp is None:
        return None
    try:
        data = resp.json()
        if isinstance(data, dict):
            return set(data.keys())
    except (json.JSONDecodeError, ValueError, AttributeError):
        pass
    return None


def _compute_body_length_ratio(baseline_len: int, test_len: int) -> float:
    if baseline_len == 0:
        return float(test_len) if test_len > 0 else 1.0
    return test_len / baseline_len


def _compute_similarity(
    status_same: bool,
    hash_same: bool,
    length_ratio: float,
    json_key_overlap: Optional[float],
) -> float:
    """Compute a 0.0-1.0 similarity score from individual signals."""
    score = 0.0

    # Status code match contributes 30%
    if status_same:
        score += 0.30

    # Exact body hash match contributes 70% — identical bodies are identical
    if hash_same:
        score += 0.70
    else:
        # Body length similarity contributes up to 20% when hash differs
        if length_ratio > 1.0:
            ratio_closeness = 1.0 / length_ratio
        else:
            ratio_closeness = length_ratio
        score += 0.20 * ratio_closeness

        # JSON structure overlap contributes up to 20% when hash differs
        if json_key_overlap is not None:
            score += 0.20 * json_key_overlap

    return min(score, 1.0)


def _verdict_from_score(score: float) -> str:
    if score >= 0.90:
        return "SAME"
    if score >= 0.60:
        return "SIMILAR"
    return "DIFFERENT"


def compare_responses(
    baseline_resp: Optional[Response],
    test_resp: Optional[Response],
    keywords: Optional[List[str]] = None,
) -> DiffResult:
    """Compare a baseline HTTP response against a test response.

    Returns a ``DiffResult`` describing how much the two responses differ.
    """
    if keywords is None:
        keywords = []

    # --- Handle None cases ---------------------------------------------------
    if baseline_resp is None and test_resp is None:
        return DiffResult(
            similarity_score=1.0,
            status_changed=False,
            body_length_ratio=1.0,
            new_keywords=[],
            verdict="SAME",
        )

    if baseline_resp is None or test_resp is None:
        found_keywords = has_new_content(baseline_resp, test_resp, keywords)
        return DiffResult(
            similarity_score=0.0,
            status_changed=True,
            body_length_ratio=0.0,
            new_keywords=found_keywords,
            verdict="DIFFERENT",
        )

    # --- Status code ----------------------------------------------------------
    status_same = baseline_resp.status_code == test_resp.status_code

    # --- Body -----------------------------------------------------------------
    baseline_text = _body_text(baseline_resp)
    test_text = _body_text(test_resp)

    hash_same = _body_hash(baseline_text) == _body_hash(test_text)

    baseline_len = len(baseline_text)
    test_len = len(test_text)
    length_ratio = _compute_body_length_ratio(baseline_len, test_len)

    # --- JSON structure -------------------------------------------------------
    baseline_keys = _json_keys(baseline_resp)
    test_keys = _json_keys(test_resp)

    json_key_overlap: Optional[float] = None
    if baseline_keys is not None and test_keys is not None:
        all_keys = baseline_keys | test_keys
        if all_keys:
            json_key_overlap = len(baseline_keys & test_keys) / len(all_keys)
        else:
            json_key_overlap = 1.0

    # --- Keywords -------------------------------------------------------------
    found_keywords = has_new_content(baseline_resp, test_resp, keywords)

    # --- Aggregate ------------------------------------------------------------
    similarity = _compute_similarity(status_same, hash_same, length_ratio, json_key_overlap)
    verdict = _verdict_from_score(similarity)

    return DiffResult(
        similarity_score=round(similarity, 4),
        status_changed=not status_same,
        body_length_ratio=round(length_ratio, 4),
        new_keywords=found_keywords,
        verdict=verdict,
    )


def responses_are_same(
    baseline_resp: Optional[Response],
    test_resp: Optional[Response],
) -> bool:
    """Quick check: are these responses functionally identical?"""
    if baseline_resp is None and test_resp is None:
        return True
    if baseline_resp is None or test_resp is None:
        return False

    if baseline_resp.status_code != test_resp.status_code:
        return False

    return _body_hash(_body_text(baseline_resp)) == _body_hash(_body_text(test_resp))


def has_new_content(
    baseline_resp: Optional[Response],
    test_resp: Optional[Response],
    keywords: Optional[List[str]] = None,
) -> List[str]:
    """Return keywords found in *test_resp* but not in *baseline_resp*.

    Useful for injection tests where specific error strings indicate success.
    """
    if keywords is None:
        keywords = []
    if not keywords:
        return []

    baseline_lower = _body_text(baseline_resp).lower()
    test_lower = _body_text(test_resp).lower()

    new: List[str] = []
    for kw in keywords:
        kw_lower = kw.lower()
        if kw_lower in test_lower and kw_lower not in baseline_lower:
            new.append(kw)

    return new
