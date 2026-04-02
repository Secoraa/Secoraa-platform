from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "API8:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
CVSS_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

NOSQL_PAYLOADS = [
    {"$ne": None},
    {"$gt": ""},
    {"$where": "1==1"},
    {"$regex": ".*"},
    {"$exists": True},
]

NOSQL_ERROR_PATTERNS = [
    "mongoerror", "mongod", "bson", "operator", "$where",
    "cast to objectid failed", "e11000", "writeresult",
]


async def run_nosql_injection_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Run NoSQL injection checks on POST/PUT/PATCH endpoints."""
    findings: List[Dict[str, Any]] = []
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    ep_label = f"{method} {path}"

    if method not in ("POST", "PUT", "PATCH"):
        return findings

    url = build_url(base_url, path, query_params)
    merged_headers = {**auth_headers, "Content-Type": "application/json"}

    # Get baseline response with normal body
    normal_body = endpoint.get("body", {}) or {"test": "value"}
    baseline_resp, _ = await execute_request(method, url, headers=merged_headers, body=normal_body)
    baseline_len = len(baseline_resp.text) if baseline_resp and baseline_resp.text else 0
    baseline_status = baseline_resp.status_code if baseline_resp else 0

    # Extract field names from endpoint body schema
    body_fields = list((endpoint.get("body") or {}).keys())
    if not body_fields:
        body_fields = ["username", "email", "name", "query", "search", "filter", "id"]

    for payload in NOSQL_PAYLOADS:
        # Strategy 1: Inject into each field individually
        for field in body_fields:
            test_body = dict(normal_body)
            test_body[field] = payload

            resp, evidence = await execute_request(method, url, headers=merged_headers, body=test_body)
            if resp is None:
                continue

            # Detection: response returns more data, or error messages with NoSQL keywords
            resp_text = (resp.text or "").lower()
            is_error_based = any(p in resp_text for p in NOSQL_ERROR_PATTERNS)
            is_data_leak = (
                resp.status_code == 200
                and baseline_len > 0
                and len(resp.text or "") > baseline_len * 1.5
            )

            if is_error_based or is_data_leak:
                reason = "error message containing NoSQL keywords" if is_error_based else "response returned significantly more data than baseline"
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title=f"NoSQL Injection — {field}",
                    cvss_vector=CVSS_VEC,
                    endpoint=ep_label,
                    description=f"The field '{field}' appears vulnerable to NoSQL injection. Detection: {reason}. Payload: {payload}",
                    evidence=evidence,
                    impact="Attacker can bypass authentication, extract data, or modify queries by injecting NoSQL operators.",
                    remediation="Sanitize all user inputs. Use parameterized queries. Reject objects with MongoDB operators ($ne, $gt, $where, etc.) in user-supplied data.",
                    confidence="HIGH" if is_error_based else "MEDIUM",
                    references=[REF],
                ))
                # One proof per payload type is enough
                break

        # Strategy 2: Inject as entire body (catches weak parsers)
        resp, evidence = await execute_request(method, url, headers=merged_headers, body=payload)
        if resp is not None and resp.status_code == 200:
            resp_text = (resp.text or "").lower()
            if any(p in resp_text for p in NOSQL_ERROR_PATTERNS) or (baseline_len > 0 and len(resp.text or "") > baseline_len * 1.5):
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title="NoSQL Injection — Full Body Replacement",
                    cvss_vector=CVSS_VEC,
                    endpoint=ep_label,
                    description=f"The endpoint accepts a raw NoSQL operator as the entire request body. Payload: {payload}",
                    evidence=evidence,
                    impact="Complete query manipulation possible. Attacker can bypass filters and access all records.",
                    remediation="Validate request body schema strictly. Reject payloads that don't match expected fields.",
                    references=[REF],
                ))
                break

    return findings
