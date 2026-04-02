from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.engine.response_differ import compare_responses, responses_are_same
from app.scanners.api_scanner.engine.scan_context import ScanContext
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "API2:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"


def _detect_auth_type(auth_headers: Dict[str, str], query_params: Dict[str, str]) -> str:
    """Detect which auth mechanism is in use based on the headers/params."""
    for k, v in auth_headers.items():
        if k.lower() == "authorization":
            if v.lower().startswith("bearer "):
                return "bearer"
            if v.lower().startswith("basic "):
                return "basic"
    # If there are auth headers but not Authorization, it's likely API key in header
    if auth_headers:
        return "api_key"
    # Check query params
    if query_params:
        return "api_key_query"
    return "none"


async def run_auth_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
    secondary_auth_headers: Optional[Dict[str, str]] = None,
    secondary_query_params: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Run authentication checks on a single endpoint using response diffing
    to reduce false positives on public endpoints."""

    findings: List[Dict[str, Any]] = []
    path = endpoint.get("path", "")
    method = endpoint.get("method", "GET")
    url = build_url(base_url, path, query_params)
    ep_label = f"{method} {path}"

    has_auth = bool(auth_headers) or bool(query_params)
    auth_type = _detect_auth_type(auth_headers, query_params)

    # ── 1. Baseline: authenticated request ────────────────────────────────
    if has_auth:
        baseline_resp, baseline_evidence = await execute_request(
            method, url, headers=auth_headers,
        )
    else:
        baseline_resp = None
        baseline_evidence = {}

    # ── 2. No-auth request & compare against baseline ─────────────────────
    # Build a URL without auth query params for no-auth test
    noauth_url = build_url(base_url, path)
    noauth_resp, noauth_evidence = await execute_request(method, noauth_url)

    if noauth_resp is not None:
        noauth_status = noauth_resp.status_code

        # If the no-auth request is outright rejected, endpoint requires auth — good.
        if noauth_status in (401, 403):
            logger.debug("%s correctly requires auth (got %d)", ep_label, noauth_status)
        elif has_auth and baseline_resp is not None:
            # Both responses exist — compare them.
            if responses_are_same(baseline_resp, noauth_resp):
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title="Missing Authentication",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    endpoint=ep_label,
                    description=(
                        "The endpoint returns identical data with and without "
                        "authentication headers, indicating authentication is "
                        "not enforced."
                    ),
                    evidence=noauth_evidence,
                    impact=(
                        "Anyone on the internet can access this endpoint and "
                        "retrieve the same data as an authenticated user."
                    ),
                    remediation=(
                        "Require a valid authentication token on every request. "
                        "Return 401 Unauthorized when no credentials are provided."
                    ),
                    confidence="HIGH",
                    references=[REF],
                ))
            else:
                # Responses differ — check if no-auth still returns partial data.
                diff = compare_responses(baseline_resp, noauth_resp)
                if (
                    noauth_status == 200
                    and diff.body_length_ratio > 0.0
                    and not diff.status_changed
                ):
                    findings.append(make_finding(
                        owasp_category=OWASP,
                        title="Partial Authentication Bypass",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        endpoint=ep_label,
                        description=(
                            "The endpoint returns a subset of data without "
                            "authentication. The authenticated response contains "
                            "richer data, suggesting partial enforcement."
                        ),
                        evidence=noauth_evidence,
                        impact=(
                            "Unauthenticated users can retrieve partial data "
                            "from this endpoint."
                        ),
                        remediation=(
                            "Ensure all sensitive data requires authentication. "
                            "Return 401 for fully unauthenticated requests."
                        ),
                        confidence="MEDIUM",
                        references=[REF],
                    ))
        elif not has_auth and noauth_status == 200:
            # No auth headers available to establish a baseline — low confidence.
            body_len = len(noauth_resp.text) if noauth_resp.text else 0
            if body_len > 2:
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title="Missing Authentication",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    endpoint=ep_label,
                    description=(
                        "The endpoint returns data without authentication. "
                        "No valid credentials were available to verify whether "
                        "authenticated responses differ."
                    ),
                    evidence=noauth_evidence,
                    impact=(
                        "The endpoint may be publicly accessible. Manual review "
                        "is recommended to confirm this is not intentional."
                    ),
                    remediation=(
                        "Require a valid authentication token on every request. "
                        "Return 401 Unauthorized when no credentials are provided."
                    ),
                    confidence="LOW",
                    references=[REF],
                ))

    # ── 3. Token/key bypass tests — ONLY for the configured auth type ─────
    if has_auth and baseline_resp is not None:
        if auth_type == "bearer":
            # Test empty Bearer and invalid Bearer
            await _test_bearer_bypass(findings, method, url, baseline_resp, ep_label)

        elif auth_type == "api_key":
            # Test wrong API key value in the same header
            await _test_api_key_header_bypass(
                findings, method, url, baseline_resp, ep_label, auth_headers,
            )

        elif auth_type == "api_key_query":
            # Test wrong API key value in query param
            await _test_api_key_query_bypass(
                findings, method, base_url, path, baseline_resp, ep_label, query_params,
            )

        elif auth_type == "basic":
            # Test wrong Basic credentials
            await _test_basic_bypass(findings, method, url, baseline_resp, ep_label)

    # ── 4. Secondary token — check if both users see identical data ───────
    if secondary_auth_headers is not None and baseline_resp is not None:
        secondary_url = build_url(
            base_url, path,
            secondary_query_params if secondary_query_params else query_params,
        )
        secondary_resp, secondary_evidence = await execute_request(
            method, secondary_url, headers=secondary_auth_headers,
        )

        if (
            secondary_resp is not None
            and responses_are_same(baseline_resp, secondary_resp)
        ):
            findings.append(make_finding(
                owasp_category=OWASP,
                title="Identical Response Across Users",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                endpoint=ep_label,
                description=(
                    "Two different authenticated users receive identical "
                    "responses, which may indicate missing per-user data "
                    "scoping or a shared resource that should be isolated."
                ),
                evidence=secondary_evidence,
                impact=(
                    "Users may be able to access data belonging to other "
                    "users if per-user authorization is not enforced."
                ),
                remediation=(
                    "Ensure responses are scoped to the authenticated user. "
                    "Implement object-level authorization checks."
                ),
                confidence="MEDIUM",
                references=[REF],
            ))

    # ── 5. API key in query string (static analysis) ──────────────────────
    raw_url = build_url(base_url, path)
    sensitive_params = re.findall(
        r'[?&](api_key|token|key|secret|password|access_token)=',
        raw_url.lower(),
    )
    endpoint_params = endpoint.get("parameters", [])
    has_sensitive_query_param = any(
        p.get("name", "").lower()
        in ("api_key", "token", "key", "secret", "password", "access_token")
        for p in endpoint_params
        if p.get("in") == "query"
    )

    if sensitive_params or has_sensitive_query_param:
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Sensitive Credential in URL Query String",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            endpoint=ep_label,
            description=(
                "The endpoint accepts authentication credentials as URL query "
                "parameters, which are logged in server logs, browser history, "
                "and proxy caches."
            ),
            evidence={
                "request": {
                    "url": raw_url,
                    "note": "Credential parameter detected in query string",
                },
                "response": {},
            },
            impact=(
                "Credentials leaked via server logs, browser history, referrer "
                "headers, and proxy caches."
            ),
            remediation=(
                "Pass credentials in HTTP headers (Authorization, X-API-Key) "
                "instead of URL query strings."
            ),
            confidence="MEDIUM",
            references=[REF],
        ))

    return findings


# ── Helper functions for auth-type-specific bypass tests ──────────────────


async def _test_bearer_bypass(findings, method, url, baseline_resp, ep_label):
    """Test empty and invalid Bearer tokens."""
    ctx = ScanContext()
    # Empty Bearer
    empty_resp, empty_evidence = await execute_request(
        method, url, headers={"Authorization": "Bearer "},
    )
    if empty_resp is not None and responses_are_same(baseline_resp, empty_resp):
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Empty Bearer Token Accepted",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            endpoint=ep_label,
            description=(
                "The endpoint returns the same response for an empty Bearer "
                "token as for a valid token, indicating the token is not validated."
            ),
            evidence=empty_evidence,
            impact="Authentication can be bypassed by sending an empty Authorization header.",
            remediation=(
                "Validate that the Bearer token is non-empty and "
                "cryptographically valid before processing the request."
            ),
            references=[REF],
        ))

    # Invalid Bearer
    invalid_resp, invalid_evidence = await execute_request(
        method, url, headers={"Authorization": f"Bearer {ctx.invalid_token}"},
    )
    if invalid_resp is not None and responses_are_same(baseline_resp, invalid_resp):
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Invalid Token Accepted",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            endpoint=ep_label,
            description=(
                "The endpoint returns the same response for an invalid Bearer "
                "token as for a valid token, indicating token validation is "
                "broken or absent."
            ),
            evidence=invalid_evidence,
            impact=(
                "Authentication is not properly validated. Any arbitrary token "
                "grants access to the same data as a legitimate user."
            ),
            remediation=(
                "Verify token signature and claims server-side. Reject tokens "
                "that fail validation with 401."
            ),
            references=[REF],
        ))


async def _test_api_key_header_bypass(findings, method, url, baseline_resp, ep_label, auth_headers):
    """Test wrong API key value in the same header."""
    ctx = ScanContext()
    # Find the API key header name (non-Authorization header)
    key_header = None
    for k in auth_headers:
        if k.lower() != "authorization":
            key_header = k
            break
    if not key_header:
        return

    # Wrong API key value
    wrong_key_headers = {key_header: ctx.invalid_api_key}
    wrong_resp, wrong_evidence = await execute_request(
        method, url, headers=wrong_key_headers,
    )
    if wrong_resp is not None and responses_are_same(baseline_resp, wrong_resp):
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Invalid API Key Accepted",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            endpoint=ep_label,
            description=(
                f"The endpoint returns the same response for an invalid "
                f"'{key_header}' value as for the valid key, indicating "
                f"the API key is not validated."
            ),
            evidence=wrong_evidence,
            impact=(
                "Authentication can be bypassed with any arbitrary API key value."
            ),
            remediation=(
                "Validate the API key server-side against a known set of valid keys. "
                "Return 401 or 403 for invalid keys."
            ),
            references=[REF],
        ))

    # Empty API key value
    empty_key_headers = {key_header: ""}
    empty_resp, empty_evidence = await execute_request(
        method, url, headers=empty_key_headers,
    )
    if empty_resp is not None and responses_are_same(baseline_resp, empty_resp):
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Empty API Key Accepted",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            endpoint=ep_label,
            description=(
                f"The endpoint returns the same response for an empty "
                f"'{key_header}' header as for a valid key, indicating "
                f"the API key is not validated."
            ),
            evidence=empty_evidence,
            impact="Authentication can be bypassed by sending an empty API key header.",
            remediation=(
                "Validate that the API key is non-empty and matches a known valid key. "
                "Return 401 or 403 for empty or missing keys."
            ),
            references=[REF],
        ))


async def _test_api_key_query_bypass(findings, method, base_url, path, baseline_resp, ep_label, query_params):
    """Test wrong API key value in query parameter."""
    ctx = ScanContext()
    # Find the API key param name
    key_param = None
    for k in query_params:
        key_param = k
        break
    if not key_param:
        return

    # Wrong value
    wrong_params = {key_param: ctx.invalid_api_key}
    wrong_url = build_url(base_url, path, wrong_params)
    wrong_resp, wrong_evidence = await execute_request(method, wrong_url)
    if wrong_resp is not None and responses_are_same(baseline_resp, wrong_resp):
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Invalid API Key Accepted (Query)",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            endpoint=ep_label,
            description=(
                f"The endpoint returns the same response for an invalid "
                f"'{key_param}' query parameter as for the valid key."
            ),
            evidence=wrong_evidence,
            impact="Authentication can be bypassed with any arbitrary API key.",
            remediation=(
                "Validate the API key server-side. Return 401 or 403 for invalid keys."
            ),
            references=[REF],
        ))


async def _test_basic_bypass(findings, method, url, baseline_resp, ep_label):
    """Test wrong Basic auth credentials."""
    import base64
    wrong_creds = base64.b64encode(b"invalid_user:invalid_pass").decode()
    wrong_resp, wrong_evidence = await execute_request(
        method, url, headers={"Authorization": f"Basic {wrong_creds}"},
    )
    if wrong_resp is not None and responses_are_same(baseline_resp, wrong_resp):
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Invalid Basic Credentials Accepted",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            endpoint=ep_label,
            description=(
                "The endpoint returns the same response for invalid Basic auth "
                "credentials as for valid credentials, indicating authentication "
                "is not enforced."
            ),
            evidence=wrong_evidence,
            impact="Authentication can be bypassed with arbitrary credentials.",
            remediation=(
                "Validate username and password server-side. Return 401 for "
                "invalid credentials."
            ),
            references=[REF],
        ))
