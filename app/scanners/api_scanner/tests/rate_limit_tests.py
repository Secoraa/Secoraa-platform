from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "API4:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "retry-after", "x-rate-limit",
]

RAPID_REQUEST_COUNT = 15  # Send 15 rapid requests to detect rate limiting


async def run_rate_limit_tests(
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
    endpoints: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Test for missing rate limiting. GLOBAL check — picks a representative
    endpoint and sends rapid requests.
    """
    findings: List[Dict[str, Any]] = []

    # Pick first GET endpoint as test target, or fall back to base_url
    test_path = "/"
    for ep in endpoints:
        if ep.get("method", "GET") == "GET":
            test_path = ep.get("path", "/")
            break

    url = build_url(base_url, test_path, query_params)
    merged_headers = {**auth_headers}
    ep_label = f"GET {test_path}"

    got_429 = False
    has_rate_headers = False
    last_evidence = None

    for i in range(RAPID_REQUEST_COUNT):
        resp, evidence = await execute_request("GET", url, headers=merged_headers)
        last_evidence = evidence
        if resp is None:
            continue

        # Check for rate limit response
        if resp.status_code == 429:
            got_429 = True
            break

        # Check for rate limit headers
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        if any(h in resp_headers_lower for h in RATE_LIMIT_HEADERS):
            has_rate_headers = True

    if not got_429 and not has_rate_headers and last_evidence:
        findings.append(make_finding(
            owasp_category=OWASP,
            title="No Rate Limiting Detected",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            endpoint=ep_label,
            description=f"Sent {RAPID_REQUEST_COUNT} rapid requests without receiving a 429 response or any rate-limit headers.",
            evidence=last_evidence,
            impact="Without rate limiting, the API is vulnerable to brute force attacks, credential stuffing, DoS, and resource exhaustion.",
            remediation="Implement rate limiting (e.g., 100 requests/minute per IP). Return 429 Too Many Requests with Retry-After header when limits are exceeded.",
            confidence="HIGH",
            references=[REF],
        ))
    elif has_rate_headers and not got_429:
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Rate Limit Headers Present But Not Enforced",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            endpoint=ep_label,
            description=f"Rate limit headers are present but the API did not return 429 after {RAPID_REQUEST_COUNT} rapid requests.",
            evidence=last_evidence,
            impact="Rate limiting may be misconfigured or set too high to be effective against automated attacks.",
            remediation="Ensure rate limits are enforced with appropriate thresholds. Return 429 when limits are exceeded.",
            confidence="MEDIUM",
            references=[REF],
        ))

    # ── Check auth endpoints specifically ─────────────────────────────
    auth_paths = ["/login", "/auth", "/token", "/signin", "/api/auth", "/api/login", "/api/token"]
    for auth_path in auth_paths:
        auth_url = build_url(base_url, auth_path)
        resp, _ = await execute_request("POST", auth_url, headers={"Content-Type": "application/json"},
                                        body={"username": "test", "password": "wrong"})
        if resp is None or resp.status_code in (404, 405):
            continue

        # Found an auth endpoint — test brute force protection
        got_lockout = False
        for i in range(15):
            resp, evidence = await execute_request(
                "POST", auth_url, headers={"Content-Type": "application/json"},
                body={"username": "admin", "password": f"wrong_password_{i}"},
            )
            if resp and resp.status_code == 429:
                got_lockout = True
                break

        if not got_lockout:
            findings.append(make_finding(
                owasp_category=OWASP,
                title=f"No Brute Force Protection on Auth Endpoint",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                endpoint=f"POST {auth_path}",
                description=f"The authentication endpoint {auth_path} allows 15+ failed login attempts without lockout or rate limiting.",
                evidence=evidence,
                impact="Attackers can brute-force user credentials without being blocked.",
                remediation="Implement account lockout after 5 failed attempts, progressive delays, or CAPTCHA on authentication endpoints.",
                references=[REF],
            ))
        break  # Only test first discovered auth endpoint

    return findings
