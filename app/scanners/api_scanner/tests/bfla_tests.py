from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.engine.response_differ import compare_responses, responses_are_same
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP_BFLA = "API5:2023"
OWASP_INVENTORY = "API9:2023"
REF_BFLA = "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"
REF_INVENTORY = "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]

# Admin/debug paths to probe
ADMIN_PATHS = [
    "/admin", "/admin/", "/internal", "/manage", "/management",
    "/superuser", "/staff", "/debug", "/debug/",
]

DEBUG_PATHS = [
    "/health", "/status", "/metrics", "/actuator", "/actuator/env",
    "/env", "/info", "/.env", "/swagger", "/swagger-ui",
    "/api-docs", "/graphql", "/__debug__", "/phpinfo", "/server-status",
    "/wp-admin", "/elmah.axd",
]


async def run_bfla_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
    secondary_auth_headers: Optional[Dict[str, str]] = None,
    secondary_query_params: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Test for function-level authorization bypass via method tampering,
    privilege escalation (two-token), and unauthenticated function access."""
    findings: List[Dict[str, Any]] = []
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    ep_label = f"{method} {path}"
    body = endpoint.get("body")
    merged_headers = {**auth_headers}

    # ── 1. HTTP Method Tampering ──────────────────────────────────────
    # Try destructive methods on GET endpoints
    if method == "GET":
        for test_method in ("DELETE", "PUT", "PATCH"):
            url = build_url(base_url, path, query_params)
            req_body = body if test_method in ("PUT", "PATCH") else None
            resp, evidence = await execute_request(
                test_method, url, headers=merged_headers, body=req_body,
            )

            if (
                resp is not None
                and resp.status_code == 200
                and len(resp.text or "") > 2
            ):
                findings.append(make_finding(
                    owasp_category=OWASP_BFLA,
                    title=f"HTTP Method Tampering — {test_method} Accepted on GET Endpoint",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
                    endpoint=ep_label,
                    description=(
                        f"The endpoint accepts {test_method} requests even though "
                        f"it is documented as a {method} endpoint. This may allow "
                        f"unauthorized data modification or deletion."
                    ),
                    evidence=evidence,
                    impact=(
                        f"Users with read-only access may be able to "
                        f"{test_method.lower()} resources by changing the HTTP method."
                    ),
                    remediation=(
                        f"Explicitly reject unsupported HTTP methods with "
                        f"405 Method Not Allowed. Only allow {method} for this endpoint."
                    ),
                    confidence="MEDIUM",
                    references=[REF_BFLA],
                ))
                break  # One method tampering finding per endpoint

    # ── 2. Privilege Escalation (two-token) ───────────────────────────
    if secondary_auth_headers is not None:
        url_primary = build_url(base_url, path, query_params)
        sec_qp = secondary_query_params if secondary_query_params is not None else query_params
        url_secondary = build_url(base_url, path, sec_qp)
        req_body = body if method in ("POST", "PUT", "PATCH") else None

        # Baseline: request with primary (high-priv) auth
        primary_resp, primary_evidence = await execute_request(
            method, url_primary, headers={**auth_headers}, body=req_body,
        )

        if primary_resp is not None and primary_resp.status_code == 200:
            # Test: same request with secondary (low-priv) auth
            secondary_resp, secondary_evidence = await execute_request(
                method, url_secondary, headers={**secondary_auth_headers}, body=req_body,
            )

            if secondary_resp is not None and secondary_resp.status_code == 200:
                if responses_are_same(primary_resp, secondary_resp):
                    # Low-priv user got the same response as high-priv user
                    is_write = method in WRITE_METHODS
                    title_action = "Write" if is_write else "Read"
                    findings.append(make_finding(
                        owasp_category=OWASP_BFLA,
                        title=f"Privilege Escalation — {title_action} Access via Low-Privilege Token on {method} {path}",
                        cvss_vector=(
                            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
                            if is_write
                            else "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
                        ),
                        endpoint=ep_label,
                        description=(
                            f"A low-privilege token can access the {method} {path} "
                            f"endpoint and receives the same response as a high-privilege "
                            f"token. This indicates broken function-level authorization."
                        ),
                        evidence={
                            "primary": primary_evidence,
                            "secondary": secondary_evidence,
                        },
                        impact=(
                            f"A low-privilege user can perform {method} operations on "
                            f"this endpoint, potentially accessing or modifying data "
                            f"restricted to higher-privilege roles."
                        ),
                        remediation=(
                            "Implement role-based access control (RBAC) that validates "
                            "the user's privilege level for each function. Deny access "
                            "to privileged endpoints for low-privilege tokens."
                        ),
                        confidence="HIGH",
                        references=[REF_BFLA],
                    ))

    # ── 3. Unauthenticated Function Access ────────────────────────────
    # For write endpoints, test if the endpoint is accessible without auth
    if method in WRITE_METHODS:
        url = build_url(base_url, path, query_params)
        req_body = body if method in ("POST", "PUT", "PATCH") else None

        # Baseline: authenticated request
        auth_resp, auth_evidence = await execute_request(
            method, url, headers=merged_headers, body=req_body,
        )

        if auth_resp is not None and auth_resp.status_code == 200:
            # Test: same request without authentication
            noauth_resp, noauth_evidence = await execute_request(
                method, url, headers=None, body=req_body,
            )

            if (
                noauth_resp is not None
                and noauth_resp.status_code == 200
                and responses_are_same(auth_resp, noauth_resp)
            ):
                findings.append(make_finding(
                    owasp_category=OWASP_BFLA,
                    title=f"Unauthenticated {method} Access — {path}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
                    endpoint=ep_label,
                    description=(
                        f"The write endpoint {method} {path} is accessible without "
                        f"any authentication and returns the same response as an "
                        f"authenticated request. This indicates missing authentication "
                        f"enforcement on a state-changing operation."
                    ),
                    evidence={
                        "authenticated": auth_evidence,
                        "unauthenticated": noauth_evidence,
                    },
                    impact=(
                        f"An unauthenticated attacker can perform {method} operations, "
                        f"potentially modifying or deleting data without any credentials."
                    ),
                    remediation=(
                        "Require authentication for all write endpoints. Reject "
                        "unauthenticated requests with 401 Unauthorized."
                    ),
                    confidence="HIGH",
                    references=[REF_BFLA],
                ))

    return findings


async def run_admin_path_tests(
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    Probe for exposed admin and debug endpoints. GLOBAL check — run once per scan.
    """
    findings: List[Dict[str, Any]] = []
    merged_headers = {**auth_headers}

    # ── Admin endpoints ───────────────────────────────────────────────
    for admin_path in ADMIN_PATHS:
        url = build_url(base_url, admin_path)
        resp, evidence = await execute_request("GET", url, headers=merged_headers)
        if resp is not None and resp.status_code == 200 and len(resp.text or "") > 10:
            findings.append(make_finding(
                owasp_category=OWASP_BFLA,
                title=f"Admin Endpoint Accessible — {admin_path}",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                endpoint=f"GET {admin_path}",
                description=f"The admin/internal endpoint '{admin_path}' is accessible. This may allow privilege escalation.",
                evidence=evidence,
                impact="Non-admin users may access administrative functions, leading to privilege escalation and data breach.",
                remediation="Restrict admin endpoints to admin roles only. Implement strict role-based access control (RBAC).",
                confidence="MEDIUM",
                references=[REF_BFLA],
            ))

    # ── Debug / info endpoints ────────────────────────────────────────
    for debug_path in DEBUG_PATHS:
        url = build_url(base_url, debug_path)
        resp, evidence = await execute_request("GET", url)  # No auth — these shouldn't be public
        if resp is not None and resp.status_code == 200 and len(resp.text or "") > 10:
            findings.append(make_finding(
                owasp_category=OWASP_INVENTORY,
                title=f"Debug/Info Endpoint Exposed — {debug_path}",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                endpoint=f"GET {debug_path}",
                description=f"The debug/info endpoint '{debug_path}' is publicly accessible without authentication.",
                evidence=evidence,
                impact="Internal application details, environment variables, or configuration data may be exposed to attackers.",
                remediation="Disable debug endpoints in production. If health/status endpoints are needed, restrict them to internal networks or require authentication.",
                confidence="HIGH" if debug_path in ("/.env", "/actuator/env", "/env", "/__debug__") else "MEDIUM",
                references=[REF_INVENTORY],
            ))

    return findings
