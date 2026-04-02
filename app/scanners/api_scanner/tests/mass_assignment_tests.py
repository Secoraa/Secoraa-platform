from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "API3:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
CVSS_VEC = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"

# Fields to inject — privilege escalation + value manipulation
INJECTION_FIELDS = {
    # Privilege escalation
    "role": "admin",
    "is_admin": True,
    "admin": True,
    "permissions": ["*"],
    "user_type": "admin",
    "access_level": 999,
    # Status manipulation
    "verified": True,
    "email_verified": True,
    "active": True,
    "approved": True,
    "banned": False,
    # Value manipulation
    "balance": 99999,
    "credit": 99999,
    "discount": 100,
    "price": 0,
}


async def run_mass_assignment_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Test for mass assignment on POST/PUT/PATCH endpoints."""
    findings: List[Dict[str, Any]] = []
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    ep_label = f"{method} {path}"

    if method not in ("POST", "PUT", "PATCH"):
        return findings

    url = build_url(base_url, path, query_params)
    merged_headers = {**auth_headers, "Content-Type": "application/json"}

    # Get baseline with normal body
    normal_body = endpoint.get("body") or {"test": "value"}

    baseline_resp, _ = await execute_request(method, url, headers=merged_headers, body=normal_body)
    if baseline_resp is None:
        return findings

    baseline_body = baseline_resp.text or ""

    # Inject extra fields into the body
    injected_body = dict(normal_body)
    injected_body.update(INJECTION_FIELDS)

    resp, evidence = await execute_request(method, url, headers=merged_headers, body=injected_body)
    if resp is None or resp.status_code not in (200, 201):
        return findings

    resp_text = (resp.text or "").lower()

    # Check if any injected fields are reflected in the response
    reflected_fields = []
    for field, value in INJECTION_FIELDS.items():
        str_value = str(value).lower()
        if field.lower() in resp_text and str_value in resp_text:
            reflected_fields.append(field)

    if reflected_fields:
        # Privilege escalation fields are more critical
        priv_fields = [f for f in reflected_fields if f in ("role", "is_admin", "admin", "permissions", "user_type", "access_level")]

        if priv_fields:
            findings.append(make_finding(
                owasp_category=OWASP,
                title=f"Mass Assignment — Privilege Escalation",
                cvss_vector=CVSS_VEC,
                endpoint=ep_label,
                description=f"The endpoint accepted and reflected privilege escalation fields: {', '.join(priv_fields)}. These were not in the original request schema but were processed by the server.",
                evidence=evidence,
                impact="Attackers can escalate privileges by injecting admin/role fields into create or update requests.",
                remediation="Use a whitelist of allowed fields for each endpoint. Reject unknown fields. Never bind raw request bodies to internal models.",
                references=[REF],
            ))

        value_fields = [f for f in reflected_fields if f not in priv_fields]
        if value_fields:
            findings.append(make_finding(
                owasp_category=OWASP,
                title=f"Mass Assignment — Field Injection",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
                endpoint=ep_label,
                description=f"The endpoint accepted and reflected injected fields: {', '.join(value_fields)}. These were not in the original request schema.",
                evidence=evidence,
                impact="Attackers can manipulate account status, balances, or other business-critical values by injecting extra fields.",
                remediation="Use DTOs or serializers that explicitly define allowed fields. Reject unknown fields in the request body.",
                confidence="MEDIUM",
                references=[REF],
            ))

    return findings
