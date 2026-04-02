from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "API8:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "impact": "Without HSTS, connections can be downgraded from HTTPS to HTTP via man-in-the-middle attacks.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "X-Content-Type-Options": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "impact": "Browser may MIME-sniff responses and execute content as a different type than declared.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "impact": "The page can be embedded in iframes, enabling clickjacking attacks.",
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing is required)",
    },
    "Content-Security-Policy": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "impact": "Without CSP, the application is more vulnerable to XSS and data injection attacks.",
        "remediation": "Add a Content-Security-Policy header with appropriate directives for your application.",
    },
    "Cache-Control": {
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "impact": "Sensitive API responses may be cached by browsers or proxies, exposing data to other users.",
        "remediation": "Add header: Cache-Control: no-store, no-cache for sensitive endpoints.",
    },
    "Referrer-Policy": {
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "impact": "Full URLs including query parameters may leak to third parties via the Referer header.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
}


async def run_headers_tests(
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    Check for missing security headers. This is a GLOBAL check — run once per scan,
    not per endpoint, to avoid duplicate findings.
    """
    findings: List[Dict[str, Any]] = []
    merged_headers = {**auth_headers}

    resp, evidence = await execute_request("GET", base_url, headers=merged_headers)
    if resp is None:
        return findings

    response_headers = {k.lower(): v for k, v in resp.headers.items()}

    for header_name, info in REQUIRED_HEADERS.items():
        if header_name.lower() not in response_headers:
            findings.append(make_finding(
                owasp_category=OWASP,
                title=f"Missing Security Header: {header_name}",
                cvss_vector=info["cvss"],
                endpoint=f"GET {base_url}",
                description=f"The response is missing the {header_name} security header.",
                evidence=evidence,
                impact=info["impact"],
                remediation=info["remediation"],
                confidence="HIGH",
                references=[REF],
            ))

    # ── Check for version disclosure headers ──────────────────────────
    server_header = response_headers.get("server", "")
    if server_header and any(c.isdigit() for c in server_header):
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Server Version Disclosure",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            endpoint=f"GET {base_url}",
            description=f"The Server header discloses version information: '{server_header}'.",
            evidence=evidence,
            impact="Attackers can identify the exact server software and version to search for known vulnerabilities.",
            remediation="Remove or generalize the Server header. Do not include version numbers.",
            confidence="HIGH",
            references=[REF],
        ))

    powered_by = response_headers.get("x-powered-by", "")
    if powered_by:
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Technology Disclosure via X-Powered-By",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            endpoint=f"GET {base_url}",
            description=f"The X-Powered-By header exposes the backend technology: '{powered_by}'.",
            evidence=evidence,
            impact="Attackers can fingerprint the technology stack and target known framework-specific vulnerabilities.",
            remediation="Remove the X-Powered-By header entirely.",
            confidence="HIGH",
            references=[REF],
        ))

    return findings
