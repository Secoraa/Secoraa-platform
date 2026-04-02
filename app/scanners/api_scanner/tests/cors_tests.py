from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.engine.scan_context import ScanContext
from app.scanners.api_scanner.tests import make_finding

logger = logging.getLogger(__name__)

OWASP = "API8:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"


async def run_cors_tests(
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    CORS misconfiguration checks. GLOBAL check — run once per scan.
    """
    findings: List[Dict[str, Any]] = []
    ctx = ScanContext()

    # ── 1. Arbitrary origin reflection ────────────────────────────────
    evil_origin = ctx.evil_origin
    test_headers = {**auth_headers, "Origin": evil_origin}
    resp, evidence = await execute_request("GET", base_url, headers=test_headers)

    if resp is not None:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            findings.append(make_finding(
                owasp_category=OWASP,
                title="CORS Allows Any Origin (Wildcard)",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                endpoint=f"GET {base_url}",
                description="The API returns Access-Control-Allow-Origin: * allowing any website to make cross-origin requests.",
                evidence=evidence,
                impact="Any malicious website can read responses from this API, potentially stealing sensitive data.",
                remediation="Restrict CORS to trusted origins only. Replace the wildcard with a whitelist of allowed domains.",
                references=[REF],
            ))

            if acac == "true":
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title="CORS Wildcard with Credentials",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    endpoint=f"GET {base_url}",
                    description="The API allows CORS from any origin AND allows credentials. This is the most dangerous CORS misconfiguration.",
                    evidence=evidence,
                    impact="Malicious websites can make authenticated cross-origin requests and steal user data including session tokens.",
                    remediation="Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use an explicit origin whitelist.",
                    references=[REF],
                ))

        elif acao == evil_origin:
            findings.append(make_finding(
                owasp_category=OWASP,
                title="CORS Reflects Arbitrary Origin",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                endpoint=f"GET {base_url}",
                description=f"The API echoes back the Origin header value ({evil_origin}) in Access-Control-Allow-Origin, allowing any website to be trusted.",
                evidence=evidence,
                impact="Any website can make cross-origin requests by setting its own Origin header. Combined with credentials, this allows full account takeover.",
                remediation="Do not reflect the Origin header. Maintain a whitelist of trusted origins and only allow those.",
                references=[REF],
            ))

    # ── 2. Null origin ────────────────────────────────────────────────
    null_headers = {**auth_headers, "Origin": "null"}
    resp, evidence = await execute_request("GET", base_url, headers=null_headers)
    if resp is not None:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "null":
            findings.append(make_finding(
                owasp_category=OWASP,
                title="CORS Allows Null Origin",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                endpoint=f"GET {base_url}",
                description="The API allows the 'null' origin, which can be triggered from sandboxed iframes and local file:// pages.",
                evidence=evidence,
                impact="Attackers can craft requests from sandboxed iframes that are treated as trusted by the API.",
                remediation="Do not allow 'null' as a valid origin in CORS configuration.",
                confidence="MEDIUM",
                references=[REF],
            ))

    return findings
