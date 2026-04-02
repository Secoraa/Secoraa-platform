from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "API8:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"

# Patterns that indicate stack trace / error leakage
STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call",
    r"at [\w.]+\([\w]+\.java:\d+\)",
    r"at .+\.js:\d+:\d+",
    r"File \"[/\\].*\.py\", line \d+",
    r"Exception in thread",
    r"System\.NullReferenceException",
    r"TypeError:.*is not",
    r"ReferenceError:",
    r"SyntaxError:",
    r"Internal Server Error",
]

PRIVATE_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

FILE_PATH_PATTERN = re.compile(
    r"(/var/www/|/home/\w+/|/usr/local/|/app/|/opt/|/etc/|C:\\\\|[A-Z]:\\\\Users\\\\)"
)


async def run_info_disclosure_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Check for information disclosure in error responses."""
    findings: List[Dict[str, Any]] = []
    path = endpoint.get("path", "")
    method = endpoint.get("method", "GET")
    ep_label = f"{method} {path}"
    url = build_url(base_url, path, query_params)

    # Trigger error responses with malformed requests
    test_cases = [
        # Bad JSON body
        ("POST", url, {**auth_headers, "Content-Type": "application/json"}, "{{INVALID JSON}}"),
        # Wrong content type
        (method, url, {**auth_headers, "Content-Type": "text/xml"}, None),
    ]

    for test_method, test_url, test_headers, raw_body in test_cases:
        if raw_body:
            # Send raw string body to trigger parse errors
            resp, evidence = await execute_request(test_method, test_url, headers=test_headers, body={"__raw_trigger__": raw_body})
        else:
            resp, evidence = await execute_request(test_method, test_url, headers=test_headers)

        if resp is None:
            continue

        body = resp.text or ""

        # ── Stack trace detection ─────────────────────────────────────
        for pattern in STACK_TRACE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title="Stack Trace in Error Response",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    endpoint=ep_label,
                    description="The API returns stack traces or detailed error information in error responses, revealing internal implementation details.",
                    evidence=evidence,
                    impact="Attackers can learn internal file paths, library versions, database structure, and application logic from stack traces.",
                    remediation="Return generic error messages to clients. Log detailed errors server-side only. Use a global error handler that strips internal details.",
                    references=[REF],
                ))
                break  # one finding per endpoint

        # ── Internal IP disclosure ────────────────────────────────────
        ip_matches = PRIVATE_IP_PATTERN.findall(body)
        if ip_matches:
            findings.append(make_finding(
                owasp_category=OWASP,
                title="Internal IP Address Disclosed",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                endpoint=ep_label,
                description=f"The response contains internal/private IP addresses: {', '.join(set(ip_matches[:3]))}",
                evidence=evidence,
                impact="Internal network topology exposed. Attackers can map internal infrastructure for targeted attacks.",
                remediation="Strip internal IP addresses from all responses. Use reverse proxies to mask backend IPs.",
                confidence="MEDIUM",
                references=[REF],
            ))

        # ── File path disclosure ──────────────────────────────────────
        path_matches = FILE_PATH_PATTERN.findall(body)
        if path_matches:
            findings.append(make_finding(
                owasp_category=OWASP,
                title="Internal File Path Disclosed",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                endpoint=ep_label,
                description=f"The response exposes internal file system paths: {', '.join(set(path_matches[:3]))}",
                evidence=evidence,
                impact="Attackers learn the server's directory structure, OS type, and deployment paths — useful for path traversal and targeted exploits.",
                remediation="Ensure error handlers do not include file paths in responses. Sanitize all error output.",
                confidence="MEDIUM",
                references=[REF],
            ))

    return findings
