from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanners.api_scanner.engine.oob_server import OOBTracker
from app.scanners.api_scanner.engine.oob_tokens import ssrf_oob_payloads
from app.scanners.api_scanner.engine.payload_encoder import encode_for_context
from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.engine.scan_context import ScanContext
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "API7:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"

# Parameter names that typically accept URLs
URL_PARAM_NAMES = {
    "url", "uri", "href", "src", "link", "callback", "redirect",
    "redirect_url", "redirect_uri", "return_url", "next", "next_url",
    "dest", "destination", "target", "endpoint", "webhook",
    "webhook_url", "path", "file", "page", "site", "feed",
}

# SSRF test probes — covers localhost variants, cloud metadata, protocol handlers, port scanning
SSRF_PROBES = [
    {
        "payload": "http://127.0.0.1",
        "title": "SSRF — Localhost Access",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "description": "The API fetches content from 127.0.0.1 (localhost).",
    },
    {
        "payload": "http://0.0.0.0",
        "title": "SSRF — 0.0.0.0 Access",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "description": "The API fetches content from 0.0.0.0, which resolves to localhost on some systems.",
    },
    {
        "payload": "http://localhost",
        "title": "SSRF — Localhost Hostname",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "description": "The API fetches content using 'localhost' hostname, bypassing IP-based blocklists.",
    },
    {
        "payload": "http://2130706433",
        "title": "SSRF — Decimal IP (127.0.0.1)",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "description": "The API fetches content from decimal representation of 127.0.0.1, bypassing regex blocklists.",
    },
    {
        "payload": "http://0x7f000001",
        "title": "SSRF — Hex IP (127.0.0.1)",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "description": "The API fetches content from hex representation of 127.0.0.1, bypassing string-based blocklists.",
    },
    {
        "payload": "http://169.254.169.254/latest/meta-data/",
        "title": "SSRF — AWS Metadata (IMDSv1)",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "description": "The API fetches from AWS metadata endpoint (169.254.169.254), exposing IAM credentials.",
    },
    {
        "payload": "http://169.254.169.254/latest/api/token",
        "title": "SSRF — AWS Metadata (IMDSv2 Token)",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "description": "The API accesses the IMDSv2 token endpoint for temporary AWS credentials.",
    },
    {
        "payload": "http://metadata.google.internal/computeMetadata/v1/",
        "title": "SSRF — GCP Metadata",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "description": "The API fetches from GCP metadata endpoint, exposing service account tokens.",
    },
    {
        "payload": "http://169.254.169.254/metadata/v1/",
        "title": "SSRF — Azure/DigitalOcean Metadata",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "description": "The API fetches from the cloud metadata endpoint used by Azure and DigitalOcean.",
    },
    {
        "payload": "http://[::1]",
        "title": "SSRF — IPv6 Localhost",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "description": "The API fetches from IPv6 localhost (::1), bypassing IPv4 blocklists.",
    },
    {
        "payload": "file:///etc/passwd",
        "title": "SSRF — Local File Read (file://)",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "description": "The API processes file:// protocol URLs, enabling local file reading.",
    },
    {
        "payload": "http://127.0.0.1:22",
        "title": "SSRF — Internal Port Scan (SSH)",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",
        "description": "The API connects to internal port 22 (SSH), enabling port scanning via SSRF.",
    },
    {
        "payload": "http://127.0.0.1:6379",
        "title": "SSRF — Internal Service (Redis)",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "description": "The API connects to internal Redis (port 6379), potentially allowing data theft.",
    },
]

# Baseline URL is now generated dynamically per-scan via ScanContext


async def run_ssrf_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
    oob_tracker: Optional[OOBTracker] = None,
) -> List[Dict[str, Any]]:
    """Test for SSRF on parameters that accept URL values."""
    findings: List[Dict[str, Any]] = []
    ctx = ScanContext()
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    ep_label = f"{method} {path}"
    url = build_url(base_url, path, query_params)
    merged_headers = {**auth_headers, "Content-Type": "application/json"}

    # Find URL-accepting parameters
    url_targets: List[Dict[str, str]] = []

    for p in endpoint.get("parameters", []):
        pname = p.get("name", "").lower()
        if pname in URL_PARAM_NAMES:
            url_targets.append({"location": p.get("in", "query"), "name": p.get("name", "")})

    if method in ("POST", "PUT", "PATCH"):
        for field in (endpoint.get("body") or {}):
            if field.lower() in URL_PARAM_NAMES:
                url_targets.append({"location": "body", "name": field})

    if not url_targets:
        return findings

    # Get baseline response with invalid URL
    for target in url_targets[:3]:
        # Get baseline (invalid URL)
        if target["location"] in ("query", "path"):
            baseline_params = {**query_params, target["name"]: ctx.baseline_domain}
            baseline_test_url = build_url(base_url, path, baseline_params)
            baseline_resp, _ = await execute_request(method, baseline_test_url, headers=merged_headers)
        else:
            baseline_body = dict(endpoint.get("body") or {})
            baseline_body[target["name"]] = ctx.baseline_domain
            baseline_resp, _ = await execute_request(method, url, headers=merged_headers, body=baseline_body)

        baseline_len = len(baseline_resp.text) if baseline_resp and baseline_resp.text else 0
        baseline_status = baseline_resp.status_code if baseline_resp else 0

        # Test each SSRF probe (with encoded variants for WAF bypass)
        for probe in SSRF_PROBES:
            ctx_type = "query" if target["location"] in ("query", "path") else "body"
            for encoded_payload, enc_desc in encode_for_context(probe["payload"], ctx_type, max_variants=2):
                if target["location"] in ("query", "path"):
                    test_params = {**query_params, target["name"]: encoded_payload}
                    test_url = build_url(base_url, path, test_params)
                    resp, evidence = await execute_request(method, test_url, headers=merged_headers)
                else:
                    test_body = dict(endpoint.get("body") or {})
                    test_body[target["name"]] = encoded_payload
                    resp, evidence = await execute_request(method, url, headers=merged_headers, body=test_body)

                if resp is None:
                    continue

                # Detection: response differs significantly from baseline (different status or much more content)
                resp_len = len(resp.text) if resp.text else 0
                is_different_status = resp.status_code != baseline_status and resp.status_code == 200
                is_more_content = baseline_len > 0 and resp_len > baseline_len * 2
                has_metadata = any(kw in (resp.text or "").lower() for kw in [
                    "ami-id", "instance-id", "iam", "security-credentials",
                    "root:x:0:0", "daemon:x:", "computemetadata",
                ])

                if has_metadata or is_different_status or is_more_content:
                    confidence = "HIGH" if has_metadata else "MEDIUM"
                    findings.append(make_finding(
                        owasp_category=OWASP,
                        title=f"{probe['title']} — {target['location']}: {target['name']}",
                        cvss_vector=probe["cvss"],
                        endpoint=ep_label,
                        description=probe["description"],
                        evidence=evidence,
                        impact="Server-side request forgery allows attackers to access internal services, cloud metadata, and local files from the server.",
                        remediation="Validate and sanitize all user-supplied URLs. Block internal IPs (127.0.0.1, 169.254.x.x, 10.x.x.x, etc.), private ranges, and non-HTTP protocols (file://, gopher://). Use an allowlist of permitted domains.",
                        confidence=confidence,
                        references=[REF],
                    ))
                    break  # One SSRF proof per target is enough

    # ── OOB SSRF probes ──────────────────────────────────────────────
    if oob_tracker and oob_tracker.enabled:
        for target in url_targets[:3]:
            callback_url = oob_tracker.generate_payload_url(
                "ssrf", ep_label, f"SSRF OOB via {target['name']}"
            )
            oob_payloads = ssrf_oob_payloads(callback_url)
            for payload, desc in oob_payloads:
                if target["location"] in ("query", "path"):
                    test_params = {**query_params, target["name"]: payload}
                    test_url = build_url(base_url, path, test_params)
                    await execute_request(method, test_url, headers=merged_headers)
                else:
                    test_body = dict(endpoint.get("body") or {})
                    test_body[target["name"]] = payload
                    await execute_request(method, url, headers=merged_headers, body=test_body)
                logger.debug("OOB SSRF probe sent: %s — %s", target["name"], desc)

    return findings
