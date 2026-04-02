from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanners.api_scanner.engine.payload_encoder import encode_for_context
from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "Injection"
REF = "https://portswigger.net/web-security/server-side-template-injection"
CVSS_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Template injection probes — each with a math expression and expected result
SSTI_PROBES = [
    ("{{7*7}}", "49"),            # Jinja2, Twig, Nunjucks
    ("${7*7}", "49"),             # Freemarker, Velocity, Mako
    ("<%= 7*7 %>", "49"),         # ERB (Ruby), EJS
    ("#{7*7}", "49"),             # Slim, Pug
    ("{{7*'7'}}", "7777777"),     # Jinja2 string multiplication
]

# Polyglot probe that triggers errors in most template engines
POLYGLOT = "${{<%[%'\"}}%\\"

# Template engine error signatures
ENGINE_SIGNATURES = [
    "jinja2", "twig", "freemarker", "velocity", "thymeleaf",
    "mako", "django.template", "nunjucks", "handlebars",
    "templateerror", "templatesyntaxerror", "undefined variable",
]


async def run_ssti_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Test for server-side template injection in string parameters and body fields."""
    findings: List[Dict[str, Any]] = []
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    ep_label = f"{method} {path}"
    url = build_url(base_url, path, query_params)
    merged_headers = {**auth_headers, "Content-Type": "application/json"}

    # Collect string injection targets
    targets: List[Dict[str, str]] = []

    for p in endpoint.get("parameters", []):
        if p.get("in") == "query" and p.get("type", "string") == "string":
            targets.append({"location": "query", "name": p.get("name", "")})

    if method in ("POST", "PUT", "PATCH"):
        for field in (endpoint.get("body") or {}):
            targets.append({"location": "body", "name": field})

    if not targets:
        return findings

    for target in targets[:3]:  # Limit scope
        # ── Math-based detection ──────────────────────────────────────
        for probe, expected in SSTI_PROBES:
            ctx_type = "query" if target["location"] == "query" else "body"
            for encoded_probe, enc_desc in encode_for_context(probe, ctx_type, max_variants=3):
                if target["location"] == "query":
                    test_params = {**query_params, target["name"]: encoded_probe}
                    test_url = build_url(base_url, path, test_params)
                    resp, evidence = await execute_request(method, test_url, headers=merged_headers)
                else:
                    test_body = dict(endpoint.get("body") or {})
                    test_body[target["name"]] = encoded_probe
                    resp, evidence = await execute_request(method, url, headers=merged_headers, body=test_body)

                if resp is None:
                    continue

                if expected in (resp.text or ""):
                    findings.append(make_finding(
                        owasp_category=OWASP,
                        title=f"Server-Side Template Injection — {target['location']}: {target['name']}",
                        cvss_vector=CVSS_VEC,
                        endpoint=ep_label,
                        description=f"Template expression '{probe}' ({enc_desc}) was evaluated to '{expected}', confirming server-side template injection.",
                        evidence=evidence,
                        impact="Full remote code execution. Attacker can read files, execute commands, and take complete control of the server.",
                        remediation="Never pass user input directly into template rendering. Use parameterized templates. Sandbox template engines if dynamic rendering is required.",
                        references=[REF],
                    ))
                    return findings  # Critical — one proof is enough

        # ── Polyglot error detection ──────────────────────────────────
        if target["location"] == "query":
            test_params = {**query_params, target["name"]: POLYGLOT}
            test_url = build_url(base_url, path, test_params)
            resp, evidence = await execute_request(method, test_url, headers=merged_headers)
        else:
            test_body = dict(endpoint.get("body") or {})
            test_body[target["name"]] = POLYGLOT
            resp, evidence = await execute_request(method, url, headers=merged_headers, body=test_body)

        if resp is not None:
            body_lower = (resp.text or "").lower()
            for sig in ENGINE_SIGNATURES:
                if sig in body_lower:
                    findings.append(make_finding(
                        owasp_category=OWASP,
                        title=f"Template Engine Detected — {target['location']}: {target['name']}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        endpoint=ep_label,
                        description=f"Polyglot template probe triggered an error revealing template engine '{sig}'. This strongly suggests the parameter is rendered in a template context.",
                        evidence=evidence,
                        impact="Potential remote code execution via server-side template injection.",
                        remediation="Never pass raw user input into template engines. Use proper escaping and parameterization.",
                        confidence="MEDIUM",
                        references=[REF],
                    ))
                    return findings

    return findings
