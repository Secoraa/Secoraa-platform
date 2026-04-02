from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "API9:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"

VERSION_PATTERN = re.compile(r"/v(\d+)/")

ALTERNATE_VERSIONS = ["v0", "v1", "v2", "v3", "v4"]
ALTERNATE_PREFIXES = ["api/old", "api/beta", "api/test", "api/dev", "api/staging"]


async def run_version_discovery_tests(
    endpoints: List[Dict[str, Any]],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    Discover old/alternate API versions. GLOBAL check — analyzes endpoint
    paths for version segments and probes alternatives.
    """
    findings: List[Dict[str, Any]] = []
    merged_headers = {**auth_headers}
    tested_paths: set = set()

    # ── 1. Find versioned endpoints and try older versions ────────────
    for endpoint in endpoints:
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        match = VERSION_PATTERN.search(path)
        if not match:
            continue

        current_version = f"v{match.group(1)}"

        for alt_version in ALTERNATE_VERSIONS:
            if alt_version == current_version:
                continue

            alt_path = path.replace(f"/{current_version}/", f"/{alt_version}/")
            if alt_path in tested_paths:
                continue
            tested_paths.add(alt_path)

            url = build_url(base_url, alt_path, query_params)
            resp, evidence = await execute_request(method, url, headers=merged_headers)

            if resp is not None and resp.status_code == 200 and len(resp.text or "") > 2:
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title=f"Old API Version Accessible — {alt_version}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    endpoint=f"{method} {alt_path}",
                    description=f"The old API version '{alt_version}' (path: {alt_path}) is still accessible. Current version is '{current_version}'. Old versions may lack security controls added in newer versions.",
                    evidence=evidence,
                    impact="Deprecated API versions may have weaker authentication, missing rate limiting, or known vulnerabilities that were fixed in newer versions.",
                    remediation=f"Decommission old API version '{alt_version}'. If backward compatibility is needed, ensure all security controls from '{current_version}' are backported.",
                    confidence="MEDIUM",
                    references=[REF],
                ))

    # ── 2. Probe alternate prefixes ───────────────────────────────────
    sample_path = ""
    for ep in endpoints:
        p = ep.get("path", "")
        # Strip version prefix to get the resource path
        stripped = VERSION_PATTERN.sub("/", p)
        if stripped and stripped != "/":
            sample_path = stripped
            break

    if sample_path:
        for prefix in ALTERNATE_PREFIXES:
            test_path = f"/{prefix}{sample_path}"
            if test_path in tested_paths:
                continue
            tested_paths.add(test_path)

            url = build_url(base_url, test_path)
            resp, evidence = await execute_request("GET", url, headers=merged_headers)

            if resp is not None and resp.status_code == 200 and len(resp.text or "") > 2:
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title=f"Alternate API Path Accessible — /{prefix}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    endpoint=f"GET {test_path}",
                    description=f"An alternate API path '/{prefix}' is accessible. This may expose development, staging, or legacy endpoints in production.",
                    evidence=evidence,
                    impact="Development or staging APIs may have weaker security controls, verbose error messages, or test data accessible in production.",
                    remediation=f"Remove or restrict access to the '/{prefix}' path in production. Use network-level controls to isolate non-production environments.",
                    confidence="MEDIUM",
                    references=[REF],
                ))

    return findings
