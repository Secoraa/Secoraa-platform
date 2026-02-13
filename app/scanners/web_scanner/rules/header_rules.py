from typing import List, Dict


MISSING_HEADER_RULES = {
    "content-security-policy": "headersContentSecurityPolicy",
    "strict-transport-security": "headersStrictTransportSecurity",
    "x-frame-options": "clickjacking",
    "x-content-type-options": "headersXContentType",
    "referrer-policy": "headerReferrerPolicy",
    "permissions-policy": "headerPermissionsPolicy",
    "x-xss-protection": "xXssProtection",
}


def evaluate_headers(detected_headers: Dict[str, str]) -> List[str]:
    findings = []
    for header, vuln_key in MISSING_HEADER_RULES.items():
        if not detected_headers.get(header):
            findings.append(vuln_key)
    return findings
