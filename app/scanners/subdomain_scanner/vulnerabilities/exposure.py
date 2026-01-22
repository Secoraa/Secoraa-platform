# app/scanners/subdomain_scanner/vulnerabilities/exposure.py

import requests
from typing import Dict, List

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/config",
    "/debug",
    "/admin",
    "/metrics",
    "/backup",
]


def check_exposure(subdomains: List[str]) -> Dict[str, List[str]]:
    """
    Detect exposed sensitive endpoints
    """
    findings = {}

    for subdomain in subdomains:
        exposed = []

        for scheme in ("https", "http"):
            base_url = f"{scheme}://{subdomain}"

            for path in SENSITIVE_PATHS:
                try:
                    url = base_url + path
                    response = requests.get(url, timeout=5)

                    if response.status_code in (200, 401, 403):
                        exposed.append(path)
                except Exception:
                    continue

        if exposed:
            findings[subdomain] = exposed

    return findings
