# app/scanners/subdomain_scanner/vulnerabilities/misconfig.py

import requests
from typing import Dict, List
from app.scanners.subdomain_scanner.vulnerabilities.cve_mapper import map_cves

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def check_misconfiguration(subdomains: List[str]) -> Dict[str, Dict]:
    """
    Detect common HTTP security misconfigurations
    """
    results = {}

    for subdomain in subdomains:
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                response = requests.get(url, timeout=5)

                missing_headers = [
                    h for h in SECURITY_HEADERS if h not in response.headers
                ]

                server = response.headers.get("Server", "Unknown")

                if missing_headers:
                    results[subdomain] = {
                        "missing_headers": missing_headers,
                        "server": server,
                        "cves": map_cves(server),
                    }
                break
            except Exception:
                continue

    return results
