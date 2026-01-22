# app/scanners/subdomain_scanner/scan.py

from typing import List, Optional

from app.scanners.subdomain_scanner.discovery.bruteforce import bruteforce_subdomains
from app.scanners.subdomain_scanner.validation.dns_check import validate_dns
from app.scanners.subdomain_scanner.validation.http_probe import probe_http
from app.scanners.subdomain_scanner.vulnerabilities.exposure import check_exposure
from app.scanners.subdomain_scanner.vulnerabilities.misconfig import check_misconfiguration
from app.scanners.subdomain_scanner.vulnerabilities.takeover import check_takeover


def run_subdomain_scan(domain: str, subdomains: Optional[List[str]] = None) -> dict:
    """
    Runs full subdomain scan pipeline
    """

    discovered = list(subdomains) if subdomains else bruteforce_subdomains(domain)
    resolved = validate_dns(discovered)
    status_list = probe_http(resolved)
    http_status = {resolved[i]: status_list[i] for i in range(min(len(resolved), len(status_list)))}

    exposure = check_exposure(resolved)
    misconfig = check_misconfiguration(resolved)
    takeover = check_takeover(resolved)

    results = {}
    for sub in resolved:
        results[sub] = {
            "http_status": http_status.get(sub),
            "vulnerabilities": {
                "exposure": exposure.get(sub, []) if isinstance(exposure, dict) else [],
                "misconfiguration": misconfig.get(sub, {}) if isinstance(misconfig, dict) else {},
                "takeover": takeover.get(sub) if isinstance(takeover, dict) else None,
            },
        }

    return {
        "domain": domain,
        "input_subdomains": list(subdomains) if subdomains else None,
        "total_subdomains": len(resolved),
        "subdomains": results,  # per-subdomain findings
    }
