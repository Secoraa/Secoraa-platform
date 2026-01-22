# app/scanners/subdomain_scanner/reporter/report.py

from typing import Dict

from app.scanners.subdomain_scanner.discovery.bruteforce import bruteforce_subdomains
from app.scanners.subdomain_scanner.discovery.passive import fetch_from_crtsh
from app.scanners.subdomain_scanner.validation.dns_check import validate_dns
from app.scanners.subdomain_scanner.validation.http_probe import probe_http

from app.scanners.subdomain_scanner.vulnerabilities.exposure import check_exposure
from app.scanners.subdomain_scanner.vulnerabilities.misconfig import check_misconfiguration
from app.scanners.subdomain_scanner.vulnerabilities.takeover import check_takeover

from app.scanners.subdomain_scanner.scoring.severity import (
    score_exposure,
    score_misconfig,
    score_takeover
)

def run_subdomain_scan(domain: str) -> Dict:
    """
    Full subdomain scan pipeline
    """

    # 1. Discovery
    brute = set(bruteforce_subdomains(domain))
    passive = fetch_from_crtsh(domain)

    discovered = list(brute.union(passive))

    # 2. DNS validation
    resolved = validate_dns(discovered)

    # 3. HTTP probing
    http_status = probe_http(resolved)

    exposure = check_exposure(resolved)
    misconfig = check_misconfiguration(resolved)
    takeover = check_takeover(resolved)

    return {
        "domain": domain,
        "resolved_subdomains": resolved,
        "http_status": http_status,
        "vulnerabilities": {
            "exposure": exposure,
            "misconfiguration": misconfig,
            "takeover": takeover,
        }
    }

