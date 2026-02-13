from typing import List, Optional

from app.scanners.base import BaseScanner
from app.scanners.web_scanner.scanner import run_scan


class SubdomainScanner(BaseScanner):
    """
    Subdomain scan runner that plugs into `/scans/` so it shows up in Scan History.

    Expected payload:
      - domain: str
      - subdomains: Optional[List[str]]  (selected subdomains)
    """

    name = "subdomain"

    def run(self, payload: dict) -> dict:
        domain = (payload.get("domain") or "").strip()
        subdomains = payload.get("subdomains")
        if not domain:
            raise ValueError("domain is required")

        selected: Optional[List[str]]
        if isinstance(subdomains, list):
            selected = [str(s).strip() for s in subdomains if str(s).strip()]
        else:
            selected = None

        target = selected[0] if selected else domain
        tenant = payload.get("tenant") or payload.get("tenant_name")
        report = run_scan(target, tenant=tenant)
        resolved = [target]

        # Return in the same shape DD expects so scan results persistence works.
        return {
            "scan_type": self.name,
            "domain": domain,
            "subdomains": resolved,
            "total_found": len(resolved),
            "report": report,
        }

