from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, List

OWASP_CATEGORIES = [
    "API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023",
    "API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023",
    "Injection",
]


def generate_report(
    scan_name: str,
    base_url: str,
    scan_mode: str,
    endpoints: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    started_at: datetime,
    completed_at: datetime,
) -> Dict[str, Any]:
    """Generate the full scan report with summary stats."""

    # Severity counts
    severity_counts = Counter(f.get("severity", "INFORMATIONAL") for f in findings)

    # OWASP coverage map
    finding_categories = Counter(f.get("owasp_category", "") for f in findings)
    owasp_coverage = {}
    for cat in OWASP_CATEGORIES:
        owasp_coverage[cat] = {
            "tested": True,
            "findings": finding_categories.get(cat, 0),
        }

    # Sort findings: CRITICAL first, then by CVSS score descending
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (severity_order.get(f.get("severity", "INFORMATIONAL"), 5), -(f.get("cvss_score", 0))),
    )

    return {
        "scan_name": scan_name,
        "scan_type": "API_SECURITY",
        "base_url": base_url,
        "scan_mode": scan_mode,
        "started_at": started_at.isoformat() + "Z",
        "completed_at": completed_at.isoformat() + "Z",
        "duration_seconds": round((completed_at - started_at).total_seconds(), 1),
        "total_endpoints": len(endpoints),
        "total_findings": len(findings),
        "severity_counts": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
            "INFORMATIONAL": severity_counts.get("INFORMATIONAL", 0),
        },
        "owasp_coverage": owasp_coverage,
        "findings": sorted_findings,
        # Keep legacy field for backward compatibility
        "generated_at": completed_at.isoformat(),
    }
