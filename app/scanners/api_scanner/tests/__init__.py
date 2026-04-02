from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlencode

from app.scanners.api_scanner.reporter.cvss_calculator import calculate_cvss, severity_from_score

# Finding ID counter (per-scan, resets each scan)
_finding_counter: Dict[str, int] = {}


def _next_id(prefix: str) -> str:
    _finding_counter.setdefault(prefix, 0)
    _finding_counter[prefix] += 1
    return f"{prefix}-{_finding_counter[prefix]:03d}"


def reset_finding_counters():
    _finding_counter.clear()


def make_finding(
    owasp_category: str,
    title: str,
    cvss_vector: str,
    endpoint: str,
    description: str,
    evidence: Dict[str, Any],
    impact: str,
    remediation: str,
    confidence: str = "HIGH",
    references: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a standardized finding dict."""
    prefix = owasp_category.replace(":", "").replace(" ", "")
    score = calculate_cvss(cvss_vector)
    return {
        "finding_id": _next_id(prefix),
        "owasp_category": owasp_category,
        "title": title,
        "severity": severity_from_score(score),
        "cvss_score": score,
        "cvss_vector": cvss_vector,
        "confidence": confidence,
        "endpoint": endpoint,
        "description": description,
        "evidence": evidence,
        "impact": impact,
        "remediation": remediation,
        "references": references or [],
    }


def build_url(base_url: str, path: str, query_params: Optional[Dict[str, str]] = None) -> str:
    """Build full URL from base + path + optional query params."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    if query_params:
        url = url + ("&" if "?" in url else "?") + urlencode(query_params)
    return url
