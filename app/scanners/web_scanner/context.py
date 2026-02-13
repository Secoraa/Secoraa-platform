from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class ScanContext:
    scan: Dict[str, Any] = field(default_factory=dict)
    preflight_checks: Dict[str, Any] = field(default_factory=dict)
    findings_metadata: Dict[str, Any] = field(default_factory=lambda: {
        "crawlUrls": {"authenticatedUrl": [], "unauthenticatedUrl": []},
        "totalCrawlUrls": 0,
    })
    messages: Dict[str, Any] = field(default_factory=lambda: {
        "totalCrawledUrls": 0,
        "technologies": ["all"],
        "authenticationType": None,
        "infos": [],
        "errors": [],
        "warnings": [],
    })
    findings: List[Dict[str, Any]] = field(default_factory=list)
    files: Dict[str, Any] = field(default_factory=dict)
    secrets: Dict[str, Any] = field(default_factory=dict)

    # Runtime context
    crawled_urls: List[str] = field(default_factory=list)
    detected_headers: Dict[str, str] = field(default_factory=dict)
    tls_info: Dict[str, Any] = field(default_factory=dict)
    redirect_status: Dict[str, Any] = field(default_factory=dict)
