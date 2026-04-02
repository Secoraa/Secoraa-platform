from __future__ import annotations

import logging
from typing import List

logger = logging.getLogger(__name__)

try:
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None

RECORD_TYPES = ("A", "AAAA", "CNAME")


def _resolves(subdomain: str) -> bool:
    """Check if a subdomain resolves via A, AAAA, or CNAME records."""
    for rtype in RECORD_TYPES:
        try:
            dns.resolver.resolve(subdomain, rtype)  # type: ignore[attr-defined]
            return True
        except Exception:
            continue
    return False


def validate_dns(subdomains: List[str]) -> List[str]:
    """
    Return only subdomains that resolve via DNS (A, AAAA, or CNAME).
    """
    # If dnspython isn't installed, don't crash the whole API.
    # We degrade gracefully by skipping DNS validation.
    if dns is None:
        logger.warning("dnspython not installed — skipping DNS validation")
        return list(subdomains)

    valid = []
    for subdomain in subdomains:
        if _resolves(subdomain):
            valid.append(subdomain)

    logger.info("DNS validation: %d / %d subdomains resolved", len(valid), len(subdomains))
    return valid
