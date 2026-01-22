from typing import List

try:
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None


def validate_dns(subdomains: List[str]) -> List[str]:
    """
    Return only subdomains that resolve via DNS
    """
    # If dnspython isn't installed, don't crash the whole API.
    # We degrade gracefully by skipping DNS validation.
    if dns is None:
        return list(subdomains)

    valid = []

    for subdomain in subdomains:
        try:
            dns.resolver.resolve(subdomain, "A")  # type: ignore[attr-defined]
            valid.append(subdomain)
        except Exception:
            continue

    return valid
