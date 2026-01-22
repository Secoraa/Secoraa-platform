from typing import Dict, List

try:
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None

TAKEOVER_FINGERPRINTS = {
    "github.io": "GitHub Pages",
    "amazonaws.com": "AWS S3",
    "herokudns.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "cloudfront.net": "AWS CloudFront",
}


def check_takeover(subdomains: List[str]) -> Dict[str, str]:
    """
    Identify possible subdomain takeover candidates
    """
    if dns is None:
        return {}

    vulnerable = {}

    for subdomain in subdomains:
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME")  # type: ignore[attr-defined]
            for rdata in answers:
                cname = str(rdata.target)

                for fingerprint, provider in TAKEOVER_FINGERPRINTS.items():
                    if fingerprint in cname:
                        vulnerable[subdomain] = provider

        except Exception:
            continue

    return vulnerable
