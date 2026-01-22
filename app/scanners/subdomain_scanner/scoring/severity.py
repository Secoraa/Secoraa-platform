# app/scanners/subdomain_scanner/scoring/severity.py

def score_exposure(paths: list) -> str:
    if ".env" in paths or ".git/config" in paths:
        return "HIGH"
    if "/admin" in paths or "/debug" in paths:
        return "MEDIUM"
    return "LOW"


def score_misconfig(missing_headers: list) -> str:
    if "Content-Security-Policy" in missing_headers:
        return "MEDIUM"
    if len(missing_headers) >= 3:
        return "HIGH"
    return "LOW"


def score_takeover() -> str:
    return "HIGH"  # takeover is always critical
