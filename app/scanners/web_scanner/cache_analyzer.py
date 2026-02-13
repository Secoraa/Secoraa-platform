from typing import Dict


def analyze_cache_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        "cache-control": headers.get("cache-control", ""),
        "pragma": headers.get("pragma", ""),
        "expires": headers.get("expires", ""),
    }
