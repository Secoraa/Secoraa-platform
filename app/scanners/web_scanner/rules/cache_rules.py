from typing import Dict, Optional


def evaluate_cache(cache_headers: Dict[str, str]) -> Optional[str]:
    if not cache_headers.get("cache-control") and not cache_headers.get("pragma") and not cache_headers.get("expires"):
        return "cacheHttpsResponse"
    return None
