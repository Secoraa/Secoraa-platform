import asyncio
from typing import List, Optional

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None


async def _probe_one(session, url: str) -> Optional[int]:
    try:
        async with session.get(url, timeout=5) as r:
            return int(r.status)
    except Exception:
        return None


async def _probe_all_async(subdomains: List[str]) -> List[Optional[int]]:
    if aiohttp is None:
        return [None for _ in subdomains]
    async with aiohttp.ClientSession() as session:
        tasks = [_probe_one(session, f"https://{s}") for s in subdomains]
        return await asyncio.gather(*tasks)


def probe_http(subdomains: List[str]) -> List[Optional[int]]:
    """
    Sync wrapper expected by `run_subdomain_scan`.
    Returns a list of HTTP status codes aligned with input `subdomains`.
    """
    if not subdomains:
        return []
    if aiohttp is None:
        return [None for _ in subdomains]
    return asyncio.run(_probe_all_async(subdomains))
