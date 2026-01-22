# engine/request_executor.py
import asyncio
from typing import Optional, Dict, Any

import requests


async def execute_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None,
):
    """
    Async wrapper around `requests` to avoid adding extra async HTTP deps (httpx/aiohttp).
    Returns a `requests.Response` (has .status_code, .headers, .json(), etc).
    """

    def _do():
        return requests.request(
            method=method,
            url=url,
            headers=headers,
            json=body,
            timeout=10,
            allow_redirects=True,
        )

    return await asyncio.to_thread(_do)
