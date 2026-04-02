from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Tuple, Union

import requests as req_lib

from app.scanners.api_scanner.engine.evidence_collector import build_evidence

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5
MAX_RETRIES = 2
RETRY_BACKOFF = 0.5  # seconds, doubles each retry


async def execute_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None,
    raw_body: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[Optional[req_lib.Response], Dict[str, Any]]:
    """
    Execute an HTTP request and return (response, evidence).

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        headers: Request headers
        body: JSON body (sent as json=)
        raw_body: Raw string body (sent as data=) — use for XML, form data, etc.
        timeout: Request timeout in seconds

    Uses run_in_executor for Celery compatibility.
    Retries up to MAX_RETRIES times on transient errors (timeout, connection reset).
    """

    def _do():
        kwargs = {
            "method": method,
            "url": url,
            "headers": headers,
            "timeout": timeout,
            "allow_redirects": True,
            "verify": False,
        }
        if raw_body is not None:
            kwargs["data"] = raw_body
        elif body is not None:
            kwargs["json"] = body
        return req_lib.request(**kwargs)

    response = None
    last_error = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, _do)
            break  # success
        except req_lib.exceptions.Timeout:
            last_error = "timeout"
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF * (2 ** attempt))
                continue
            logger.warning("Request timed out after %d attempts: %s %s", attempt + 1, method, url)
        except req_lib.exceptions.ConnectionError as exc:
            error_str = str(exc).lower()
            # Retry on transient connection errors (reset, refused), not DNS failures
            is_transient = any(kw in error_str for kw in ["reset", "broken pipe", "connection refused"])
            if is_transient and attempt < MAX_RETRIES:
                last_error = "connection_reset"
                await asyncio.sleep(RETRY_BACKOFF * (2 ** attempt))
                continue
            logger.warning("Connection error: %s %s", method, url)
            break
        except Exception as exc:
            logger.warning("Request failed: %s %s — %s", method, url, exc)
            break

    evidence = build_evidence(method, url, headers, body or raw_body, response)
    return response, evidence
