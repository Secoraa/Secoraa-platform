from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

MAX_BODY_SIZE = 2048  # 2 KB max for evidence body snippets


def _truncate(text: Optional[str], limit: int = MAX_BODY_SIZE) -> Optional[str]:
    if text is None:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + "... [truncated]"


def _sanitize_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Partially mask sensitive header values for evidence storage."""
    if not headers:
        return {}
    sanitized = {}
    sensitive_keys = {"authorization", "x-api-key", "cookie", "set-cookie"}
    for k, v in headers.items():
        if k.lower() in sensitive_keys and len(v) > 12:
            sanitized[k] = v[:12] + "..." + v[-4:]
        else:
            sanitized[k] = v
    return sanitized


def build_evidence(
    method: str,
    url: str,
    request_headers: Optional[Dict[str, str]] = None,
    request_body: Any = None,
    response=None,
) -> Dict[str, Any]:
    """Build an evidence dict from a request/response pair."""
    evidence: Dict[str, Any] = {
        "request": {
            "method": method,
            "url": url,
            "headers": _sanitize_headers(request_headers),
            "body": _truncate(str(request_body)) if request_body else None,
        },
        "response": {
            "status_code": None,
            "headers": {},
            "body_snippet": None,
        },
    }

    if response is not None:
        try:
            evidence["response"]["status_code"] = response.status_code
            evidence["response"]["headers"] = dict(response.headers)
            evidence["response"]["body_snippet"] = _truncate(response.text)
        except Exception as exc:
            logger.warning("Failed to capture response evidence: %s", exc)

    return evidence
