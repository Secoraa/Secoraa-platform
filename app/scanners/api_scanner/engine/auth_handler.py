from __future__ import annotations

import base64
import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def build_auth_headers(
    auth_config: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Build auth headers and query params from an auth config dict.

    Returns (headers_dict, query_params_dict).

    Supported types:
      - bearer:       {"type": "bearer", "token": "eyJ..."}
      - api_key:      {"type": "api_key", "header_name": "X-API-Key", "value": "abc"}
      - api_key_query: {"type": "api_key_query", "param_name": "api_key", "value": "abc"}
      - basic:        {"type": "basic", "username": "user", "password": "pass"}
      - none / null:  no auth
    """
    if not auth_config:
        return {}, {}

    auth_type = (auth_config.get("type") or "none").strip()

    if auth_type == "none":
        return {}, {}

    if auth_type == "bearer":
        token = (auth_config.get("token") or "").strip()
        if not token:
            logger.warning("Bearer auth selected but token is empty — treating as no auth")
            return {}, {}
        return {"Authorization": f"Bearer {token}"}, {}

    if auth_type == "api_key":
        header_name = (auth_config.get("header_name") or "").strip()
        value = (auth_config.get("value") or "").strip()
        if not header_name or not value:
            logger.warning("API key auth selected but header_name or value is empty — treating as no auth")
            return {}, {}
        return {header_name: value}, {}

    if auth_type == "api_key_query":
        param_name = (auth_config.get("param_name") or "").strip()
        value = (auth_config.get("value") or "").strip()
        if not param_name or not value:
            logger.warning("API key query auth selected but param_name or value is empty — treating as no auth")
            return {}, {}
        return {}, {param_name: value}

    if auth_type == "basic":
        username = (auth_config.get("username") or "").strip()
        password = (auth_config.get("password") or "").strip()
        if not username:
            logger.warning("Basic auth selected but username is empty — treating as no auth")
            return {}, {}
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}, {}

    logger.info("Auth type '%s' — no auth headers applied", auth_type)
    return {}, {}
