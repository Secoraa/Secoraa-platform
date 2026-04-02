from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


def _resolve_ref(spec: Dict, ref: str) -> Dict:
    """Resolve a $ref pointer like '#/components/schemas/User'."""
    parts = ref.lstrip("#/").split("/")
    node = spec
    for p in parts:
        node = node.get(p, {})
    return node


def _extract_body_fields(spec: Dict, operation: Dict) -> Optional[Dict]:
    """Extract request body JSON schema fields from an operation."""
    request_body = operation.get("requestBody", {})
    content = request_body.get("content", {})

    json_content = content.get("application/json", {})
    schema = json_content.get("schema", {})

    if "$ref" in schema:
        schema = _resolve_ref(spec, schema["$ref"])

    if schema.get("properties"):
        return schema["properties"]
    return None


def _extract_body_fields_swagger(spec: Dict, parameters: List[Dict]) -> Optional[Dict]:
    """Extract body fields from Swagger 2.0 parameters."""
    for param in parameters:
        if param.get("in") == "body":
            schema = param.get("schema", {})
            if "$ref" in schema:
                schema = _resolve_ref(spec, schema["$ref"])
            if schema.get("properties"):
                return schema["properties"]
    return None


def parse_openapi(spec: Any) -> List[Dict]:
    """
    Parse an OpenAPI 3.x or Swagger 2.0 spec into normalized endpoint list.

    Accepts:
      - dict (already parsed JSON/YAML)
      - str  (raw JSON or YAML string)

    Returns same format as postman_parser: [{name, method, path, headers, body, parameters}]
    """
    if isinstance(spec, str):
        # Try JSON first, then YAML
        import json
        try:
            spec = json.loads(spec)
        except (json.JSONDecodeError, ValueError):
            if yaml is not None:
                spec = yaml.safe_load(spec)
            else:
                logger.error("Cannot parse YAML — pyyaml not installed")
                return []

    if not isinstance(spec, dict):
        logger.error("Invalid OpenAPI spec — expected dict, got %s", type(spec))
        return []

    is_swagger_2 = spec.get("swagger", "").startswith("2")
    endpoints: List[Dict] = []

    paths = spec.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            operation = path_item.get(method)
            if not operation:
                continue

            # Extract parameters
            params = operation.get("parameters", []) + path_item.get("parameters", [])
            parameters = []
            for p in params:
                if "$ref" in p:
                    p = _resolve_ref(spec, p["$ref"])
                parameters.append({
                    "name": p.get("name", ""),
                    "in": p.get("in", ""),
                    "type": p.get("schema", {}).get("type", p.get("type", "string")),
                    "required": p.get("required", False),
                })

            # Extract body fields
            if is_swagger_2:
                body_fields = _extract_body_fields_swagger(spec, params)
            else:
                body_fields = _extract_body_fields(spec, operation)

            # Build sample body from schema
            body = {}
            if body_fields:
                for field_name, field_schema in body_fields.items():
                    if "$ref" in field_schema:
                        field_schema = _resolve_ref(spec, field_schema["$ref"])
                    field_type = field_schema.get("type", "string")
                    if field_type == "string":
                        body[field_name] = "test"
                    elif field_type == "integer":
                        body[field_name] = 1
                    elif field_type == "number":
                        body[field_name] = 1.0
                    elif field_type == "boolean":
                        body[field_name] = True
                    elif field_type == "array":
                        body[field_name] = []
                    elif field_type == "object":
                        body[field_name] = {}
                    else:
                        body[field_name] = "test"

            # Check if auth is required
            security = operation.get("security", spec.get("security", []))
            auth_required = bool(security)

            name = operation.get("summary") or operation.get("operationId") or f"{method.upper()} {path}"

            endpoints.append({
                "name": name,
                "method": method.upper(),
                "path": path,
                "headers": {},
                "body": body if body else {},
                "parameters": parameters,
                "auth_required": auth_required,
            })

    logger.info("Parsed %d endpoints from OpenAPI spec", len(endpoints))
    return endpoints
