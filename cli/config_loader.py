"""
.secoraa.yml config loader.

Config precedence (highest wins):
    1. CLI flags
    2. Environment variables
    3. .secoraa.yml in the current directory (or explicit --config path)
    4. Built-in defaults

Example .secoraa.yml:

    scan:
      target: https://staging.example.com
      spec: ./docs/openapi.yaml
      mode: active
      auth:
        type: bearer
        token_env: API_AUTH_TOKEN   # read secret from this env var

    gate:
      severity_threshold: HIGH
      fail_on_findings: true
      ignore_rules:
        - API8:2023

    report:
      format: sarif
      output_file: secoraa-results.sarif
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_CONFIG_NAMES = (".secoraa.yml", ".secoraa.yaml")


class ConfigError(Exception):
    """Raised when .secoraa.yml is malformed."""


def find_config_file(start: Optional[Path] = None) -> Optional[Path]:
    """Look for a .secoraa.yml in the given dir (defaults to cwd)."""
    base = Path(start) if start else Path.cwd()
    for name in _DEFAULT_CONFIG_NAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load a .secoraa.yml file into a nested dict. Returns `{}` if no file is
    found and no explicit path was provided.
    """
    if path:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f".secoraa.yml not found at: {path}")
    else:
        p = find_config_file()
        if not p:
            return {}

    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise ConfigError(
            "PyYAML is required to read .secoraa.yml. Install with: pip install pyyaml"
        ) from exc

    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"failed to parse {p}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{p}: top-level must be a mapping")

    _validate(data, source=str(p))
    return data


# ---------------------------------------------------------------------------
# Resolution: merge CLI > env > config > defaults
# ---------------------------------------------------------------------------
def resolve(
    cli_value: Optional[Any],
    env_key: Optional[str],
    config: Dict[str, Any],
    config_path: List[str],
    default: Any = None,
) -> Any:
    """
    Walk config via dotted path, fall back to env var, then default.
    CLI flag always wins if truthy.
    """
    if cli_value not in (None, "", []):
        return cli_value

    if env_key:
        env_val = os.environ.get(env_key)
        if env_val:
            return env_val

    cur: Any = config
    for key in config_path:
        if not isinstance(cur, dict):
            cur = None
            break
        cur = cur.get(key)
    if cur not in (None, "", []):
        return cur

    return default


def resolve_auth_token(config: Dict[str, Any]) -> Optional[str]:
    """
    Resolve an auth token from config.
    Supports `scan.auth.token` (literal) or `scan.auth.token_env` (env var name).
    """
    auth = (config.get("scan") or {}).get("auth") or {}
    if not isinstance(auth, dict):
        return None
    if auth.get("token"):
        return str(auth["token"])
    env_name = auth.get("token_env")
    if env_name:
        return os.environ.get(str(env_name))
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
_KNOWN_TOP_LEVEL = {"scan", "gate", "report"}
_KNOWN_SCAN = {"target", "spec", "mode", "auth", "secondary_auth", "name"}
_KNOWN_AUTH = {"type", "token", "token_env", "header_name"}
_KNOWN_GATE = {"severity_threshold", "fail_on_findings", "ignore_rules"}
_KNOWN_REPORT = {"format", "output_file"}


def _warn(msg: str) -> None:
    # Stderr-only; we don't want to spam stdout which may be the report itself.
    import sys
    print(f"[secoraa] warning: {msg}", file=sys.stderr)


def _validate(data: Dict[str, Any], source: str) -> None:
    for key in data:
        if key not in _KNOWN_TOP_LEVEL:
            _warn(f"{source}: unknown top-level key '{key}'")

    scan = data.get("scan")
    if scan is not None:
        if not isinstance(scan, dict):
            raise ConfigError(f"{source}: 'scan' must be a mapping")
        for key in scan:
            if key not in _KNOWN_SCAN:
                _warn(f"{source}: unknown scan.{key}")
        auth = scan.get("auth")
        if auth is not None and not isinstance(auth, dict):
            raise ConfigError(f"{source}: 'scan.auth' must be a mapping")
        if isinstance(auth, dict):
            for key in auth:
                if key not in _KNOWN_AUTH:
                    _warn(f"{source}: unknown scan.auth.{key}")

    gate = data.get("gate")
    if gate is not None:
        if not isinstance(gate, dict):
            raise ConfigError(f"{source}: 'gate' must be a mapping")
        for key in gate:
            if key not in _KNOWN_GATE:
                _warn(f"{source}: unknown gate.{key}")
        ignore = gate.get("ignore_rules")
        if ignore is not None and not isinstance(ignore, list):
            raise ConfigError(f"{source}: 'gate.ignore_rules' must be a list")

    report = data.get("report")
    if report is not None:
        if not isinstance(report, dict):
            raise ConfigError(f"{source}: 'report' must be a mapping")
        for key in report:
            if key not in _KNOWN_REPORT:
                _warn(f"{source}: unknown report.{key}")
