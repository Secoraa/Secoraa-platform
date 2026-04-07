#!/usr/bin/env python3
"""
Secoraa API Security Scanner — GitHub Action entrypoint.

Reads inputs from INPUT_* environment variables, invokes the scanner,
and sets an exit code based on findings vs the configured severity threshold.

Exit codes:
  0 — no findings at or above the severity threshold
  1 — findings at or above the severity threshold
  2 — infrastructure error (bad inputs, missing files, scanner crash, timeout)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import traceback
from typing import Any, Dict, Optional

# Ensure repo root is on sys.path so `app.scanners.*` resolves when
# entrypoint.py is invoked from an arbitrary working directory.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Severity ordering (lower index = more severe). "INFORMATIONAL" is listed
# for completeness but is filtered out of threshold comparisons below.
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFORMATIONAL": 4,
}

VALID_AUTH_TYPES = {"bearer", "api_key", "api_key_query", "basic"}

# Exit codes
EXIT_PASS = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


# ────────────────────────────────────────────────────────────────────
# Workflow commands (stdout) — must not use logging (stderr)
# ────────────────────────────────────────────────────────────────────

def mask(value: str) -> None:
    """Emit a GitHub Actions ::add-mask:: workflow command."""
    if value:
        print(f"::add-mask::{value}", flush=True)


def log_info(msg: str) -> None:
    print(msg, flush=True)


def log_error(msg: str) -> None:
    print(f"::error::{msg}", flush=True)


# ────────────────────────────────────────────────────────────────────
# Input reading
# ────────────────────────────────────────────────────────────────────

def get_input(name: str, default: str = "") -> str:
    """Read a GitHub Action input from INPUT_<NAME> env var."""
    key = f"INPUT_{name.upper().replace('-', '_')}"
    return os.environ.get(key, default).strip()


def build_auth_config(auth_type: str, auth_token: str) -> Optional[Dict[str, Any]]:
    """Assemble the auth_config dict consumed by run_api_scan()."""
    if not auth_token:
        return None
    auth_type = auth_type.lower() or "bearer"
    if auth_type not in VALID_AUTH_TYPES:
        raise ValueError(
            f"INPUT_AUTH_TYPE must be one of {sorted(VALID_AUTH_TYPES)}, got: {auth_type}"
        )
    return {"type": auth_type, "token": auth_token}


def load_openapi_spec(path: str) -> str:
    """Read OpenAPI spec file as a string (parse_openapi handles JSON/YAML detection)."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"OpenAPI spec not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_postman_collection(path: str) -> Dict[str, Any]:
    """Read Postman collection file and parse as JSON dict."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Postman collection not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Postman collection is not valid JSON: {e}") from e


# ────────────────────────────────────────────────────────────────────
# Severity threshold logic
# ────────────────────────────────────────────────────────────────────

def exceeds_threshold(severity_counts: Dict[str, int], threshold: str) -> bool:
    """
    Return True if any finding at or above the threshold exists.

    Cumulative semantics: threshold=HIGH means CRITICAL + HIGH trigger failure.
    INFORMATIONAL NEVER triggers failure regardless of threshold.
    """
    threshold = (threshold or "HIGH").upper()
    if threshold not in SEVERITY_ORDER:
        raise ValueError(
            f"INPUT_FAIL_ON_SEVERITY must be one of CRITICAL/HIGH/MEDIUM/LOW, got: {threshold}"
        )
    threshold_level = SEVERITY_ORDER[threshold]
    for severity, count in severity_counts.items():
        if count <= 0:
            continue
        if severity == "INFORMATIONAL":
            continue
        level = SEVERITY_ORDER.get(severity.upper(), 99)
        if level <= threshold_level:
            return True
    return False


# ────────────────────────────────────────────────────────────────────
# Scan name
# ────────────────────────────────────────────────────────────────────

def derive_scan_name() -> str:
    """Build a unique scan name from GitHub env vars (or fallback)."""
    repo = os.environ.get("GITHUB_REPOSITORY", "local").replace("/", "-")
    sha = os.environ.get("GITHUB_SHA", "nosha")[:8]
    return f"ci-{repo}-{sha}-{int(time.time())}"


# ────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────

async def _run_scan(
    target_url: str,
    openapi_spec: Optional[str],
    postman_collection: Optional[Dict[str, Any]],
    auth_config: Optional[Dict[str, Any]],
    timeout_seconds: int,
) -> Dict[str, Any]:
    """Invoke run_api_scan with a timeout wrapper."""
    # Import here so the ::add-mask:: lines run BEFORE any scanner
    # module is imported (which might emit log lines on import).
    from app.scanners.api_scanner.main import run_api_scan

    return await asyncio.wait_for(
        run_api_scan(
            scan_name=derive_scan_name(),
            asset_url=target_url,
            openapi_spec=openapi_spec,
            postman_collection=postman_collection,
            auth_config=auth_config,
            scan_mode="active",
            db=None,
            scan_id=None,
        ),
        timeout=timeout_seconds,
    )


def main() -> int:
    # STEP 1: Mask secrets BEFORE anything else runs.
    auth_token = get_input("auth-token")
    secoraa_api_key = get_input("secoraa-api-key")
    mask(auth_token)
    mask(secoraa_api_key)

    # STEP 2: Read and validate inputs.
    target_url = get_input("target-url")
    openapi_file = get_input("openapi-file")
    postman_file = get_input("postman-file")
    auth_type = get_input("auth-type", "bearer")
    fail_on_severity = get_input("fail-on-severity", "HIGH")
    timeout_minutes_raw = get_input("timeout-minutes", "10")

    if not target_url:
        log_error("INPUT_TARGET_URL is required")
        return EXIT_ERROR

    if not openapi_file and not postman_file:
        log_error("Either INPUT_OPENAPI_FILE or INPUT_POSTMAN_FILE must be provided")
        return EXIT_ERROR

    if openapi_file and postman_file:
        log_error("Provide only one of INPUT_OPENAPI_FILE or INPUT_POSTMAN_FILE, not both")
        return EXIT_ERROR

    try:
        timeout_seconds = int(timeout_minutes_raw) * 60
        if timeout_seconds <= 0:
            raise ValueError("must be positive")
    except ValueError:
        log_error(f"INPUT_TIMEOUT_MINUTES must be a positive integer, got: {timeout_minutes_raw}")
        return EXIT_ERROR

    # STEP 3: Load spec file.
    try:
        openapi_spec: Optional[str] = None
        postman_collection: Optional[Dict[str, Any]] = None
        if openapi_file:
            openapi_spec = load_openapi_spec(openapi_file)
            log_info(f"Loaded OpenAPI spec from {openapi_file}")
        else:
            postman_collection = load_postman_collection(postman_file)
            log_info(f"Loaded Postman collection from {postman_file}")
    except (FileNotFoundError, ValueError) as e:
        log_error(str(e))
        return EXIT_ERROR

    # STEP 4: Build auth config.
    try:
        auth_config = build_auth_config(auth_type, auth_token)
    except ValueError as e:
        log_error(str(e))
        return EXIT_ERROR

    # STEP 5: Run the scan.
    log_info(f"Starting scan against {target_url} (timeout: {timeout_seconds}s)")
    try:
        report = asyncio.run(
            _run_scan(
                target_url=target_url,
                openapi_spec=openapi_spec,
                postman_collection=postman_collection,
                auth_config=auth_config,
                timeout_seconds=timeout_seconds,
            )
        )
    except asyncio.TimeoutError:
        log_error(f"Scan exceeded {timeout_seconds}s timeout")
        return EXIT_ERROR
    except Exception as e:  # noqa: BLE001
        log_error(f"Scanner error: {e}")
        traceback.print_exc()
        return EXIT_ERROR

    # STEP 6: Report summary and apply threshold.
    severity_counts = report.get("severity_counts", {})
    total_findings = report.get("total_findings", 0)
    total_endpoints = report.get("total_endpoints", 0)
    log_info(
        f"Scan complete: {total_findings} findings across {total_endpoints} endpoints"
    )
    log_info(f"Severity counts: {severity_counts}")

    try:
        fail = exceeds_threshold(severity_counts, fail_on_severity)
    except ValueError as e:
        log_error(str(e))
        return EXIT_ERROR

    if fail:
        log_error(
            f"Findings at or above severity threshold '{fail_on_severity}' — failing the build"
        )
        return EXIT_FINDINGS

    log_info(f"No findings at or above severity threshold '{fail_on_severity}' — pass")
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
