---
plan: 02
phase: 01-scanner-foundation
title: Write github-action/entrypoint.py
wave: 1
depends_on: [01]
files_modified:
  - github-action/entrypoint.py
requirements: [SCAN-01, SCAN-03, SCAN-04, SCAN-05, SCAN-06, SCAN-07]
autonomous: true
---

# Plan 02: Write github-action/entrypoint.py

<objective>
Create `github-action/entrypoint.py` — the thin CLI orchestrator that the Phase 2 Docker container action will invoke. It reads `INPUT_*` environment variables, loads the OpenAPI or Postman spec file, builds the auth config dict, calls `run_api_scan()`, checks findings against the severity threshold, and exits with the correct code.

Covers 6 of the 7 phase requirements (SCAN-02 handled by Plan 01).
</objective>

<must_haves>
- File exists at `github-action/entrypoint.py` and is executable
- Reads inputs exclusively from environment variables using the `INPUT_<NAME>` convention (SCAN-01)
- Supports both OpenAPI and Postman spec files via `INPUT_OPENAPI_FILE` / `INPUT_POSTMAN_FILE` (SCAN-03, SCAN-04)
- Builds `auth_config` from `INPUT_AUTH_TYPE` + `INPUT_AUTH_TOKEN` (SCAN-05)
- Exit codes: 0=pass, 1=findings at/above threshold, 2=infrastructure/input error (SCAN-06)
- Severity threshold via `INPUT_FAIL_ON_SEVERITY`, default `HIGH`, cumulative semantics (SCAN-07)
- Emits `::add-mask::` for `INPUT_AUTH_TOKEN` and `INPUT_SECORAA_API_KEY` BEFORE any other output
- `INFORMATIONAL` severity never triggers failure regardless of threshold
- Input validation errors produce exit code 2, not 1
- Any uncaught exception produces exit code 2
</must_haves>

<tasks>

<task id="2.1">
<title>Create github-action/entrypoint.py with full scaffolding</title>
<read_first>
- .planning/phases/01-scanner-foundation/01-CONTEXT.md (all 5 decisions, env var table, exit code contract)
- .planning/phases/01-scanner-foundation/01-RESEARCH.md (F3, F4, F5, F6, F7, F8, F9, F10, P2, P3, P6, P7)
- app/scanners/api_scanner/main.py (run_api_scan signature on line 182)
- app/scanners/api_scanner/reporter/report_generator.py (severity_counts structure on line 44)
- app/scanners/api_scanner/parser/openapi_parser.py (parse_openapi accepts str or dict, line 51)
- app/scanners/api_scanner/parser/postman_parser.py (parse_postman accepts dict only, line 4)
</read_first>
<action>
Create the directory `github-action/` at the repository root if it does not exist. Create `github-action/entrypoint.py` with the following exact content:

```python
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
```

After writing the file, make it executable:
```bash
chmod +x github-action/entrypoint.py
```
</action>
<acceptance_criteria>
- File exists: `test -f github-action/entrypoint.py` exits 0
- File is executable: `test -x github-action/entrypoint.py` exits 0
- First line is `#!/usr/bin/env python3`: `head -1 github-action/entrypoint.py` prints exactly `#!/usr/bin/env python3`
- File parses cleanly: `python -c "import ast; ast.parse(open('github-action/entrypoint.py').read())"` exits 0
- Contains `::add-mask::` emission: `grep -c '::add-mask::' github-action/entrypoint.py` returns at least 1
- Contains three exit code constants: `grep -c 'EXIT_PASS = 0' github-action/entrypoint.py` returns 1, same for `EXIT_FINDINGS = 1` and `EXIT_ERROR = 2`
- Contains `INFORMATIONAL` filter: `grep -c 'INFORMATIONAL' github-action/entrypoint.py` returns at least 2 (one in SEVERITY_ORDER, one in exceeds_threshold)
- Contains default severity HIGH: `grep -q 'fail-on-severity", "HIGH"' github-action/entrypoint.py` exits 0
- Default auth type bearer: `grep -q 'auth-type", "bearer"' github-action/entrypoint.py` exits 0
- Has TYPE_CHECKING-free imports at module scope (no sqlalchemy): `grep -c '^from sqlalchemy' github-action/entrypoint.py` returns 0
- Uses asyncio.run with wait_for: `grep -q 'asyncio.wait_for' github-action/entrypoint.py` exits 0
</acceptance_criteria>
</task>

<task id="2.2">
<title>Smoke-test entrypoint error paths</title>
<read_first>
- github-action/entrypoint.py (just created)
- .planning/phases/01-scanner-foundation/01-RESEARCH.md (V4, V5)
</read_first>
<action>
Run these five smoke tests from the repo root. They exercise error paths without needing a live target API.

**Test A — Missing target URL (exit 2):**
```bash
env -i PATH="$PATH" python github-action/entrypoint.py; echo "exit=$?"
```
Expected: stderr/stdout contains `INPUT_TARGET_URL is required`; last line prints `exit=2`.

**Test B — Missing spec file input (exit 2):**
```bash
env -i PATH="$PATH" INPUT_TARGET_URL=http://localhost:9999 python github-action/entrypoint.py; echo "exit=$?"
```
Expected: output contains `INPUT_OPENAPI_FILE or INPUT_POSTMAN_FILE`; last line `exit=2`.

**Test C — Nonexistent spec file (exit 2):**
```bash
env -i PATH="$PATH" INPUT_TARGET_URL=http://localhost:9999 INPUT_OPENAPI_FILE=/tmp/does_not_exist.json python github-action/entrypoint.py; echo "exit=$?"
```
Expected: output contains `OpenAPI spec not found`; last line `exit=2`.

**Test D — Invalid auth type (exit 2):**
```bash
echo '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}' > /tmp/empty_openapi.json
env -i PATH="$PATH" INPUT_TARGET_URL=http://localhost:9999 INPUT_OPENAPI_FILE=/tmp/empty_openapi.json INPUT_AUTH_TYPE=wrong INPUT_AUTH_TOKEN=abc python github-action/entrypoint.py 2>&1; echo "exit=$?"
```
Expected: output contains `::add-mask::abc` (first or second line), then `INPUT_AUTH_TYPE must be one of`; last line `exit=2`.

**Test E — Both spec files provided (exit 2):**
```bash
echo '{"item":[]}' > /tmp/empty_postman.json
env -i PATH="$PATH" INPUT_TARGET_URL=http://localhost:9999 INPUT_OPENAPI_FILE=/tmp/empty_openapi.json INPUT_POSTMAN_FILE=/tmp/empty_postman.json python github-action/entrypoint.py; echo "exit=$?"
```
Expected: output contains `Provide only one`; last line `exit=2`.

All five tests MUST print `exit=2`. If any exits with a different code or raises an unhandled traceback, the entrypoint has a bug — investigate and fix before completing this task.
</action>
<acceptance_criteria>
- Test A exit code is 2 AND output contains `INPUT_TARGET_URL is required`
- Test B exit code is 2 AND output contains `INPUT_OPENAPI_FILE or INPUT_POSTMAN_FILE`
- Test C exit code is 2 AND output contains `OpenAPI spec not found`
- Test D exit code is 2 AND output contains `::add-mask::abc` AND contains `INPUT_AUTH_TYPE must be one of`
- Test E exit code is 2 AND output contains `Provide only one`
- None of the tests produce an uncaught Python traceback (no `Traceback (most recent call last):` in output unless the entrypoint explicitly printed it as part of error handling)
</acceptance_criteria>
</task>

<task id="2.3">
<title>Unit-test exceeds_threshold logic</title>
<read_first>
- github-action/entrypoint.py (the exceeds_threshold function)
- .planning/phases/01-scanner-foundation/01-CONTEXT.md (Decision D5)
</read_first>
<action>
Run this Python one-liner from the repo root to verify the severity threshold logic matches the 7 cases in CONTEXT.md D5:

```bash
python <<'EOF'
import sys, os
sys.path.insert(0, os.path.abspath("github-action"))
from entrypoint import exceeds_threshold

# Case 1: No findings + threshold=HIGH → False
assert exceeds_threshold({"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFORMATIONAL":0}, "HIGH") is False, "case1"

# Case 2: HIGH finding + threshold=HIGH → True
assert exceeds_threshold({"CRITICAL":0,"HIGH":2,"MEDIUM":0,"LOW":0,"INFORMATIONAL":0}, "HIGH") is True, "case2"

# Case 3: CRITICAL finding + threshold=HIGH → True (cumulative)
assert exceeds_threshold({"CRITICAL":1,"HIGH":0,"MEDIUM":0,"LOW":0,"INFORMATIONAL":0}, "HIGH") is True, "case3"

# Case 4: HIGH finding + threshold=CRITICAL → False
assert exceeds_threshold({"CRITICAL":0,"HIGH":5,"MEDIUM":0,"LOW":0,"INFORMATIONAL":0}, "CRITICAL") is False, "case4"

# Case 5: MEDIUM finding + threshold=HIGH → False
assert exceeds_threshold({"CRITICAL":0,"HIGH":0,"MEDIUM":3,"LOW":0,"INFORMATIONAL":0}, "HIGH") is False, "case5"

# Case 6: MEDIUM finding + threshold=MEDIUM → True
assert exceeds_threshold({"CRITICAL":0,"HIGH":0,"MEDIUM":1,"LOW":0,"INFORMATIONAL":0}, "MEDIUM") is True, "case6"

# Case 7: Only INFORMATIONAL findings + threshold=LOW → False (INFO never triggers)
assert exceeds_threshold({"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFORMATIONAL":99}, "LOW") is False, "case7"

# Case 8: Default threshold when empty string → HIGH
assert exceeds_threshold({"HIGH":1}, "") is True, "case8_default"

# Case 9: Lowercase threshold normalized
assert exceeds_threshold({"HIGH":1}, "high") is True, "case9_case"

print("ALL_CASES_PASS")
EOF
```

Expected stdout: `ALL_CASES_PASS`. If any assertion fails, fix the `exceeds_threshold` function in entrypoint.py before marking the task complete.
</action>
<acceptance_criteria>
- Command prints exactly `ALL_CASES_PASS` on stdout
- Command exit code is `0`
- No AssertionError in stderr
</acceptance_criteria>
</task>

</tasks>

<verification>
All acceptance criteria in tasks 2.1, 2.2, and 2.3 must pass. Additionally:

**Phase success criteria coverage:**
1. ✓ "Produces a report dict without importing SQLAlchemy or psycopg2" — Plan 01 verifies this
2. ✓ "Postman collection file produces report dict with endpoints" — entrypoint dispatches to parse_postman (full end-to-end test requires a running target API and is deferred to Phase 2 integration)
3. ✓ "Exits 0/1/2 correctly" — Plan 02 Task 2.2 tests exit 2 paths; exit 0/1 require running against real target (Phase 2)
4. ✓ "INPUT_FAIL_ON_SEVERITY=HIGH means CRITICAL+HIGH trigger exit 1" — Plan 02 Task 2.3 unit-tests this logic
5. ✓ "Emits ::add-mask:: for API key before any log output" — Plan 02 Task 2.2 Test D verifies this

**Requirement coverage:**
- SCAN-01 (env var reading): Plan 02, get_input() function
- SCAN-02 (SQLAlchemy decoupled): Plan 01
- SCAN-03 (OpenAPI input): Plan 02, load_openapi_spec()
- SCAN-04 (Postman input): Plan 02, load_postman_collection()
- SCAN-05 (auth config): Plan 02, build_auth_config()
- SCAN-06 (exit codes): Plan 02, EXIT_* constants + Task 2.2
- SCAN-07 (severity threshold): Plan 02, exceeds_threshold() + Task 2.3
</verification>
