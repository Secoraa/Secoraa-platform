---
plan: 02
phase: 01-scanner-foundation
title: Write github-action/entrypoint.py
status: complete
completed: 2026-04-07
requirements: [SCAN-01, SCAN-03, SCAN-04, SCAN-05, SCAN-06, SCAN-07]
---

# Plan 02 Summary: Write github-action/entrypoint.py

## What Was Built

Created `github-action/entrypoint.py` — a 279-line CLI orchestrator that Phase 2's Docker container action will invoke. The entrypoint:

- Masks `INPUT_AUTH_TOKEN` and `INPUT_SECORAA_API_KEY` via `::add-mask::` **before** any other output (prevents accidental secret leakage)
- Reads 8 `INPUT_*` env vars (target-url, openapi-file, postman-file, auth-type, auth-token, fail-on-severity, secoraa-api-key, timeout-minutes)
- Validates that exactly one of OpenAPI or Postman file is provided
- Loads OpenAPI specs as raw strings (scanner's `parse_openapi` auto-detects JSON/YAML)
- Loads Postman collections as parsed dicts (via `json.load`)
- Assembles `auth_config = {"type": ..., "token": ...}` with whitelisted auth types
- Wraps `run_api_scan()` in `asyncio.wait_for` with configurable timeout
- Applies cumulative severity threshold with INFORMATIONAL always exempt
- Exits 0 (pass), 1 (findings meet threshold), or 2 (infra/input error)

## Tasks Completed

| Task | Description | Status |
|------|-------------|--------|
| 2.1 | Create github-action/entrypoint.py with full scaffolding | ✓ |
| 2.2 | Smoke-test entrypoint error paths (5 cases) | ✓ |
| 2.3 | Unit-test exceeds_threshold logic (9 cases) | ✓ |

## Key Files Created

- `github-action/entrypoint.py` (executable, 279 lines, stdlib-only)

## Verification Results

**Task 2.1 acceptance criteria (10/10 passed):**
- File exists and is executable
- Shebang is `#!/usr/bin/env python3`
- Parses cleanly via `ast.parse()`
- Contains 3 `::add-mask::` references
- Contains `EXIT_PASS = 0`, `EXIT_FINDINGS = 1`, `EXIT_ERROR = 2` constants
- Contains 4 `INFORMATIONAL` references (SEVERITY_ORDER + exceeds_threshold filter)
- Default severity `HIGH`, default auth type `bearer`
- Zero `^from sqlalchemy` imports
- Uses `asyncio.wait_for`

**Task 2.2 acceptance criteria (5/5 passed):**

| Test | Scenario | Expected | Actual |
|------|----------|----------|--------|
| A | No inputs | exit 2 + `INPUT_TARGET_URL is required` | ✓ |
| B | No spec file | exit 2 + `INPUT_OPENAPI_FILE or INPUT_POSTMAN_FILE` | ✓ |
| C | Nonexistent file | exit 2 + `OpenAPI spec not found` | ✓ |
| D | Invalid auth-type | exit 2 + `::add-mask::abc` (first line) + `INPUT_AUTH_TYPE must be one of` | ✓ |
| E | Both files provided | exit 2 + `Provide only one` | ✓ |

Test D specifically verifies SCAN-05 success criterion #5 (`::add-mask::` emitted before any log output) — `::add-mask::abc` appears as the very first line of output, before the OpenAPI load message and error.

**Task 2.3 acceptance criteria (9/9 passed):**
- Case 1: No findings + HIGH → pass ✓
- Case 2: HIGH + HIGH threshold → fail ✓
- Case 3: CRITICAL + HIGH threshold → fail (cumulative) ✓
- Case 4: HIGH + CRITICAL threshold → pass ✓
- Case 5: MEDIUM + HIGH threshold → pass ✓
- Case 6: MEDIUM + MEDIUM threshold → fail ✓
- Case 7: 99 INFORMATIONAL + LOW threshold → pass (INFO exempt) ✓
- Case 8: empty threshold → defaults to HIGH ✓
- Case 9: lowercase `high` → normalized ✓

## Key-Links

None — entrypoint.py is a leaf artifact consumed by Phase 2's Dockerfile (not yet created).

## Commits

- `71f947b` — feat(github-action): add entrypoint.py for CI scanner orchestration

## Requirements Covered

| ID | Description | Covered By |
|----|-------------|------------|
| SCAN-01 | Entrypoint reads inputs from INPUT_* env vars, invokes run_api_scan() headlessly | `get_input()`, `_run_scan()` |
| SCAN-03 | Scanner accepts OpenAPI spec file path and parses for endpoint discovery | `load_openapi_spec()` |
| SCAN-04 | Scanner accepts Postman collection file path and parses for endpoint discovery | `load_postman_collection()` |
| SCAN-05 | Scanner accepts target base URL and auth configuration (bearer, api_key, basic) | `build_auth_config()` + INPUT_TARGET_URL |
| SCAN-06 | Scanner exits with code 0/1/2 | `EXIT_PASS/FINDINGS/ERROR` constants, validated error paths |
| SCAN-07 | User can configure severity threshold via fail-on-severity input | `exceeds_threshold()` + INPUT_FAIL_ON_SEVERITY |

## Known Limitations (Deferred)

- **End-to-end scan test:** Requires a running target API. Deferred to Phase 2 when the Docker image is built and can be tested against `tests/vulnerable_api.py` locally.
- **CI progress logging:** `_update_progress()` in scanner core short-circuits when `db=None`. No progress output appears in CI logs. Deferred — not in v1 requirements.
- **Graceful partial results on timeout:** Currently exits 2 on timeout. Partial reporting is v2 (CI-04).
- **YAML OpenAPI specs:** Scanner's `parse_openapi` handles YAML via PyYAML, which is already in requirements.txt, so this works in practice. Entrypoint doesn't need YAML-specific logic — passes the raw string through.
