# Phase 1 Context: Scanner Foundation

**Phase Goal**: Developer-controlled entrypoint calls the scanner cleanly from a context with no database
**Requirements**: SCAN-01, SCAN-02, SCAN-03, SCAN-04, SCAN-05, SCAN-06, SCAN-07
**Created**: 2026-04-04

## Decisions

### D1: SQLAlchemy Decoupling — TYPE_CHECKING Guard

**Decision**: Wrap the `from sqlalchemy.orm import Session` import (line 8 of `main.py`) in a `TYPE_CHECKING` guard so it never executes at runtime.

**Details**:
- Line 8 is the ONLY top-level SQLAlchemy import in the scanner package
- Lines 55 and 77 (`from app.database.models import Scan`) are already safe — they're inside functions guarded by `if not db: return`
- Use `from __future__ import annotations` (already present) + `if TYPE_CHECKING:` block
- Result: scanner package imports cleanly without sqlalchemy or psycopg2 installed
- No changes needed to any other scanner file — grep confirmed no other SQLAlchemy imports in `app/scanners/api_scanner/`

### D2: Entrypoint Location — `github-action/entrypoint.py`

**Decision**: Place entrypoint at `github-action/entrypoint.py` in a dedicated directory for all GitHub Action files.

**Details**:
- `github-action/` will contain: `entrypoint.py`, `action.yml` (Phase 2), `Dockerfile.action` (Phase 2)
- Clean separation from platform code
- Dockerfile will COPY `app/scanners/api_scanner/` as a dependency into the image
- Entrypoint is a thin orchestrator: reads env vars → loads spec → calls `run_api_scan()` → sets exit code

### D3: Spec File Loading — Entrypoint Reads and Parses

**Decision**: Entrypoint reads the spec file from disk, detects format (JSON/YAML), and passes the parsed dict to `run_api_scan()`.

**Details**:
- `INPUT_OPENAPI_FILE` → read file → pass as `openapi_spec=` kwarg
- `INPUT_POSTMAN_FILE` → read file → pass as `postman_collection=` kwarg
- One of the two must be provided; error (exit 2) if neither
- `run_api_scan()` signature is NOT modified — platform UI callers unaffected
- JSON detection: try `json.load()` first, fall back to YAML if installed
- For Phase 1, JSON-only is acceptable (OpenAPI specs and Postman collections are typically JSON)

### D4: Auth Input Format — Separate Type + Token

**Decision**: Two separate inputs: `auth-type` (default: `bearer`) and `auth-token`.

**Details**:
- `INPUT_AUTH_TYPE`: one of `bearer`, `api_key`, `api_key_query`, `basic` (default: `bearer`)
- `INPUT_AUTH_TOKEN`: the secret value (masked via `::add-mask::`)
- Entrypoint builds: `auth_config = {"type": auth_type, "token": auth_token}`
- For `basic` auth: token is expected as `username:password` (base64 encoding handled by `build_auth_headers()`)
- `secondary_auth_config` deferred to v2 (CI-01 requirement)
- Auth is optional — scan runs without auth if neither input is provided

### D5: Severity Threshold — Cumulative, Default HIGH

**Decision**: Cumulative threshold where the configured severity and everything above it triggers exit 1. Default is HIGH.

**Details**:
- Severity ordering: CRITICAL > HIGH > MEDIUM > LOW > INFO
- `INPUT_FAIL_ON_SEVERITY=HIGH` → exit 1 if any CRITICAL or HIGH findings exist
- `INPUT_FAIL_ON_SEVERITY=MEDIUM` → exit 1 if any CRITICAL, HIGH, or MEDIUM findings exist
- `INPUT_FAIL_ON_SEVERITY=CRITICAL` → exit 1 only on CRITICAL findings
- `INPUT_FAIL_ON_SEVERITY=LOW` → exit 1 on anything except INFO
- INFO findings NEVER trigger failure regardless of threshold
- Default when not set: `HIGH`
- Comparison uses the `severity_counts` dict from `generate_report()` return value

## Environment Variables (Input Contract)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `INPUT_TARGET_URL` | Yes | — | Base URL of the API to scan |
| `INPUT_OPENAPI_FILE` | One of these | — | Path to OpenAPI spec (JSON) |
| `INPUT_POSTMAN_FILE` | One of these | — | Path to Postman collection (JSON) |
| `INPUT_AUTH_TYPE` | No | `bearer` | Auth type: bearer, api_key, api_key_query, basic |
| `INPUT_AUTH_TOKEN` | No | — | Auth secret value (masked in logs) |
| `INPUT_FAIL_ON_SEVERITY` | No | `HIGH` | Severity threshold for exit code 1 |
| `INPUT_SECORAA_API_KEY` | No | — | Platform API key for callback (Phase 4) |
| `INPUT_TIMEOUT_MINUTES` | No | `10` | Scan timeout in minutes |

## Exit Code Contract

| Code | Meaning | When |
|------|---------|------|
| 0 | Pass | No findings at or above severity threshold |
| 1 | Fail | One or more findings at or above severity threshold |
| 2 | Error | Infrastructure/scanner error (spec parse failure, network error, timeout, invalid inputs) |

## Codebase Touch Points

**Modified files**:
- `app/scanners/api_scanner/main.py` — Add TYPE_CHECKING guard for Session import (line 8)

**New files**:
- `github-action/entrypoint.py` — Thin CLI entrypoint reading INPUT_* env vars

**Unchanged**:
- All 16 test modules in `app/scanners/api_scanner/tests/`
- All engine modules in `app/scanners/api_scanner/engine/`
- Both parsers in `app/scanners/api_scanner/parser/`
- Reporter modules in `app/scanners/api_scanner/reporter/`

## Deferred to Later Phases

- `action.yml` definition → Phase 2
- `Dockerfile.action` → Phase 2
- SARIF output generation → Phase 2
- PR comment posting → Phase 3
- Platform callback → Phase 4
- `secondary_auth_config` (two-token testing) → v2
- YAML spec file support → v2 (JSON covers >95% of use cases)

---
*Context created: 2026-04-04 after discuss-phase*
