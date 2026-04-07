# Phase 1 Research: Scanner Foundation

**Phase:** 01-scanner-foundation
**Goal:** Developer-controlled entrypoint calls the scanner cleanly from a context with no database
**Requirements:** SCAN-01, SCAN-02, SCAN-03, SCAN-04, SCAN-05, SCAN-06, SCAN-07
**Researched:** 2026-04-07

## Scope

Phase 1 creates `github-action/entrypoint.py` and modifies exactly one line in `app/scanners/api_scanner/main.py`. No action.yml, no Dockerfile, no SARIF emitter — those land in Phase 2.

## Key Findings

### F1: Only One SQLAlchemy Import Blocks Standalone Use

**Location:** `app/scanners/api_scanner/main.py:8`
```python
from sqlalchemy.orm import Session
```

**Purpose:** Used ONLY as type annotation in function signatures:
- `def _update_progress(db, scan_id, ...)` — no type annotation in signature, uses `# type: (Optional[Session], ...)` comment
- `def _is_cancelled(db, scan_id)` — same pattern
- `async def run_api_scan(..., db: Optional[Session] = None, ...)` — line 192, PEP 484 annotation

Every other reference to `Scan` model is inside `if not db or not scan_id: return` guards (lines 55, 77) — already lazy.

**Fix:** `TYPE_CHECKING` guard. Because `from __future__ import annotations` is already at line 1, all annotations are strings at runtime and never evaluated. This is a cosmetic change that makes imports fail gracefully without sqlalchemy installed.

**Verification command:**
```bash
cd /path/to/repo
python -c "import sys; sys.modules['sqlalchemy'] = None; from app.scanners.api_scanner.main import run_api_scan; print('OK')"
```

Should print `OK`. Without the fix, it raises `ImportError: No module named 'sqlalchemy'`.

### F2: run_api_scan() Already Headless-Ready

**Signature** (`main.py:182`):
```python
async def run_api_scan(
    *,
    scan_name: str,
    asset_url: str,
    postman_collection: Optional[Dict[str, Any]] = None,
    endpoints: Optional[List[Dict[str, Any]]] = None,
    openapi_spec: Optional[Any] = None,
    auth_config: Optional[Dict[str, Any]] = None,
    secondary_auth_config: Optional[Dict[str, Any]] = None,
    scan_mode: str = "active",
    db: Optional[Session] = None,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
```

All DB params already optional and default `None`. Zero scanner-core changes needed beyond F1.

### F3: Parser Input Contracts

**`parse_openapi(spec: Any)`** (`openapi_parser.py:51`):
- Accepts dict (already parsed) OR raw string (auto-detects JSON vs YAML)
- YAML support requires `pyyaml` — already in requirements.txt (`PyYAML 6.0.3`)
- Simplest entrypoint path: read file → pass string → let parser auto-detect

**`parse_postman(collection: Dict)`** (`postman_parser.py:4`):
- Accepts ONLY dict
- Postman collections are always JSON — entrypoint must `json.load(open(path))` before passing

**Implication for entrypoint:**
```python
if openapi_file:
    with open(openapi_file) as f:
        openapi_spec = f.read()  # parse_openapi handles JSON/YAML
elif postman_file:
    with open(postman_file) as f:
        postman_collection = json.load(f)
```

### F4: Report Dict Structure — severity_counts Key

**`generate_report()`** (`reporter/report_generator.py:44`) returns:
```python
{
    "scan_name": ...,
    "base_url": ...,
    "severity_counts": {
        "CRITICAL": int,
        "HIGH": int,
        "MEDIUM": int,
        "LOW": int,
        "INFORMATIONAL": int,
    },
    "findings": [...],
    "total_findings": int,
    "owasp_coverage": {...},
    ...
}
```

**Severity value note:** Scanner uses `INFORMATIONAL` (full word), NOT `INFO`. Entrypoint threshold logic must normalize both.

**Severity threshold logic (pseudo-code):**
```python
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}

def exceeds_threshold(severity_counts: dict, threshold: str) -> bool:
    threshold_level = SEVERITY_ORDER[threshold.upper()]
    for sev, count in severity_counts.items():
        if count > 0 and SEVERITY_ORDER.get(sev, 99) <= threshold_level:
            # INFORMATIONAL never triggers failure per CONTEXT D5
            if sev == "INFORMATIONAL":
                continue
            return True
    return False
```

### F5: GitHub Actions ::add-mask:: Workflow Command

**Syntax:** Print a single line to stdout before any other output:
```
::add-mask::<value>
```

GitHub Actions runner intercepts this line and adds the value to its redaction list. Subsequent appearances of the value in logs are replaced with `***`.

**Rules:**
- Must be on its own line
- Must appear BEFORE the secret value is logged elsewhere
- Only works inside GitHub Actions runners (harmless no-op elsewhere)
- Empty/missing values should be skipped (printing `::add-mask::` alone does nothing harmful but is noise)

**Entrypoint pattern:**
```python
import os, sys

def mask(value: str):
    if value:
        print(f"::add-mask::{value}", flush=True)

# First thing in main():
mask(os.environ.get("INPUT_AUTH_TOKEN", ""))
mask(os.environ.get("INPUT_SECORAA_API_KEY", ""))
```

### F6: Exit Code Contract and Python Conventions

Python's `sys.exit(code)` is the standard way to set process exit code. Docker containers inherit the process exit code. GitHub Actions reads it to determine step success/failure.

**Entrypoint should use three distinct paths:**

```python
def main() -> int:
    try:
        # validate inputs
        if not target_url:
            log_error("INPUT_TARGET_URL is required")
            return 2
        if not (openapi_file or postman_file):
            log_error("Either INPUT_OPENAPI_FILE or INPUT_POSTMAN_FILE is required")
            return 2
        # parse spec
        # run scan
        report = asyncio.run(run_api_scan(...))
        # check threshold
        if exceeds_threshold(report["severity_counts"], threshold):
            return 1
        return 0
    except Exception as e:
        log_error(f"Scanner error: {e}")
        traceback.print_exc()
        return 2

if __name__ == "__main__":
    sys.exit(main())
```

**Key principles:**
- Input validation errors → exit 2 (not 1) — matches PITFALLS.md finding #5
- ANY uncaught exception → exit 2
- Only "findings at/above threshold" triggers exit 1

### F7: Environment Variable Reading Patterns

GitHub Actions passes inputs via `INPUT_<NAME>` env vars (uppercased, dashes → underscores). Standard Python:

```python
def get_input(name: str, default: str = "") -> str:
    """Read GitHub Action input from INPUT_<NAME> env var."""
    return os.environ.get(f"INPUT_{name.upper().replace('-', '_')}", default).strip()
```

**Inputs from CONTEXT.md D5:**
| Input | Env Var | Default |
|-------|---------|---------|
| target-url | INPUT_TARGET_URL | (required) |
| openapi-file | INPUT_OPENAPI_FILE | "" |
| postman-file | INPUT_POSTMAN_FILE | "" |
| auth-type | INPUT_AUTH_TYPE | "bearer" |
| auth-token | INPUT_AUTH_TOKEN | "" |
| fail-on-severity | INPUT_FAIL_ON_SEVERITY | "HIGH" |
| secoraa-api-key | INPUT_SECORAA_API_KEY | "" |
| timeout-minutes | INPUT_TIMEOUT_MINUTES | "10" |

### F8: Async Runtime — asyncio.run() Pattern

`run_api_scan()` is `async def`. Entrypoint is sync. Use `asyncio.run(coro)` at the top level:

```python
import asyncio
report = asyncio.run(run_api_scan(
    scan_name=scan_name,
    asset_url=target_url,
    openapi_spec=openapi_spec_str,
    auth_config=auth_config,
    scan_mode="active",
))
```

`asyncio.run()` creates a new event loop, runs the coroutine to completion, and cleans up. Safe for one-shot CLI use.

### F9: Timeout Handling

`INPUT_TIMEOUT_MINUTES` should wrap the scan call:

```python
timeout_seconds = int(os.environ.get("INPUT_TIMEOUT_MINUTES", "10")) * 60
try:
    report = asyncio.run(
        asyncio.wait_for(run_api_scan(...), timeout=timeout_seconds)
    )
except asyncio.TimeoutError:
    log_error(f"Scan exceeded {timeout_seconds}s timeout")
    return 2
```

**Note:** Graceful partial-results reporting on timeout is a v2 feature (CI-04). Phase 1 just exits cleanly with code 2.

### F10: Scan Name Generation for CI Context

`run_api_scan()` requires `scan_name: str`. In CI context, derive from env vars GitHub provides:

```python
scan_name = (
    f"ci-{os.environ.get('GITHUB_REPOSITORY', 'local')}-"
    f"{os.environ.get('GITHUB_SHA', 'nosha')[:8]}-"
    f"{int(time.time())}"
)
```

This gives uniqueness for logging. Database-side scan_name uniqueness is a Phase 4 concern (see STATE.md blockers).

## Validation Architecture

Phase 1 success criteria map to these verification commands:

### V1: Standalone Import Test
**Criterion:** "Produces a report dict without importing SQLAlchemy or psycopg2"

**Command:**
```bash
python -c "
import sys
# Block sqlalchemy from being imported
class Blocker:
    def find_module(self, name, path=None):
        if name.startswith('sqlalchemy') or name.startswith('psycopg2'):
            return self
    def load_module(self, name):
        raise ImportError(f'{name} is blocked')
sys.meta_path.insert(0, Blocker())

# Now try to import the scanner
from app.scanners.api_scanner.main import run_api_scan
print('IMPORT_OK')
"
```

**Expected:** Prints `IMPORT_OK`. Exit code 0.

### V2: OpenAPI Spec Scan Test
**Criterion:** "INPUT_TARGET_URL + INPUT_OPENAPI_FILE produces a report dict"

**Setup:** Use existing `tests/vulnerable_api.py` as mock target (it exposes an OpenAPI spec on `/openapi.json`). Save to `/tmp/test_openapi.json`.

**Command:**
```bash
INPUT_TARGET_URL=http://localhost:8001 \
INPUT_OPENAPI_FILE=/tmp/test_openapi.json \
INPUT_FAIL_ON_SEVERITY=CRITICAL \
python github-action/entrypoint.py
echo "Exit: $?"
```

**Expected:** Exit 0, 1, or 2 depending on findings; stdout contains `"severity_counts"` from report.

### V3: Postman Collection Scan Test
**Criterion:** "INPUT_POSTMAN_FILE produces a report dict with endpoints discovered from that collection"

**Setup:** Hand-craft minimal Postman collection JSON at `/tmp/test_postman.json` with 2 endpoints.

**Command:**
```bash
INPUT_TARGET_URL=http://localhost:8001 \
INPUT_POSTMAN_FILE=/tmp/test_postman.json \
python github-action/entrypoint.py
```

**Expected:** Report dict produced, `total_endpoints == 2`.

### V4: Exit Code Contract
**Criterion:** "Exits 0, 1, 2 correctly"

**Test matrix:**
- No findings + threshold=HIGH → exit 0
- HIGH finding + threshold=HIGH → exit 1
- HIGH finding + threshold=CRITICAL → exit 0
- Invalid INPUT_TARGET_URL (empty) → exit 2
- Missing spec file → exit 2
- Unreadable JSON → exit 2

### V5: Mask Emission Test
**Criterion:** "Entrypoint emits ::add-mask:: for the API key value before any log output"

**Command:**
```bash
INPUT_TARGET_URL=http://localhost:8001 \
INPUT_OPENAPI_FILE=/tmp/test_openapi.json \
INPUT_AUTH_TOKEN=secret123 \
python github-action/entrypoint.py 2>&1 | head -5
```

**Expected:** First or second line contains `::add-mask::secret123`. No `secret123` appears in any other log line.

## Pitfalls / Gotchas

### P1: `from __future__ import annotations` Is Critical
The TYPE_CHECKING fix RELIES on `from __future__ import annotations` (line 1 of main.py). Without it, the `db: Optional[Session]` annotation on line 192 would be evaluated at function definition time and crash. Already present, but DO NOT REMOVE during cleanup.

### P2: Severity Key Is "INFORMATIONAL" Not "INFO"
CONTEXT.md says "INFO never triggers failure." The actual key in `severity_counts` is `INFORMATIONAL`. Entrypoint threshold code must use the full word.

### P3: asset_url Must Be Provided
`run_api_scan()` requires `asset_url` kwarg (not optional). Entrypoint must pass INPUT_TARGET_URL as asset_url, and exit 2 if missing.

### P4: Scanner Makes Real HTTP Requests
Phase 1 smoke tests need a local mock target. Options:
- Use `tests/vulnerable_api.py` (exists in repo) as throwaway test server
- Use `httpbin` Docker image
- Use `python -m http.server` with stub JSON responses (limited — no POST/PUT)

Plan should pick ONE approach and document the test fixture command.

### P5: Cancellation & Progress Still Reference DB
`_update_progress()` and `_is_cancelled()` short-circuit when `db=None`. They are called throughout the scan loop. This works correctly but generates zero progress output in CI. Phase 1 does NOT add CI progress logging (deferred). Plan should note this as a known limitation.

### P6: Working Directory Assumption
Entrypoint imports `from app.scanners.api_scanner.main import run_api_scan`. This requires `app/` to be on Python path. The entrypoint script must either:
- Add repo root to `sys.path` (`sys.path.insert(0, '/app')` or similar)
- Be run from repo root with `PYTHONPATH=.`
- Install the scanner as a package (deferred to Phase 2 Dockerfile)

**Phase 1 recommendation:** Add explicit `sys.path` manipulation at top of entrypoint (before any `app.*` imports). Phase 2 Docker build will handle this cleanly; Phase 1 only needs local-run capability.

### P7: Logging Goes to stderr by Default
Python's default logging writes to stderr. GitHub Actions captures stderr. `::add-mask::` must go to stdout (not stderr). Plan must use `print(..., flush=True)` for workflow commands, not `logger.info`.

## Dependencies & Versions

**Already in requirements.txt:**
- `PyYAML 6.0.3` — for OpenAPI YAML specs
- `httpx 0.28.1` — scanner's HTTP client
- `aiohttp 3.10.11` — async HTTP
- Python 3.11

**New dependencies needed:** NONE for Phase 1. The entrypoint uses only stdlib: `os`, `sys`, `json`, `asyncio`, `logging`, `traceback`, `time`.

## References

- `app/scanners/api_scanner/main.py` — Scanner entry point (1 line to modify)
- `app/scanners/api_scanner/parser/openapi_parser.py:51` — parse_openapi signature
- `app/scanners/api_scanner/parser/postman_parser.py:4` — parse_postman signature
- `app/scanners/api_scanner/reporter/report_generator.py:14` — report dict structure
- `tests/vulnerable_api.py` — intentionally vulnerable mock API for smoke tests
- GitHub Actions workflow commands: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#masking-a-value-in-log
- `.planning/phases/01-scanner-foundation/01-CONTEXT.md` — User decisions (D1-D5)

---

## RESEARCH COMPLETE

All 7 requirements (SCAN-01 through SCAN-07) have clear implementation paths. Zero open questions for planning. No external web research needed — all answers derived from existing codebase inspection and prior decisions in CONTEXT.md.
