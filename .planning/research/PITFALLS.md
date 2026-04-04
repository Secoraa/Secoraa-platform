# Pitfalls: CI/CD API Security Scanning

**Domain:** CI/CD-integrated API security scanning
**Researched:** 2026-04-04

## Critical Pitfalls

### 1. Hard SQLAlchemy Imports in Scanner (BLOCKER)
**Risk:** HIGH | **Phase:** Docker Packaging
**Problem:** `app/scanners/api_scanner/main.py` imports DB models at module scope. The Action Docker image will either need all 70+ platform deps or crash on startup.
**Warning signs:** ImportError on first container test run
**Prevention:** Create a scanner-only import path or lazy-load DB dependencies. The entrypoint must be able to import and call `run_api_scan()` without SQLAlchemy/psycopg2 installed.

### 2. OOB Blind Detection Silent Failure in CI
**Risk:** MEDIUM | **Phase:** Scanner Entrypoint
**Problem:** OOB callback server requires inbound internet connectivity. GitHub-hosted runners are behind NAT — OOB callbacks from scanned APIs cannot reach back.
**Warning signs:** Zero blind SSRF/XXE/SQLi findings in CI that appear in manual platform scans
**Prevention:** Code already handles this (`DEFAULT_OOB_BASE = ""`), but must be documented. Don't advertise blind detection as a CI feature unless external OOB relay is available.

### 3. No Production Scanning Guard
**Risk:** HIGH | **Phase:** Action Inputs Design
**Problem:** Active OWASP tests fire against whatever `base_url` is provided. No guard prevents users from pointing the Action at production APIs. SQLi, SSRF, and BOLA payloads will hit real endpoints.
**Warning signs:** User reports data corruption or service disruption
**Prevention:** Add prominent warning in docs and Action description. Consider optional `--confirm-non-production` flag. Log a warning when target URL doesn't match common staging patterns.

### 4. SARIF 10MB Upload Limit
**Risk:** MEDIUM | **Phase:** SARIF Emitter
**Problem:** Raw evidence dicts from `evidence_collector.py` embedded in SARIF will breach GitHub's 10MB upload limit on APIs with >50 endpoints.
**Warning signs:** SARIF upload silently rejected by GitHub
**Prevention:** Truncate evidence in SARIF output. Include summary + first N bytes of evidence. Full evidence goes in PR comment or platform callback only.

### 5. Exit Code Design
**Risk:** HIGH | **Phase:** Entrypoint
**Problem:** Using only 0/1 exit codes means infrastructure errors (network timeout, spec parse failure) look like "vulnerabilities found" and block PRs incorrectly.
**Warning signs:** Users disable branch protection because "it keeps failing for no reason"
**Prevention:** Use 3 exit codes: 0=pass, 1=findings above threshold, 2=infrastructure/scanner error. Document clearly in action.yml outputs.

### 6. API Key Leakage to GitHub Actions Logs
**Risk:** HIGH | **Phase:** Entrypoint
**Problem:** `request_executor.py` logs request details including headers. API keys will appear in GitHub Actions logs.
**Warning signs:** API keys visible in public repo action logs
**Prevention:** Emit `::add-mask::${API_KEY}` before any other output. Ensure all logging sanitizes the Authorization header.

### 7. scan_name Uniqueness Constraint
**Risk:** MEDIUM | **Phase:** Platform Callback
**Problem:** Existing `scan_name` uniqueness constraint in the Scan model will cause IntegrityError when CI scans sync to platform on re-runs (same PR, same scan name).
**Warning signs:** 500 errors on callback endpoint
**Prevention:** CI scans need a composite identifier: `{repo}/{branch}/{commit_sha}/{run_id}`. Fix or relax the uniqueness constraint for CI-sourced scans.

## Important Pitfalls

### 8. Docker Image Size Bloat
**Risk:** MEDIUM | **Phase:** Docker Packaging
**Problem:** Including full platform requirements.txt creates a 1GB+ image. GitHub Actions downloads the image on every run — slow images get abandoned.
**Prevention:** Create minimal `requirements-scanner.txt` with only scanner dependencies. Target <200MB image. Use multi-stage build.

### 9. GitHub Token Permissions Confusion
**Risk:** MEDIUM | **Phase:** Action Configuration
**Problem:** `GITHUB_TOKEN` has different permission scopes depending on the event trigger and repo settings. `security-events: write` needed for SARIF upload, `pull-requests: write` for PR comments.
**Prevention:** Document required permissions clearly in action.yml. Provide helpful error messages when permissions are insufficient.

### 10. Rate Limiting on GitHub API
**Risk:** LOW | **Phase:** PR Comment Builder
**Problem:** GitHub REST API has rate limits (1000 requests/hour for GITHUB_TOKEN). Unlikely to hit in normal use but possible in monorepos with many concurrent PRs.
**Prevention:** Use single PR comment with update-or-create pattern rather than posting new comments per run.

### 11. Scan Timeout in CI
**Risk:** MEDIUM | **Phase:** Entrypoint
**Problem:** Large APIs (100+ endpoints) can take 10+ minutes to scan. GitHub Actions has a 6-hour job timeout but users expect fast CI.
**Prevention:** Add `timeout-minutes` input (default: 10). Kill scan gracefully and report partial results with a warning.

### 12. Concurrent Scans Against Same Target
**Risk:** LOW | **Phase:** Documentation
**Problem:** Multiple PRs trigger simultaneous scans against the same staging API. Rate limiting tests interfere with each other.
**Prevention:** Document the risk. Suggest using GitHub's `concurrency` key to serialize scans per target URL.

### 13. Spec File Discovery Complexity
**Risk:** LOW | **Phase:** Action Inputs
**Problem:** Users want auto-discovery of OpenAPI specs ("just find it in my repo"). This is a rabbit hole — specs can be in `docs/`, `api/`, generated at build time, or served from a running server.
**Prevention:** Require explicit file path input. Don't attempt auto-discovery in v1.

### 14. SARIF Rule ID Stability
**Risk:** MEDIUM | **Phase:** SARIF Emitter
**Problem:** If rule IDs change between scanner versions, GitHub treats them as different rules. Historical trends break and "fixed" alerts reappear as new ones.
**Prevention:** Use stable OWASP category IDs as rule IDs (e.g., `API1:2023-BOLA`). Never derive rule IDs from finding titles or descriptions.

### 15. Callback Payload Size
**Risk:** LOW | **Phase:** Platform Callback
**Problem:** Full scan results with evidence for large APIs can be several MB. Fire-and-forget POST with large payload may timeout.
**Prevention:** Limit callback payload to summary + findings metadata. Truncate evidence fields. Set 10s timeout on POST.

## Roadmap Implications

1. **Docker packaging must come before SARIF** — can't test SARIF output until container imports cleanly
2. **Action inputs design must happen before implementation** — base_url safety, timeout, exit code contract need to be locked first
3. **Platform callback phase should address scan_name uniqueness bug** — CI feature forces this existing tech debt to be fixed
