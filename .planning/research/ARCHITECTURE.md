# Architecture Research: CI/CD API Security Scanning

**Domain:** CI/CD-integrated API security scanning
**Researched:** 2026-04-04

## Component Decomposition

The system decomposes into **6 clearly bounded components**:

### 1. Scanner Core (existing — unchanged)
- Location: `app/scanners/api_scanner/`
- `run_api_scan()` already accepts `db=None, scan_id=None` and runs fully headlessly
- `_update_progress` helper no-ops when `db=None`
- Zero modifications needed to existing code

### 2. GitHub Action Wrapper (new)
- Location: `github-action/`
- Contains: `action.yml` + `Dockerfile.action` + `entrypoint.py`
- Thin orchestration: reads inputs, calls `run_api_scan()`, drives outputs, sets exit code

### 3. SARIF Emitter (new)
- Location: `sarif_emitter.py`
- Maps report dict to SARIF 2.1.0
- Severity mapping: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFORMATIONAL → `note`
- Rule IDs use `owasp_category`
- Physical locations reference spec file + logical location carries endpoint path

### 4. PR Comment Builder (new)
- Location: `pr_commenter.py`
- Formats findings as Markdown table
- Posts via `GITHUB_TOKEN` to GitHub REST API
- Uses update-or-create pattern to avoid duplicate comments on re-runs

### 5. Platform Callback (new)
- Location: `platform_callback.py`
- Fire-and-forget POST to `/ci-scans` with `X-API-Key` header
- 10s timeout, all exceptions swallowed
- Never blocks the gate

### 6. API Key Management (platform side — new)
- New `ApiKey` table (stores SHA-256 hash, never plaintext)
- New endpoints for generate/list/revoke from Settings page
- New `get_api_key_claims()` FastAPI dependency for CI-facing endpoint

## Data Flow

```
OpenAPI/Postman spec file (from repo)
    │
    ▼
run_api_scan(db=None) ─── scanner core unchanged
    │
    ▼
report dict (findings[], severity_counts, owasp_coverage)
    │
    ├──► SARIF emitter → sarif.json → upload to GitHub Security tab
    │
    ├──► PR comment builder → GitHub REST API → PR comment
    │
    ├──► Platform callback (optional, fire-and-forget) → Secoraa API
    │
    └──► Exit code (0=pass, 1=findings, 2=infra error)
```

## Build Order

Two parallel streams possible:

**Stream A (Platform side):**
1. ApiKey model + migration
2. API key generate/list/revoke endpoints
3. CI scan ingest endpoint (`/api/v1/ci-scans`)
4. CI scan history view in frontend

**Stream B (GitHub Action side):**
1. Scanner entrypoint (reads env vars, calls `run_api_scan`)
2. SARIF emitter
3. PR comment builder
4. Platform callback (fire-and-forget)
5. Docker packaging (Dockerfile.action)
6. action.yml + GHCR publish
7. Documentation + example workflow

**Integration point:** Stream B step 4 (callback) depends on Stream A step 3 (ingest endpoint).

## Anti-Patterns to Avoid

| Anti-Pattern | Why Dangerous |
|--------------|---------------|
| Importing `app.database` in Action container | Causes ImportError with no database present |
| Blocking on platform callback | Kills CI gate when platform is down |
| Sharing platform Dockerfile for Action | 800MB+ image with unnecessary deps |
| Hardcoding GitHub API URLs | Breaks for GitHub Enterprise Server |
| Storing API keys in plaintext | Security vulnerability |
| Single exit code (0/1) | Can't distinguish "scan found issues" from "scan crashed" |
