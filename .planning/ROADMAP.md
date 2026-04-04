# Roadmap: Secoraa CI/CD API Security Scanner

## Overview

Five phases take the existing API APT scanner from a platform-only UI tool to a GitHub Action that gates pull requests. Phase 1 fixes the import blocker and locks the input/output contract — everything else depends on this. Phase 2 produces a working Docker image with SARIF output published to GHCR. Phase 3 delivers the developer-facing UX: PR comments and merge blocking. Phase 4 closes the loop with the Secoraa platform via API key management and a fire-and-forget callback. Phase 5 completes the end-to-end experience with the CI scan history view and the documentation users need to adopt the action.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Scanner Foundation** - Fix SQLAlchemy import blocker, write entrypoint, lock input/exit code contract
- [ ] **Phase 2: SARIF + Docker Packaging** - Emit valid SARIF 2.1.0, build scanner-only Docker image, publish to GHCR
- [ ] **Phase 3: PR Integration** - Post findings table to PRs, enforce merge gate via Check Runs API
- [ ] **Phase 4: Platform Backend** - API key management, fire-and-forget callback, CI scan ingest endpoint
- [ ] **Phase 5: Platform Frontend + Docs** - CI scan history view, API key settings UI, README and usage documentation

## Phase Details

### Phase 1: Scanner Foundation
**Goal**: Developer-controlled entrypoint calls the scanner cleanly from a context with no database
**Depends on**: Nothing (first phase)
**Requirements**: SCAN-01, SCAN-02, SCAN-03, SCAN-04, SCAN-05, SCAN-06, SCAN-07
**Success Criteria** (what must be TRUE):
  1. Running the entrypoint with INPUT_TARGET_URL and INPUT_OPENAPI_FILE set calls run_api_scan() and produces a report dict without importing SQLAlchemy or psycopg2
  2. Running the entrypoint with a Postman collection file instead of an OpenAPI spec produces a report dict with endpoints discovered from that collection
  3. Entrypoint exits 0 when no findings meet the configured threshold, exits 1 when findings meet or exceed it, and exits 2 when the scanner itself errors
  4. Setting INPUT_FAIL_ON_SEVERITY=HIGH means CRITICAL and HIGH findings trigger exit 1 but MEDIUM and LOW do not
  5. Entrypoint emits ::add-mask:: for the API key value before any log output
**Plans**: TBD

### Phase 2: SARIF + Docker Packaging
**Goal**: A Docker image on GHCR runs the scanner and uploads a valid SARIF file to the GitHub Security tab
**Depends on**: Phase 1
**Requirements**: SARIF-01, SARIF-02, SARIF-03, SARIF-04, SARIF-05, GHA-01, GHA-02, GHA-03, GHA-04, GHA-05
**Success Criteria** (what must be TRUE):
  1. The generated SARIF file passes GitHub's SARIF 2.1.0 schema validation and appears in the repository's Security tab after upload
  2. Each SARIF result has a rule ID that matches a stable OWASP API Top 10 2023 category (e.g., API1:2023-BOLA) and the same finding produces the same rule ID across scanner versions
  3. SARIF severity levels show correctly: CRITICAL/HIGH findings appear as errors, MEDIUM as warnings, LOW/INFO as notes
  4. The SARIF file remains under 10MB even when scanning an API with 50+ endpoints
  5. The Docker image pulls without hitting a rate limit on ubuntu-latest runners and its compressed size is under 200MB
**Plans**: TBD
**UI hint**: no

### Phase 3: PR Integration
**Goal**: Pull requests display a findings table and are blocked from merging when high-severity vulnerabilities are found
**Depends on**: Phase 2
**Requirements**: PR-01, PR-02, PR-03, PR-04
**Success Criteria** (what must be TRUE):
  1. After a scan completes, a comment appears on the pull request showing severity, CVSS score, endpoint, vulnerability title, and fix guidance for each finding
  2. Re-running the workflow on the same PR updates the existing comment rather than posting a new one
  3. A Check Run named for the action appears on the PR with a pass/fail status that reflects whether findings exceeded the configured severity threshold, and branch protection can use it as a required check
  4. The SARIF API key and auth token values never appear in plain text in the GitHub Actions log
**Plans**: TBD
**UI hint**: no

### Phase 4: Platform Backend
**Goal**: The Secoraa platform can issue API keys for CI/CD auth and receive scan results from the GitHub Action via a non-blocking callback
**Depends on**: Phase 2
**Requirements**: PLAT-01, PLAT-02, PLAT-03, PLAT-04, PLAT-05, PLAT-07
**Success Criteria** (what must be TRUE):
  1. A user can generate a new API key from the Settings page; the full key is shown once at generation time and is never retrievable again
  2. A user can see all active API keys (name, creation date, last used) and revoke any of them; a revoked key immediately stops accepting CI scan callbacks
  3. When the GitHub Action completes and an API key is configured, a POST to the platform ingest endpoint records the scan result including branch name, commit SHA, repo name, and workflow run ID — and the CI pipeline does not wait for or care about the response
  4. When no API key is provided, the callback is skipped entirely and the pipeline exits with the same code it would have without platform integration
  5. Submitting two scans with the same repo/branch/commit/run combination does not cause an IntegrityError
**Plans**: TBD

### Phase 5: Platform Frontend + Docs
**Goal**: Users can view CI scan history on the platform and developers can copy a working workflow.yml from the README
**Depends on**: Phase 4
**Requirements**: PLAT-06, DOC-01, DOC-02, DOC-03
**Success Criteria** (what must be TRUE):
  1. The platform shows a scan history list that can be filtered to display only CI/CD-sourced scans separately from manual scans
  2. A developer new to the action can copy the workflow.yml example from the README, add their target URL and spec file path, and have a working pipeline without reading anything else
  3. The README contains a visible warning that test payloads are destructive and the action must not be pointed at production APIs
  4. The required GitHub token permissions (security-events: write, pull-requests: write, checks: write) are documented in the README
**Plans**: TBD
**UI hint**: yes

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Scanner Foundation | 0/TBD | Not started | - |
| 2. SARIF + Docker Packaging | 0/TBD | Not started | - |
| 3. PR Integration | 0/TBD | Not started | - |
| 4. Platform Backend | 0/TBD | Not started | - |
| 5. Platform Frontend + Docs | 0/TBD | Not started | - |
