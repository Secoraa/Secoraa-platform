# Requirements: Secoraa CI/CD API Security Scanner

**Defined:** 2026-04-04
**Core Value:** Every pull request gets automatically scanned for API security vulnerabilities before it can merge

## v1 Requirements

### Scanner Foundation

- [ ] **SCAN-01**: Scanner entrypoint reads inputs from environment variables (INPUT_* convention) and invokes `run_api_scan()` headlessly
- [ ] **SCAN-02**: SQLAlchemy/database imports are decoupled so scanner runs standalone without PostgreSQL or ORM dependencies installed
- [ ] **SCAN-03**: Scanner accepts OpenAPI spec file path as input and parses it for endpoint discovery
- [ ] **SCAN-04**: Scanner accepts Postman collection file path as input and parses it for endpoint discovery
- [ ] **SCAN-05**: Scanner accepts target base URL and auth configuration (bearer token, API key, basic auth)
- [ ] **SCAN-06**: Scanner exits with code 0 (pass), 1 (findings above threshold), or 2 (infrastructure/scanner error)
- [ ] **SCAN-07**: User can configure severity threshold (CRITICAL, HIGH, MEDIUM, LOW) for pass/fail gate via `fail-on-severity` input

### SARIF Output

- [ ] **SARIF-01**: Scanner generates SARIF 2.1.0 conformant JSON output file
- [ ] **SARIF-02**: SARIF rule IDs use stable OWASP category identifiers (e.g., `API1:2023-BOLA`) that persist across scanner versions
- [ ] **SARIF-03**: SARIF severity levels map correctly: CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note
- [ ] **SARIF-04**: SARIF evidence is truncated to keep total file under GitHub's 10MB upload limit
- [ ] **SARIF-05**: SARIF results include physical location (spec file) and logical location (endpoint path)

### GitHub Action

- [ ] **GHA-01**: `action.yml` defines inputs: target-url, openapi-file, postman-file, auth-token, fail-on-severity, secoraa-api-key, timeout-minutes
- [ ] **GHA-02**: Docker container action runs on `ubuntu-latest` GitHub-hosted runners
- [ ] **GHA-03**: Scanner-only Dockerfile excludes platform dependencies (FastAPI, Celery, SQLAlchemy) and produces image under 200MB
- [ ] **GHA-04**: Docker image is published to GHCR (ghcr.io) for zero-rate-limit pulls
- [ ] **GHA-05**: Action uploads SARIF output using `github/codeql-action/upload-sarif` for GitHub Security tab integration

### PR Integration

- [ ] **PR-01**: Action posts PR comment with findings table showing severity, CVSS score, endpoint, vulnerability title, and fix guidance
- [ ] **PR-02**: PR comments use update-or-create pattern to avoid duplicate comments on re-runs
- [ ] **PR-03**: Action creates Check Run via GitHub Check Runs API with pass/fail status based on severity threshold
- [ ] **PR-04**: API keys and sensitive inputs are masked in GitHub Actions logs via `::add-mask::`

### Platform Integration

- [ ] **PLAT-01**: User can generate API keys from Settings page for CI/CD authentication
- [ ] **PLAT-02**: User can list and revoke existing API keys from Settings page
- [ ] **PLAT-03**: API keys are stored as SHA-256 hashes in the database (never plaintext)
- [ ] **PLAT-04**: Action sends scan results to Secoraa API via fire-and-forget POST (10s timeout, all exceptions swallowed)
- [ ] **PLAT-05**: Platform callback is skipped entirely when no API key is provided
- [ ] **PLAT-06**: CI/CD scan history is viewable on the platform with source filter (manual vs ci-cd)
- [ ] **PLAT-07**: CI scan records include branch name, commit SHA, repo name, and workflow metadata

### Documentation

- [ ] **DOC-01**: README includes minimal working `workflow.yml` example that users can copy-paste
- [ ] **DOC-02**: Prominent warning about not scanning production APIs (destructive test payloads)
- [ ] **DOC-03**: Required GitHub token permissions documented (security-events: write, pull-requests: write, checks: write)

## v2 Requirements

### Enhanced CI Features

- **CI-01**: Dual-token privilege escalation testing input (secondary-token for BOLA/BFLA)
- **CI-02**: OWASP API Top 10 coverage map displayed in PR comment
- **CI-03**: Scan result diff / baseline comparison (flag new vs existing findings)
- **CI-04**: Scan timeout with graceful partial results reporting
- **CI-05**: Concurrency guidance for serializing scans per target URL

### Additional CI Providers

- **CIP-01**: GitLab CI integration
- **CIP-02**: Bitbucket Pipelines integration

### Advanced Platform Features

- **ADV-01**: CI scan trend dashboard (are vulns increasing or decreasing over time?)
- **ADV-02**: OOB relay service for blind SSRF/XXE detection in CI runners
- **ADV-03**: Webhook notifications when CI scan finds critical vulnerabilities

## Out of Scope

| Feature | Reason |
|---------|--------|
| Custom scan rule authoring (YAML/DSL) | Large surface area, few users use it — defer until user demand |
| Real-time scan streaming to platform | Creates hard uptime dependency on platform during CI |
| Slack/Teams/PagerDuty notifications from Action | Belongs in platform, not the GitHub Action |
| Browser/UI scan configuration wizard | CI audience works in YAML — adds no value |
| Per-endpoint test selection/exclusion | Complex config surface — ship all-or-nothing first |
| OAuth/OIDC for platform authentication | Impossible from CI runner — API key is correct pattern |
| Auto-discovery of OpenAPI specs in repo | Rabbit hole — require explicit file path |
| GitHub Enterprise Server support | Standard github.com first, GHE later |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SCAN-01 | Phase 1 | Pending |
| SCAN-02 | Phase 1 | Pending |
| SCAN-03 | Phase 1 | Pending |
| SCAN-04 | Phase 1 | Pending |
| SCAN-05 | Phase 1 | Pending |
| SCAN-06 | Phase 1 | Pending |
| SCAN-07 | Phase 1 | Pending |
| SARIF-01 | Phase 2 | Pending |
| SARIF-02 | Phase 2 | Pending |
| SARIF-03 | Phase 2 | Pending |
| SARIF-04 | Phase 2 | Pending |
| SARIF-05 | Phase 2 | Pending |
| GHA-01 | Phase 2 | Pending |
| GHA-02 | Phase 2 | Pending |
| GHA-03 | Phase 2 | Pending |
| GHA-04 | Phase 2 | Pending |
| GHA-05 | Phase 2 | Pending |
| PR-01 | Phase 3 | Pending |
| PR-02 | Phase 3 | Pending |
| PR-03 | Phase 3 | Pending |
| PR-04 | Phase 3 | Pending |
| PLAT-01 | Phase 4 | Pending |
| PLAT-02 | Phase 4 | Pending |
| PLAT-03 | Phase 4 | Pending |
| PLAT-04 | Phase 4 | Pending |
| PLAT-05 | Phase 4 | Pending |
| PLAT-07 | Phase 4 | Pending |
| PLAT-06 | Phase 5 | Pending |
| DOC-01 | Phase 5 | Pending |
| DOC-02 | Phase 5 | Pending |
| DOC-03 | Phase 5 | Pending |

**Coverage:**
- v1 requirements: 31 total
- Mapped to phases: 31
- Unmapped: 0

---
*Requirements defined: 2026-04-04*
*Last updated: 2026-04-04 after roadmap creation*
