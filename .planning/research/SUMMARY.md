# Project Research Summary

**Project:** Secoraa GitHub Actions API Security Scanner
**Domain:** CI/CD-integrated API security scanning (GitHub Actions delivery)
**Researched:** 2026-04-04
**Confidence:** HIGH

## Executive Summary

This project is a GitHub Actions delivery surface for Secoraa's existing API security scanner — not a new scanner build. The scanner core (`app/scanners/api_scanner/`) is already feature-complete: 11 per-endpoint OWASP test categories, 5 global checks, CVSS scoring, SARIF-ready report dicts, and headless operation via `run_api_scan(db=None)`. The CI/CD milestone is 100% about wrapping that core in a GitHub Action that produces SARIF output, posts PR comments, sets exit codes, and optionally syncs results to the Secoraa platform. No scanner capability needs to be added.

The recommended approach is a Docker container action hosted on GHCR with a thin Python entrypoint, a standalone SARIF 2.1.0 emitter built from stdlib json (~100 lines), a PR comment builder using `httpx` (already in requirements), and a fire-and-forget platform callback. The action uses a separate scanner-only Dockerfile — not the platform's Dockerfile — to keep the image under 200MB. Zero new Python dependencies are needed. The platform side adds an ApiKey model, generate/list/revoke endpoints, and a CI scan ingest endpoint; this stream can proceed in parallel with the Action build.

The primary risk is import-level coupling: `app/scanners/api_scanner/main.py` imports DB models at module scope, which will cause an ImportError in the Action container (no PostgreSQL or SQLAlchemy installed). This must be resolved before any Docker packaging work can begin. A secondary risk is OOB blind detection silently failing in CI due to NAT — GitHub-hosted runners cannot receive inbound callbacks — which needs to be documented and not advertised unless an external OOB relay is provided. All other risks are well-understood with clear mitigations.

---

## Key Findings

### Recommended Stack

The action requires no new Python dependencies. The existing `requirements.txt` covers everything: `httpx 0.28.1` handles GitHub REST API calls and platform callbacks, `asyncio` runs the scanner, and stdlib `json` builds SARIF 2.1.0 output. GHCR (not Docker Hub) is the correct image registry to avoid 100-pulls/6h rate limits on shared CI runners. The `Check Runs API` (not the legacy commit status API) is the right mechanism for merge blocking because it supports inline PR diff annotations.

A separate `Dockerfile.action` is mandatory — importing the full platform Dockerfile would add FastAPI, Celery, SQLAlchemy, OTel, and pandas to an image that needs none of them, resulting in 800MB+ bloat. Inputs arrive as `INPUT_*` environment variables per GitHub Actions Docker convention; no CLI argument parsing library is needed.

**Core technologies:**
- `Docker container action` — only action type that packages a Python runtime
- `httpx 0.28.1` — GitHub REST API + platform callback; already in requirements, no new dep
- `stdlib json` — hand-built SARIF 2.1.0; third-party SARIF libs are either read-only or unmaintained since 2021
- `Check Runs API` — merge blocking with inline diff annotations; superior to legacy commit status
- `GHCR` — zero rate limits for public repos; Docker Hub breaks shared CI runners

**Critical version requirement:** Python 3.11 slim base image — verify current security patch status before publishing.

### Expected Features

The scanner core is feature-complete. The CI/CD surface has 6 must-ship items and 3 non-blocking additions. No other CI/CD scanner combines self-contained deployment + OOB blind detection + two-token BOLA + CVSS scores + Postman collection support — this is a genuine differentiator set.

**Must have (table stakes — unusable without):**
- Docker image published to GHCR with scanner entrypoint
- SARIF 2.1.0 output file for GitHub Security tab integration
- PR comment with findings table (primary developer UX)
- Exit code gate: 0=pass, 1=findings above threshold, 2=infra/scanner error
- Core inputs: `target-url`, `openapi-file`/`postman-file`, `auth-token`, `fail-on-severity`
- Minimal working `workflow.yml` example in docs

**Should have (differentiators, not blocking launch):**
- Optional platform callback for CI scan history (opt-in with `secoraa-api-key`)
- API key management in platform Settings (generate/list/revoke)
- CI scan history view in platform frontend
- OWASP coverage map in PR comment
- Branch/commit metadata in findings for traceability

**Defer to v2+:**
- GitLab CI / Bitbucket support
- Custom scan rule authoring
- Scan result diff / baseline comparison
- Real-time scan streaming to platform
- Per-endpoint test selection/exclusion
- OAuth/OIDC for platform auth (impossible from CI runner)
- Spec file auto-discovery (rabbit hole, require explicit path)

### Architecture Approach

The system decomposes into 6 components across two parallel build streams. The Action side (Stream B) and Platform side (Stream A) can proceed independently until Stream B step 4 (platform callback), which depends on Stream A step 3 (CI scan ingest endpoint). The scanner core remains entirely unmodified — `run_api_scan(db=None)` already runs headlessly. New code is entirely in the delivery layer.

**Major components:**
1. **Scanner Core** (`app/scanners/api_scanner/`) — existing, zero changes; runs headlessly when `db=None`
2. **GitHub Action Wrapper** (`github-action/action.yml` + `Dockerfile.action` + `entrypoint.py`) — thin orchestration: reads env vars, calls scanner, drives outputs
3. **SARIF Emitter** (`sarif_emitter.py`) — maps report dict to SARIF 2.1.0; stable OWASP category IDs as rule IDs
4. **PR Comment Builder** (`pr_commenter.py`) — update-or-create pattern to avoid duplicate comments on re-runs
5. **Platform Callback** (`platform_callback.py`) — fire-and-forget POST, 10s timeout, all exceptions swallowed
6. **API Key Management** (platform side) — `ApiKey` table with SHA-256 hashed keys; generate/list/revoke endpoints

**Data flow:** spec file → `run_api_scan()` → report dict → [SARIF file | PR comment | platform callback | exit code]

### Critical Pitfalls

1. **Hard SQLAlchemy imports at module scope (BLOCKER)** — `app/scanners/api_scanner/main.py` imports DB models at module scope; the Action container has no SQLAlchemy/psycopg2 installed and will crash. Must create a scanner-only import path or lazy-load DB dependencies before any Docker packaging work.

2. **API key leakage to GitHub Actions logs** — `request_executor.py` logs headers including Authorization; API keys will appear in public repo logs. Emit `::add-mask::${API_KEY}` as the first action output and sanitize all header logging.

3. **Exit code design** — using only 0/1 means infra errors look like "vulnerabilities found" and block PRs incorrectly, causing users to disable branch protection. Use 3 codes: 0=pass, 1=findings above threshold, 2=infra/scanner error.

4. **SARIF 10MB upload limit** — raw evidence dicts embedded in SARIF will exceed GitHub's 10MB limit on APIs with 50+ endpoints. Truncate evidence in SARIF; full evidence goes to PR comment or platform callback only.

5. **scan_name uniqueness constraint** — the existing `scan_name` uniqueness constraint causes IntegrityError when CI scans sync to platform on re-runs (same PR, same scan name). CI scans need composite identifier: `{repo}/{branch}/{commit_sha}/{run_id}`.

6. **OOB blind detection silent failure** — GitHub-hosted runners are behind NAT; OOB callbacks cannot reach back. Do not advertise blind SSRF/XXE detection as a CI feature in v1 unless external OOB relay is provided.

---

## Implications for Roadmap

The PITFALLS.md is explicit about build order constraints. ARCHITECTURE.md confirms two parallel streams. The following phase structure reflects actual dependency ordering.

### Phase 1: Foundation — Scanner Entrypoint + Import Fix
**Rationale:** The SQLAlchemy import blocker must be resolved before anything else can be tested. This phase also locks the action input contract (base_url, spec file, auth, severity threshold, timeout) and exit code design — decisions that cascade into every subsequent phase.
**Delivers:** A working `entrypoint.py` that can call `run_api_scan()` cleanly from a context with no database; locked input/output contract; 3-tier exit code logic; `::add-mask::` for API key protection.
**Addresses:** GitHub Action `with:` inputs, auth configuration, severity threshold, scan timeout input
**Avoids:** SQLAlchemy import blocker (Pitfall 1), exit code design failure (Pitfall 3), API key leakage (Pitfall 2)
**Research flag:** Standard patterns — no deeper research needed. The import fix is a known refactor pattern.

### Phase 2: SARIF Emitter + Docker Packaging
**Rationale:** SARIF output is the core integration point with GitHub Security tab and PR annotations. Docker packaging must exist before SARIF can be tested end-to-end. Both are tightly coupled and blocked only by Phase 1 completing.
**Delivers:** `sarif_emitter.py` producing valid SARIF 2.1.0; `Dockerfile.action` with scanner-only deps; image published to GHCR; SARIF upload via `github/codeql-action/upload-sarif`.
**Uses:** stdlib json; Python 3.11 slim image; GHCR registry
**Implements:** SARIF Emitter component; Docker packaging
**Avoids:** SARIF 10MB limit (truncate evidence, Pitfall 4); SARIF rule ID instability (use stable OWASP category IDs, Pitfall 14); image size bloat (scanner-only Dockerfile, Pitfall 8)
**Research flag:** Standard patterns — SARIF 2.1.0 spec is well-documented. Verify `github/codeql-action/upload-sarif` current version.

### Phase 3: PR Comment Builder + Merge Gate
**Rationale:** PR comment is the primary developer UX. Merge blocking via Check Runs API ties the exit code from Phase 1 to actual branch protection enforcement. Both depend on Phase 2 (Docker image must be published to test end-to-end).
**Delivers:** `pr_commenter.py` posting a findings table to PRs with update-or-create to avoid duplicates; OWASP coverage map in comment; Check Runs API call for merge blocking; required GitHub Token permissions documented in action.yml.
**Implements:** PR Comment Builder component
**Avoids:** Duplicate comment spam on re-runs (Pitfall 10 pattern); GitHub Token permission confusion (Pitfall 9)
**Research flag:** Standard patterns — GitHub REST API endpoints for PR comments and Check Runs are stable and well-documented.

### Phase 4: Platform Callback + API Key Management
**Rationale:** This phase closes the loop between CI scans and the Secoraa platform. It can be partially developed in parallel with Phases 2-3 (platform side: ApiKey model, endpoints) but the callback integration needs the Action image from Phase 2. Addresses the scan_name uniqueness tech debt that CI forces to be fixed.
**Delivers:** `platform_callback.py` (fire-and-forget, 10s timeout, exceptions swallowed); `ApiKey` model with SHA-256 hashing; generate/list/revoke API endpoints; `/api/v1/ci-scans` ingest endpoint; scan_name uniqueness constraint fixed for CI sources; composite CI scan identifier.
**Implements:** Platform Callback + API Key Management components
**Avoids:** Platform callback blocking CI gate (Pitfall — fire-and-forget required); scan_name uniqueness IntegrityError (Pitfall 7); callback payload timeout (truncate evidence, Pitfall 15)
**Research flag:** Needs attention — the scan_name uniqueness fix touches the existing Scan model and may have migration implications. Verify constraint scope before implementation.

### Phase 5: Platform Frontend + Documentation
**Rationale:** CI scan history view and documentation are non-blocking for the Action to work but are required for the feature to be discoverable and useful. This phase completes the end-to-end experience.
**Delivers:** CI scan history view in platform frontend; API key management UI in Settings; minimal working `workflow.yml` example; README with required permissions, production scanning warning, OOB limitation note; `--confirm-non-production` flag or prominent warning.
**Addresses:** CI scan history (should-have), API key management UI (should-have), docs (table stakes for adoption)
**Avoids:** Production scanning safety risk (Pitfall 3 — prominent warning required); OOB expectation mismatch (document CI limitation); concurrent scan interference (document `concurrency` key usage)
**Research flag:** Standard patterns — frontend history view follows existing platform UI patterns.

### Phase Ordering Rationale

- **Phase 1 must be first** — the SQLAlchemy import blocker and input/exit code contract both cascade into everything downstream. Nothing can be tested until this is resolved.
- **Phase 2 before Phase 3** — SARIF upload and Docker publishing must exist before the PR comment builder can be tested end-to-end in a real workflow.
- **Phase 4 partially parallelizable** — the platform side (ApiKey model, endpoints) can be built during Phases 2-3; only the callback integration in `entrypoint.py` needs the published image.
- **Phase 5 last** — documentation accurately reflects the final input contract; frontend follows after backend endpoints are stable.
- **Two streams explicit:** Stream A (platform: ApiKey model → endpoints → ingest → frontend) and Stream B (entrypoint → SARIF → PR comment → callback → Docker → docs) can proceed in parallel with one integration point at Phase 4.

### Research Flags

Phases needing deeper research during planning:
- **Phase 4:** scan_name uniqueness constraint fix — need to inspect current migration history and Scan model constraints to determine migration scope and whether existing data is affected.

Phases with standard patterns (skip research-phase):
- **Phase 1:** Python lazy-import / import guard pattern is well-established
- **Phase 2:** SARIF 2.1.0 spec is public; Docker multi-stage builds are standard; GHCR publish workflow is documented
- **Phase 3:** GitHub REST API for PR comments and Check Runs is stable and extensively documented
- **Phase 5:** Platform frontend follows existing Secoraa UI patterns; docs are write-only

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Validated against existing codebase (`requirements.txt`, scanner source). Zero new deps confirmed by code inspection. |
| Features | HIGH | Competitive matrix grounded in actual competitor feature sets. Must-have list derived from table stakes analysis, not opinion. |
| Architecture | HIGH | Component boundaries derived from existing code structure. `run_api_scan(db=None)` headless operation confirmed by reading source. |
| Pitfalls | HIGH | Most pitfalls identified by reading actual code (`main.py` imports, `request_executor.py` logging, `scan_name` constraint). Not hypothetical. |

**Overall confidence:** HIGH

### Gaps to Address

- **OOB relay decision:** Whether to offer an external OOB relay service for blind SSRF/XXE detection in CI is a product decision not resolved by research. Defer to v2 or document limitation clearly in v1.
- **`github/codeql-action/upload-sarif` current version:** Research noted this needs verification. Confirm current major version before Phase 2 implementation.
- **Python 3.11 slim image security patch status:** Verify no outstanding CVEs in the base image before publishing to GHCR.
- **Scan model migration scope:** The scan_name uniqueness fix in Phase 4 needs a migration plan. Inspect existing migration files to determine whether a new migration or constraint modification is appropriate.
- **GitHub Enterprise Server compatibility:** `GITHUB_SERVER_URL` env var should be used for API base URL to avoid hardcoding `api.github.com`. Verify this is plumbed through all API calls in Phase 3.

---

## Sources

### Primary (HIGH confidence)
- Secoraa codebase — `app/scanners/api_scanner/main.py`, `engine/oob_server.py`, `requirements.txt`, `run_api_scan()` signature; direct code inspection
- GitHub Actions documentation — Docker container action spec, `INPUT_*` env var convention, Check Runs API, SARIF upload action
- GitHub SARIF specification — 2.1.0 schema; 10MB upload limit confirmed from GitHub docs

### Secondary (MEDIUM confidence)
- GHCR documentation — rate limit comparison with Docker Hub
- Competitor feature matrix — StackHawk, 42Crunch, Escape, ZAP Action feature pages (current as of research date)
- OWASP API Top 10 2023 — category IDs used as stable SARIF rule ID anchors

### Tertiary (LOW confidence)
- Image size estimates (800MB platform image, <200MB scanner-only target) — based on known dep weights; verify with actual Docker builds in Phase 2
- Scan timeout estimates (10+ minutes for 100+ endpoint APIs) — based on OWASP test category count; validate with real-world testing

---

*Research completed: 2026-04-04*
*Ready for roadmap: yes*
