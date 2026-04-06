# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-04)

**Core value:** Every pull request gets automatically scanned for API security vulnerabilities before it can merge
**Current focus:** Phase 1 — Scanner Foundation

## Current Position

Phase: 1 of 5 (Scanner Foundation)
Plan: 0 of TBD in current phase
Status: Context complete, ready to plan
Last activity: 2026-04-04 — Phase 1 discuss-phase complete, CONTEXT.md written

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: -
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: none yet
- Trend: -

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Init: SQLAlchemy import decoupling is a hard blocker — Phase 1 must resolve before Docker packaging
- Init: Docker container action on GHCR chosen over Docker Hub to avoid rate limits on shared runners
- Init: Three exit codes (0/1/2) required — using only 0/1 causes infra errors to look like findings
- Init: Platform callback is fire-and-forget (10s timeout, exceptions swallowed) so CI gate never depends on Secoraa uptime
- P1: SQLAlchemy decoupled via TYPE_CHECKING guard (only line 8 of main.py needs change)
- P1: Entrypoint lives at github-action/entrypoint.py — dedicated directory for Action files
- P1: Auth inputs: separate auth-type (default bearer) + auth-token; entrypoint builds dict
- P1: Severity threshold is cumulative (HIGH = CRITICAL+HIGH trigger exit 1), default HIGH
- P1: Entrypoint reads spec file from disk, parses JSON, passes to run_api_scan() — no signature changes

### Pending Todos

None yet.

### Blockers/Concerns

- Phase 4: scan_name uniqueness constraint fix — need to inspect current migration history and Scan model before implementing. CI scan composite identifier: {repo}/{branch}/{commit_sha}/{run_id}.
- Phase 2: Verify github/codeql-action/upload-sarif current major version before implementation.
- Phase 2: Verify Python 3.11 slim base image has no outstanding CVEs before publishing to GHCR.

## Session Continuity

Last session: 2026-04-04
Stopped at: Phase 1 discuss-phase complete. 01-CONTEXT.md written with 5 decisions. Ready to plan Phase 1.
Resume file: .planning/phases/01-scanner-foundation/01-CONTEXT.md
