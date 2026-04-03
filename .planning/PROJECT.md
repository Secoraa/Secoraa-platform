# Secoraa CI/CD API Security Scanner

## What This Is

A CI/CD API security scanning feature for the Secoraa platform that enables developers to automatically test their APIs for vulnerabilities on every pull request. Ships as a GitHub Action that runs self-contained in the GitHub runner, outputs SARIF results and PR comments, and optionally syncs findings back to the Secoraa platform for centralized history and trend tracking.

## Core Value

Every pull request gets automatically scanned for API security vulnerabilities before it can merge — shift-left security that catches issues before they ship to production.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] Shared scanner core that works both from platform UI and GitHub Action
- [ ] GitHub Action that reads OpenAPI/Postman spec from repo and runs OWASP security tests
- [ ] Scanner runs self-contained in GitHub runner — no dependency on Secoraa uptime
- [ ] SARIF output for GitHub Security tab integration
- [ ] PR comments with findings, CVSS scores, and fix guidance
- [ ] PR merge blocking when HIGH or CRITICAL vulnerabilities are found
- [ ] API key generation and management from Secoraa Settings page
- [ ] Optional fire-and-forget callback that POSTs scan results to Secoraa API
- [ ] CI/CD scan history view on platform (filtered by source: manual vs ci-cd)
- [ ] Auth via API key stored as GitHub Secret
- [ ] Docker image packaging of scanner for GitHub Action runner
- [ ] Configurable severity threshold for pass/fail gate

### Out of Scope

- GitLab CI / Bitbucket Pipelines support — GitHub Actions first, expand later
- Real-time scan streaming to platform — callback is fire-and-forget, async
- Custom scan rule authoring — use built-in OWASP test suite
- Mobile app integration — web platform only
- Paid tier gating — all features available for now (pre-launch)

## Context

- **Existing codebase**: FastAPI backend, React frontend, PostgreSQL, scanner architecture in `app/scanners/` with pluggable base class pattern
- **API APT scanner already exists**: OWASP test suite, OpenAPI/Postman parsing, vulnerability detection, PDF report generation — this is the scanner core to reuse
- **Pre-launch**: No users yet. Target audience is small dev teams, startups, and enterprise security teams
- **Current scan flow**: User uploads OpenAPI/Postman JSON via UI, scan runs, vulnerabilities identified, report downloadable as PDF
- **Architecture**: Scanner core in `app/scanners/`, registry pattern with BaseScanner ABC, results stored in PostgreSQL with Vulnerability/Scan models
- **Stack**: Python 3.11, FastAPI, SQLAlchemy 2.0, React 18, Docker deployment

## Constraints

- **Tech stack**: Must use existing Python scanner code — no rewrite in another language
- **GitHub Actions**: v1 targets GitHub Actions only; Action must work with `ubuntu-latest` runner
- **Docker**: Scanner must be packaged as a Docker image for the GitHub Action
- **SARIF**: Output must conform to SARIF 2.1.0 spec for GitHub Security tab compatibility
- **No platform dependency**: GitHub Action must complete successfully even if Secoraa API is unreachable
- **API key auth**: All CI/CD interactions authenticated via API key (no OAuth flows for CI)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Self-contained scan + optional callback | Enterprise needs dashboard/audit trail, but CI gate shouldn't depend on external service | — Pending |
| GitHub Actions first | Largest market share for CI, expand to GitLab/Bitbucket later | — Pending |
| Shared scanner core for UI and CI/CD | Single codebase to maintain, consistent findings across both surfaces | — Pending |
| SARIF output format | GitHub-native integration, appears in Security tab, enables code scanning alerts | — Pending |
| Fire-and-forget callback | Non-blocking — if Secoraa is down, CI pipeline still works normally | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? Move to Out of Scope with reason
2. Requirements validated? Move to Validated with phase reference
3. New requirements emerged? Add to Active
4. Decisions to log? Add to Key Decisions
5. "What This Is" still accurate? Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-04 after initialization*
