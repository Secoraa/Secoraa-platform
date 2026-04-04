# Stack Research: CI/CD API Security Scanning

**Domain:** CI/CD-integrated API security scanning (GitHub Actions delivery)
**Researched:** 2026-04-04

## Key Finding: Zero New Dependencies

Everything needed already exists in `requirements.txt`. The scanner core runs standalone without PostgreSQL — confirmed via codebase inspection (`run_api_scan(db=None, scan_id=None)` skips DB writes, `_update_progress` no-ops when `db=None`).

## Stack Decisions

| Decision | Recommendation | Rationale |
|----------|---------------|-----------|
| Action type | Docker container action | Only viable type that packages Python runtime; composite and JS actions excluded by the Python constraint |
| SARIF generation | stdlib `json`, hand-built dict | `sarif-tools` is read-only (parses, doesn't write); `sarif-om` last released 2021; SARIF 2.1.0 is trivially buildable with ~100 lines of Python |
| GitHub API (PR comments) | `httpx 0.28.1` (already in requirements) | REST calls to 2 endpoints; PyGitHub adds ~2 MB for 4 REST calls; `gh` CLI adds shell-escaping surface |
| Merge blocking | Check Runs API (`POST /repos/.../check-runs`) | Modern approach; provides inline diff annotations; legacy commit status API gives no rich output |
| Image registry | GHCR (`ghcr.io`) | No rate limits for public repos; Docker Hub has 100 pulls/6h limit that breaks shared CI runners |
| Platform callback | `httpx` with `try/except Exception: pass` | Hard constraint — CI gate must not depend on Secoraa uptime |
| Entrypoint | Plain `os.getenv` + `asyncio.run` | Inputs come as `INPUT_*` env vars per GitHub Actions Docker convention; Click/Typer unnecessary |
| Action image | Separate scanner-only Dockerfile | Full platform Dockerfile pulls in FastAPI, Celery, SQLAlchemy, OTel, pandas — none needed for a CLI scan; cuts ~800 MB from image |

## Risk: OOB Server in CI

`app/scanners/api_scanner/engine/oob_server.py` starts a callback server for SSRF/XXE detection. On GitHub-hosted runners, the action container is behind NAT — OOB callbacks from a scanned API cannot reach back. Design decision needed: skip OOB-dependent tests in CI mode or use an external OOB relay.

## Versions to Verify

- Current version of `github/codeql-action/upload-sarif`
- `action.yml` metadata syntax
- Python 3.11 slim image security patch status
