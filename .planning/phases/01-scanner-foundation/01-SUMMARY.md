---
plan: 01
phase: 01-scanner-foundation
title: Decouple SQLAlchemy from scanner core
status: complete
completed: 2026-04-07
requirements: [SCAN-02]
---

# Plan 01 Summary: Decouple SQLAlchemy from scanner core

## What Was Built

Wrapped the `sqlalchemy.orm.Session` import in `app/scanners/api_scanner/main.py` in a `TYPE_CHECKING` guard. The scanner module can now be imported without `sqlalchemy` or `psycopg2` installed — a prerequisite for the Phase 2 Docker image that will ship only scanner dependencies.

## Tasks Completed

| Task | Description | Status |
|------|-------------|--------|
| 1.1 | Wrap Session import in TYPE_CHECKING guard | ✓ |
| 1.2 | Verify scanner imports without sqlalchemy | ✓ |

## Key Files Modified

- `app/scanners/api_scanner/main.py` (lines 6-9): replaced `from sqlalchemy.orm import Session` with a `TYPE_CHECKING`-guarded import

## Verification Results

**Task 1.1 acceptance criteria — all passed:**
- `if TYPE_CHECKING:` at line 8 (within 5-15 range)
- `from sqlalchemy.orm import Session` at line 9, indented inside the TYPE_CHECKING block
- `grep -c "^from sqlalchemy" main.py` returns `0`
- `from __future__ import annotations` still at line 1
- File parses cleanly via `ast.parse()`

**Task 1.2 acceptance criteria — all passed:**
- Blocker test prints `IMPORT_OK` on stdout
- Exit code `0`
- No ImportError raised

## Key-Links

None — this plan produces no new artifacts consumed by later plans. Plan 02 uses `app.scanners.api_scanner.main` as a dependency but does not reference specific symbols added here.

## Commits

- `b93e516` — fix(scanner): decouple sqlalchemy.orm.Session import via TYPE_CHECKING

## Requirements Covered

- **SCAN-02**: SQLAlchemy/database imports are decoupled so scanner runs standalone without PostgreSQL or ORM dependencies installed ✓
