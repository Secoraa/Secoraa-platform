---
plan: 01
phase: 01-scanner-foundation
title: Decouple SQLAlchemy from scanner core
wave: 1
depends_on: []
files_modified:
  - app/scanners/api_scanner/main.py
requirements: [SCAN-02]
autonomous: true
---

# Plan 01: Decouple SQLAlchemy from scanner core

<objective>
Make `app/scanners/api_scanner/main.py` importable in an environment that has neither `sqlalchemy` nor `psycopg2` installed, so the GitHub Action Docker image can run the scanner without installing platform database dependencies.

This is the blocker identified in PITFALLS.md #1 and locked in CONTEXT.md decision D1. One-line module change plus a verification test.
</objective>

<must_haves>
- `python -c "from app.scanners.api_scanner.main import run_api_scan"` succeeds when `sqlalchemy` is blocked from import
- Type hints for `Session` still work for IDE/mypy (not removed, just deferred)
- Zero behavior change when `sqlalchemy` IS installed (platform UI code path still works)
- No changes to any file other than `main.py`
</must_haves>

<tasks>

<task id="1.1">
<title>Wrap Session import in TYPE_CHECKING guard</title>
<read_first>
- app/scanners/api_scanner/main.py (see current state of lines 1-40, need to confirm `from __future__ import annotations` is line 1 and the sqlalchemy import is line 8)
- .planning/phases/01-scanner-foundation/01-CONTEXT.md (Decision D1)
- .planning/phases/01-scanner-foundation/01-RESEARCH.md (F1, P1)
</read_first>
<action>
Edit `app/scanners/api_scanner/main.py`. Replace the line:

```python
from sqlalchemy.orm import Session
```

with:

```python
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from sqlalchemy.orm import Session
```

Placement: directly after the existing `from typing import Any, Dict, List, Optional` line (currently line 6). The replaced line was at line 8.

Do NOT modify any other import, function signature, docstring, or body. The `Optional[Session]` annotations on lines 43 (`_update_progress` type comment), 72 (`_is_cancelled` type comment), and 192 (`run_api_scan` signature) MUST remain unchanged — they work because `from __future__ import annotations` is already at line 1, which makes all annotations strings at runtime.
</action>
<acceptance_criteria>
- `grep -n "if TYPE_CHECKING:" app/scanners/api_scanner/main.py` prints a line number between 5 and 15
- `grep -n "from sqlalchemy.orm import Session" app/scanners/api_scanner/main.py` prints exactly one match that is INSIDE the TYPE_CHECKING block (indented by 4 spaces)
- `grep -c "^from sqlalchemy" app/scanners/api_scanner/main.py` returns `0` (no top-level sqlalchemy imports)
- `grep -n "from __future__ import annotations" app/scanners/api_scanner/main.py` still prints line 1
- `python -c "import ast; ast.parse(open('app/scanners/api_scanner/main.py').read())"` exits 0 (file parses cleanly)
</acceptance_criteria>
</task>

<task id="1.2">
<title>Verify scanner imports without sqlalchemy</title>
<read_first>
- app/scanners/api_scanner/main.py (post-edit state)
- .planning/phases/01-scanner-foundation/01-RESEARCH.md (V1)
</read_first>
<action>
Run this verification command from the repository root:

```bash
cd /Users/pratikawasarmol/Desktop/Secoraa/Secoraa-Platform/Secoraa-platform
python -c "
import sys
class Blocker:
    def find_module(self, name, path=None):
        if name == 'sqlalchemy' or name.startswith('sqlalchemy.') or name == 'psycopg2' or name.startswith('psycopg2.'):
            return self
        return None
    def load_module(self, name):
        raise ImportError(f'{name} is blocked by test')
sys.meta_path.insert(0, Blocker())
from app.scanners.api_scanner.main import run_api_scan
print('IMPORT_OK')
"
```

Expected stdout: `IMPORT_OK`
Expected exit code: `0`

If the command fails with `ImportError`, the TYPE_CHECKING fix is incomplete — investigate which module still imports sqlalchemy at module scope and report back. Do NOT proceed to Plan 02 until this verification passes.
</action>
<acceptance_criteria>
- Running the above command prints exactly `IMPORT_OK` on stdout
- Command exit code is `0`
- No ImportError, AttributeError, or other exception in stderr
</acceptance_criteria>
</task>

</tasks>

<verification>
All acceptance criteria above must be checked. Specifically:
1. `grep -c "^from sqlalchemy" app/scanners/api_scanner/main.py` == 0
2. The Blocker test command prints `IMPORT_OK` with exit 0
3. `git diff app/scanners/api_scanner/main.py` shows exactly one logical change (the Session import wrapped in TYPE_CHECKING)
</verification>
