#!/bin/sh
# Secoraa Scanner CI entrypoint.
#
# Dispatches to `python -m cli.scanner_cli`. All CLI flags are already
# supported via env vars (TARGET_URL, OPENAPI_SPEC_PATH, AUTH_TOKEN, etc.)
# so GitHub Action inputs are just forwarded as env.
#
# Usage:
#   entrypoint.sh api       → run API scanner
#   entrypoint.sh subdomain → run subdomain scanner
#   entrypoint.sh           → defaults to api

set -e

# Ensure /app is on PYTHONPATH so `cli` and `app` packages are importable.
export PYTHONPATH="/app:${PYTHONPATH:-}"
cd /app

SUBCOMMAND="${1:-api}"
shift 2>/dev/null || true

# Forward any extra args to the CLI untouched. Env vars provide the rest.
exec python -m cli.scanner_cli "$SUBCOMMAND" "$@"
