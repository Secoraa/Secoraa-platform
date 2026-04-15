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

# Resolve OPENAPI_SPEC_PATH relative to the GitHub workspace when running in Actions.
if [ -n "${GITHUB_WORKSPACE:-}" ] && [ -n "${OPENAPI_SPEC_PATH:-}" ]; then
  case "$OPENAPI_SPEC_PATH" in
    /*) ;; # absolute — leave as-is
    *)  OPENAPI_SPEC_PATH="${GITHUB_WORKSPACE}/${OPENAPI_SPEC_PATH}"
        export OPENAPI_SPEC_PATH ;;
  esac

  # Also resolve OUTPUT_FILE so results land in the workspace.
  if [ -n "${OUTPUT_FILE:-}" ]; then
    case "$OUTPUT_FILE" in
      /*) ;;
      *)  OUTPUT_FILE="${GITHUB_WORKSPACE}/${OUTPUT_FILE}"
          export OUTPUT_FILE ;;
    esac
  fi
fi

SUBCOMMAND="${1:-api}"
shift 2>/dev/null || true

# Forward any extra args to the CLI untouched. Env vars provide the rest.
exec python -m cli.scanner_cli "$SUBCOMMAND" "$@"
