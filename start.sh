#!/usr/bin/env zsh
# ─────────────────────────────────────────────
#  Secoraa – Full Stack Startup Script
# ─────────────────────────────────────────────

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/.venv/bin"
LOG_DIR="$ROOT/.logs"
mkdir -p "$LOG_DIR"

# ── Colours ──────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

step()  { echo "${CYAN}${BOLD}▶  $1${RESET}"; }
ok()    { echo "${GREEN}✔  $1${RESET}"; }
warn()  { echo "${YELLOW}⚠  $1${RESET}"; }
fail()  { echo "${RED}✘  $1${RESET}"; }

# ── Trap – kill all children on Ctrl-C ───────
cleanup() {
  echo ""
  warn "Shutting down all services…"
  kill 0
  exit 0
}
trap cleanup INT TERM

echo ""
echo "${BOLD}╔══════════════════════════════════════╗${RESET}"
echo "${BOLD}║      Secoraa Platform – Startup      ║${RESET}"
echo "${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""

# ── 1. Docker (Postgres, Redis, MinIO, Kafka) ─
step "Starting Docker services…"
cd "$ROOT"
docker compose up -d
if [[ $? -eq 0 ]]; then
  ok "Docker services up  (postgres · redis · minio · kafka)"
else
  fail "Docker Compose failed – check docker-compose.yml"
  exit 1
fi

# Wait for Redis to be ready (Celery needs it)
step "Waiting for Redis to be ready…"
for i in {1..20}; do
  docker exec secoraa-redis redis-cli ping &>/dev/null && break
  sleep 1
done
ok "Redis is ready"

# ── 2. Backend (FastAPI / Uvicorn) ───────────
step "Starting Backend (FastAPI)…"
cd "$ROOT"
"$VENV/python" -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload \
  > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
ok "Backend started  →  http://localhost:8000  (log: .logs/backend.log)"

# ── 3. Celery Worker ─────────────────────────
step "Starting Celery worker…"
cd "$ROOT"
"$VENV/celery" -A app.worker.celery_app worker --loglevel=info \
  > "$LOG_DIR/celery.log" 2>&1 &
CELERY_PID=$!
ok "Celery worker started  (log: .logs/celery.log)"

# ── 4. Frontend (React / webpack-dev-server) ─
step "Starting Frontend (React)…"
cd "$ROOT/frontend-react"
npm run dev > "$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
ok "Frontend started  →  http://localhost:8501  (log: .logs/frontend.log)"

# ── Summary ───────────────────────────────────
echo ""
echo "${BOLD}╔══════════════════════════════════════╗${RESET}"
echo "${BOLD}║         All Services Running         ║${RESET}"
echo "${BOLD}╠══════════════════════════════════════╣${RESET}"
echo "${BOLD}║${RESET}  ${GREEN}Frontend  ${RESET}→  http://localhost:8501   ${BOLD}║${RESET}"
echo "${BOLD}║${RESET}  ${GREEN}Backend   ${RESET}→  http://localhost:8000   ${BOLD}║${RESET}"
echo "${BOLD}║${RESET}  ${GREEN}API Docs  ${RESET}→  http://localhost:8000/docs${BOLD}║${RESET}"
echo "${BOLD}║${RESET}  ${GREEN}MinIO UI  ${RESET}→  http://localhost:9001   ${BOLD}║${RESET}"
echo "${BOLD}╠══════════════════════════════════════╣${RESET}"
echo "${BOLD}║${RESET}  Press ${RED}Ctrl+C${RESET} to stop everything      ${BOLD}║${RESET}"
echo "${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""

# ── Keep alive – tail all logs ───────────────
tail -f "$LOG_DIR/backend.log" "$LOG_DIR/celery.log" "$LOG_DIR/frontend.log"
