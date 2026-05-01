## Project

**Secoraa CI/CD API Security Scanner**

A CI/CD API security scanning feature for the Secoraa platform that enables developers to automatically test their APIs for vulnerabilities on every pull request. Ships as a GitHub Action that runs self-contained in the GitHub runner, outputs SARIF results and PR comments, and optionally syncs findings back to the Secoraa platform for centralized history and trend tracking.

**Core Value:** Every pull request gets automatically scanned for API security vulnerabilities before it can merge — shift-left security that catches issues before they ship to production.

### Constraints

- **Tech stack**: Must use existing Python scanner code — no rewrite in another language
- **GitHub Actions**: v1 targets GitHub Actions only; Action must work with `ubuntu-latest` runner
- **Docker**: Scanner must be packaged as a Docker image for the GitHub Action
- **SARIF**: Output must conform to SARIF 2.1.0 spec for GitHub Security tab compatibility
- **No platform dependency**: GitHub Action must complete successfully even if Secoraa API is unreachable
- **API key auth**: All CI/CD interactions authenticated via API key (no OAuth flows for CI)
## Technology Stack

## Languages
- Python 3.11 - Backend API, scanners, workers
- TypeScript/JavaScript - Frontend build toolchain
- JSX/TSX - React components
- SQL - Database queries (PostgreSQL)
- YAML/JSON - Configuration and API specs
## Runtime
- Python 3.11 slim (Docker: `python:3.11-slim`)
- Node.js (via npm for frontend bundling)
- pip (Python)
- npm (Node.js)
- Lockfile: `package.json` (frontend), `requirements.txt` (backend)
## Frameworks
- FastAPI 0.128.0 - REST API framework
- Uvicorn 0.39.0 - ASGI application server
- Starlette 0.49.3 - Web framework (FastAPI dependency)
- React 18.2.0 - UI component framework
- React Router DOM 6.20.0 - Client-side routing
- Webpack 5.89.0 - Module bundler
- Babel 7.23.5 - JavaScript transpiler
- pytest - Python testing framework (configured: `pytest.ini`)
- Celery 5.4.0 - Distributed task queue
- Redis 5.2.1 - In-memory broker/backend for Celery
## Key Dependencies
- SQLAlchemy 2.0.45 - ORM and database abstraction
- psycopg2-binary 2.9.11 - PostgreSQL database adapter
- Pydantic 2.12.5 - Data validation and settings management
- argon2-cffi 25.1.0 - Password hashing (Argon2)
- PyJWT 2.10.1 - JWT token encode/decode
- pycryptodome 3.23.0 - Cryptographic primitives
- requests 2.32.5 - HTTP client (used in subdomain scanner, vulnerability scanner)
- httpx 0.28.1 - Async HTTP client (API scanner, vulnerability scanner plugins)
- aiohttp 3.10.11 - Async HTTP session (HTTP probing, validation)
- aiohttp-dnspython 3.6.1 - Async DNS resolution
- beautifulsoup4 4.12.3 - HTML parsing (passive discovery)
- dnspython 2.6.1 - DNS operations (zone transfers, queries)
- minio 7.2.20 - MinIO S3-compatible object storage client
- Pillow 11.3.0 - Image processing (reporting, screenshots)
- fpdf2 2.7.9 - PDF report generation
- openpyxl 3.1.5 - Excel report generation
- numpy 2.0.2 - Numerical computing (scan analysis)
- pandas 2.3.3 - Data manipulation (scan results aggregation)
- PyYAML 6.0.3 - YAML parsing (OpenAPI specs)
- opentelemetry-api 1.38.0 - OpenTelemetry instrumentation API
- opentelemetry-sdk 1.38.0 - OpenTelemetry SDK
- opentelemetry-exporter-otlp-proto-http 1.38.0 - OTLP HTTP exporter
- rich 14.2.0 - Terminal formatting and logging
- python-dotenv 1.0.0 - Environment variable loading
- tenacity 9.1.2 - Retry library (network operations)
- Jinja2 3.1.6 - Template engine (reports)
- axios 1.6.2 - HTTP client for API calls
- xlsx 0.18.5 - Excel file handling
## Configuration
- `DATABASE_URL` (primary) or `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_HOST`, `POSTGRES_PORT`
- `REDIS_URL` (default: `redis://localhost:6379/0`)
- `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_SECURE`
- `JWT_SECRET` (required for token signing)
- `JWT_EXPIRES_MINUTES` (default: 240)
- Scanner timeout settings: `SCAN_TIMEOUT`, `EXTENSIVE_SCAN_TIMEOUT`, `PLUGIN_TIMEOUT`, `HTTP_TIMEOUT`
- Crawler settings: `KATANA_PATH`, `MAX_CRAWL_URLS`, `CRAWL_DEPTH`, `CRAWLER_TIMEOUT`
- OOB server: `OOB_HOST`, `OOB_PORT`, `OOB_BASE_URL`
- `Dockerfile` - Single-stage containerization for Railway deployment
- `docker-compose.yml` - Local development stack (PostgreSQL, MinIO, Zookeeper, Kafka, Redis)
- `frontend-react/webpack.config.js` - Webpack bundling configuration
- `.env.example` - Template with default values for local development
## Platform Requirements
- Python 3.11+
- Node.js 14+ (for frontend)
- Docker and Docker Compose (for local services)
- PostgreSQL 15 (via Docker)
- MinIO (via Docker)
- Redis 7 (via Docker)
- Railway platform (current deployment target)
- PostgreSQL database
- MinIO or S3-compatible object storage
- Redis for Celery broker
- Can be containerized via provided Dockerfile
## Conventions

## Naming Patterns
- Python backend: `snake_case.py` (e.g., `auth.py`, `response_differ.py`, `cvss_calculator.py`)
- Frontend React: `PascalCase.jsx` for components (e.g., `Sidebar.jsx`, `Header.jsx`, `Dashboard.jsx`)
- Test files: `test_*.py` prefix (e.g., `test_auth_checks.py`, `test_headers_checks.py`)
- Scanner modules: Organized by feature with full paths like `api_scanner/tests/auth_tests.py`
- Python: `snake_case` for all function and method names
- React: `camelCase` for utility functions, `PascalCase` for component functions
- Python: `snake_case` for all module/function scope variables (e.g., `base_url`, `auth_headers`, `query_params`)
- React: `camelCase` for state and props (e.g., `activePage`, `selectedScanId`, `userClaims`)
- Constants: `UPPER_CASE` (e.g., `API_BASE_URL`, `TOKEN_STORAGE_KEY`, `BASE_URL`)
- Python: Type hints used throughout (e.g., `Dict[str, Any]`, `Optional[str]`, `List[Dict[str, Any]]`)
- Python dataclasses: `@dataclass` decorator used (e.g., `DiffResult`)
- FastAPI: Pydantic BaseModel for request/response schemas (e.g., `LoginRequest`, `TokenResponse`)
## Code Style
- Python: 4-space indentation (PEP 8)
- React/JavaScript: 2-space indentation (Babel/Webpack setup)
- Line length: Python observes ~100-120 character limit
- No explicit formatter configured (ruff, black, or prettier) — style is manual
- Python: No explicit linting config found (.flake8, ruff.toml absent)
- React: No explicit linting config (no .eslintrc)
- Warnings filtered in pytest: `filterwarnings = ignore::DeprecationWarning, ignore::urllib3.exceptions.InsecureRequestWarning` in `pytest.ini`
## Import Organization
- No explicit path aliases configured in tsconfig or Python
- Relative imports avoided; absolute imports from `app.*` prefix used
## Error Handling
- FastAPI: `HTTPException(status_code=..., detail=...)` for API errors (see `app/api/reports.py`, `app/api/scans.py`)
- Database errors: Explicit exception catching (`except IntegrityError`, `except ProgrammingError`, `except OperationalError`)
- Generic fallback: `try/except Exception` used for backward compatibility and schema migration scenarios
- Custom exceptions: `TokenExpired`, `TokenInvalid` defined as simple Exception subclasses in `app/api/auth.py`
- No standardized error response format; each endpoint handles errors independently
- Database connection errors trigger rollback and retry logic
- Token validation errors raise custom exceptions caught by `get_token_claims()` middleware
- Scanner execution wrapped in try/except blocks with logging
## Logging
- Info level: Major operations start/completion (scan started, worker begun)
- Debug level: Detailed flow information (endpoint validation decisions, auth type detection)
- Exceptions: Not explicitly logged in most handlers; errors propagate via HTTPException
## Comments
- Used primarily for algorithm explanation and complex logic (response diffing, CVSS calculation)
- Comments use section markers like `# --- Normalization patterns ---` to delineate logical blocks
- Each test method has a docstring explaining what behavior it tests
- Helper function docstrings common in utility modules
- Not used in React codebase (no TypeScript, JSDoc comments absent)
- Python docstrings used in test files (e.g., `"""Tests for auth_tests — authentication bypass detection."""`)
## Function Design
- Python functions range 20-100 lines for business logic
- Scanner test modules (auth_tests, sqli_tests, etc.) are 200+ lines — function-per-test-case structure
- React components: 50-150 lines typical
- Python functions use explicit type hints (Dict, List, Optional, Any)
- FastAPI endpoints use Pydantic models for request bodies: `def endpoint(body: RequestModel = Body(...))`
- Dependencies injected via `Depends()`: `db: Session = Depends(get_db), claims: Dict = Depends(get_token_claims)`
- React functions: Props destructured in function signature (e.g., `function Sidebar({ activePage, setActivePage, tenant, username })`)
- Python: Explicit return type hints (e.g., `-> str`, `-> Dict[str, Any]`, `-> List[Dict[str, Any]]`)
- Async functions return Awaitable types (declared with `async def` and `await`)
- FastAPI endpoints return Pydantic models or HTTPException
- React: Return JSX or components
## Module Design
- No explicit `__all__` lists in most modules
- Modules import selectively from submodules (e.g., `from app.scanners.api_scanner.tests.auth_tests import run_auth_tests`)
- Functions and classes exposed directly by module name
- `app/scanners/api_scanner/tests/__init__.py` serves as barrel — exports utility functions:
- Minimal class usage; most code is procedural functions
- Pydantic models for data validation (BaseModel subclasses)
- SQLAlchemy ORM models use declarative syntax with Column definitions
- Dataclasses used for simple data containers (e.g., `DiffResult` in response_differ.py)
## Async/Await Patterns
- Test functions: `@pytest.mark.asyncio` decorator, `async def test_*()`
- Scanner execution: `async def run_auth_tests()`, `async def run_headers_tests()`
- Request execution: `await execute_request()`
- Background jobs: Threading and asyncio mixed (`threading.Thread` for scan processing, `asyncio` for test execution)
## Test Naming
- Class-based: `class Test{Feature}`, methods `test_*.py` (e.g., `class TestDetectAuthType`, `def test_bearer()`)
- Descriptive names explain behavior: `test_bearer_bypass_empty_token()`, `test_server_version_disclosure()`
## Architecture

## Pattern Overview
- FastAPI-based REST API backend serving frontend and mobile clients
- Pluggable scanner architecture with unified execution pipeline
- Synchronous REST endpoints with async background job support (threading + optional Celery/Redis)
- Multi-tenant asset management with role-based access control
- Report generation pipeline (PDF export via fpdf2 to MinIO storage)
- Dual database models: Asset Management (Domain/Subdomain/Vulnerability) and Scan History
## Layers
- Purpose: HTTP endpoints handling incoming requests from frontend/clients
- Location: `app/api/`, `app/endpoints/`
- Contains: FastAPI routers, request/response models, authentication middleware
- Depends on: Database models, scanners, services, storage
- Used by: React frontend, CLI tools, third-party integrations
- Purpose: CORS handling, custom documentation, health checks
- Location: `app/main.py` (app setup), `app/custom_swagger.py` (docs)
- Contains: Middleware registration, startup hooks, health check endpoints
- Depends on: Database session, storage clients, Redis
- Used by: FastAPI request lifecycle
- Purpose: JWT token validation, tenant isolation, permission checks
- Location: `app/api/auth.py`
- Contains: Token validation, tenant claim extraction, user lookups
- Depends on: Database (User model)
- Used by: All protected API routes (via Depends(get_token_claims))
- Purpose: Core business entities and relationships
- Location: `app/database/models.py`
- Contains: User, Scan, Domain, Subdomain, Vulnerability, IPAddress, Report, ScheduledScan, AssetGroup
- Relationships: One domain → many subdomains/IPs/vulnerabilities; one subdomain → many vulnerabilities
- Key pattern: Cascade delete on foreign keys to maintain referential integrity
- Purpose: Pluggable vulnerability discovery engines
- Location: `app/scanners/`
- Contains: 
- Depends on: External APIs (crt.sh, HackerTarget, RapidDNS), HTTP clients
- Used by: `app/api/scans.py` endpoint
- Purpose: Asset storage, scan history, vulnerability records
- Location: `app/database/`
- Contains: SQLAlchemy ORM models, database connection pool
- Database: PostgreSQL (Railway prod, Docker Compose local)
- Connection pooling: QueuePool with 5 base connections, 10 overflow, 3600s recycle
- Purpose: Report artifacts, scan outputs, temporary files
- Location: `app/storage/`
- Contains: MinIO S3-compatible client, file I/O abstractions
- Storage targets: MinIO (production), local filesystem (fallback)
- Used for: PDF reports, JSON scan results, audit logs
- Purpose: Deferred scan execution, scheduled scan triggering
- Location: `app/worker/`, `app/api/scans.py` (scheduling logic)
- Contains: Celery configuration, Redis broker connection, scheduled scan worker
- Execution model: Primary=threading for immediate scans, Optional=Celery for distributed jobs
- Fallback: Synchronous scan execution if Redis unavailable
- Purpose: Transform vulnerabilities into PDF/Excel artifacts
- Location: `app/api/reports.py`
- Contains: PDF builders (fpdf2), severity aggregation, environment detection, narrative templates
- Output: PDF streamed to client or stored in MinIO
- Report types: ASM (Asset Security), WEB, API (future)
## Data Flow
- Scan progress: Updated in-memory during execution (thread), also persisted to DB for durability
- Asset state: Persisted to PostgreSQL, cached in frontend state management (React)
- Session state: FastAPI dependency injection (get_db, get_token_claims)
- Redis: Optional caching layer for Celery task states (if enabled)
## Key Abstractions
- Purpose: Unified interface for all vulnerability discovery engines
- Location: `app/scanners/base.py`
- Pattern: Abstract base class with `run(payload: dict) → dict` contract
- Examples: `DomainDiscoveryScanner`, `SubdomainScanner`, `VulnerabilityScanner`
- Implementation detail: Registry pattern allows runtime scanner lookup
- Purpose: Represent organizational attack surface
- Structure: Domain → [Subdomain, IPAddress, IPBlock] → Vulnerabilities
- Relationships defined via SQLAlchemy foreign keys with cascade delete
- Enables: Multi-level reporting (org-wide, domain-level, host-level)
- Purpose: Atomic unit of security intelligence
- Attributes: Title, severity, CVSS score, description, recommendation, reference
- Linkage: Optional domain_id + optional subdomain_id (supports both direct domain vulns + subdomain vulns)
- Scoring: Severity enum (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Purpose: Time-based scan triggering without polling/webhooks
- Pattern: Separate table (scheduled_scans) with status tracking (PENDING → TRIGGERING → TRIGGERED)
- Worker process: `start_schedule_worker()` in startup hook checks due scans every minute
- Idempotency: triggered_scan_id + triggered_at prevent duplicate execution
## Entry Points
- Location: `main.py` (uvicorn entry)
- Triggers: `uvicorn run app, host=0.0.0.0, port=8000`
- Responsibilities: Load FastAPI app, mount all routers, start background workers
- Location: `app/main.py`
- Triggers: Imported by main.py, configured with CORS + routers + startup hooks
- Responsibilities: Configure middleware, register all routers, initialize database/Redis/MinIO
- Location: `app/api/scans.py` endpoint `POST /scans`
- Triggers: Frontend submit scan request
- Responsibilities: Validate payload, create Scan record, dispatch background thread/Celery task
- Location: `app/api/scans.py` function `start_schedule_worker()`
- Triggers: App startup event
- Responsibilities: Poll scheduled_scans table every 60s, trigger due scans, update status
- Location: `app/main.py` endpoint `GET /health`
- Triggers: External monitoring (Railway, k8s probes)
- Responsibilities: Check Redis, database, MinIO connectivity; return aggregate status
## Error Handling
- Database errors: Try ORM → fallback to raw SQL (backward-compatible with older DB schemas)
- Missing services: Log warnings, continue operation (e.g., Redis down → sync scan mode)
- Scan failures: Catch exceptions in background threads, persist error to Scan.status="FAILED"
- API validation: Pydantic models validate requests; invalid payloads return 422 with details
- File operations: Use try/except around MinIO uploads; raise HTTPException on unrecoverable failures
- Authentication: Invalid tokens → 401, missing auth header → 401, expired token → 401
## Cross-Cutting Concerns
- Framework: Python stdlib logging module
- Output: Streams to stdout (Railway/Docker logs)
- Level: DEBUG for development, INFO for production
- Examples: `logger.info("Scan started: %s", scan_id)`, `logger.error("DB error: %s", e)`
- Request validation: Pydantic BaseModel (enforces type hints, range checks)
- Scan payload validation: Schema in `app/schemas/scan.py` with optional fields
- Database constraints: SQLAlchemy constraints (NOT NULL, UNIQUE, FK, ARRAY types)
- Method: JWT tokens (PyJWT library)
- Claim extraction: `get_token_claims()` dependency validates signature, returns claims dict
- Scope: Per-request validation; no session persistence (stateless)
- Tenant context: Embedded in token, used to isolate multi-tenant queries
- Policy: Whitelist specific origins (localhost:3000, localhost:5173, Vercel/Railway prod URLs)
- Methods: Allow all (configurable)
- Credentials: Enabled for cookie-based auth fallback
- Environment variables: Loaded from .env file (dev) or Railway environment (prod)
- No hardcoded secrets: All credentials (DB, MinIO, JWT key) externalized
- Sensitive files: `.env` excluded from git via .gitignore

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
|------|----------|
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.
