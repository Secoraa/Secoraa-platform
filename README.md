## Secoraa Platform

This repository contains multiple Secoraa “products” (components):

- **Backend API**: FastAPI service in `app/`
- **Frontend (React)**: Webpack-based UI in `frontend-react/`
- **Scanners**: Domain Discovery (DD), Subdomain Scanner, API Testing scanner under `app/scanners/`

### Quickstart (Local)

#### 1) Start dependencies (Postgres, MinIO)

This repo’s `docker-compose.yml` expects a `.env` file for credentials.

- **Create `.env`** in repo root (example):

```bash
POSTGRES_DB=secoraa
POSTGRES_USER=secoraa
POSTGRES_PASSWORD=secoraa
POSTGRES_HOST=localhost
POSTGRES_PORT=15432

MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin
MINIO_API_PORT=9000
MINIO_CONSOLE_PORT=9001
MINIO_ENDPOINT=localhost:9000

AUTH_TENANT=default
JWT_SECRET=change-me-in-local-and-prod
JWT_EXPIRES_MINUTES=240
```

- **Start containers**:

```bash
docker-compose up -d postgres minio
```

#### 2) Run DB schema migration

```bash
python app/scripts/create_tables.py
```

#### 3) Start backend

```bash
uvicorn app.main:app --reload --port 8000
```

- Swagger UI is available at `/docs` (redirects to the custom docs path).

#### 4) Start frontend (React)

```bash
cd frontend-react
npm install
npm run dev
```

Frontend runs at `http://localhost:8501` by default.

---

### Documentation

Start here:

- `docs/index.md`

