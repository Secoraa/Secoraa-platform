## Backend (FastAPI)

### What it is

The backend lives under `app/` and is served via `app/main.py`.

- **Custom Swagger**: mounted at `'/api/v1alpha1/backend/docs'`
- **Convenience redirects**: `/docs` and `/swagger` redirect to the custom Swagger UI

### Run locally

Requirements:
- Python (project uses a venv; ensure you run in the correct env)
- Postgres (via `docker-compose.yml`)
- MinIO (via `docker-compose.yml`)

Commands:

```bash
uvicorn app.main:app --reload --port 8000
```

### Key routers (high level)

- **Auth**: `/auth/*`
- **Scans (DD + Subdomain via plugin registry)**: `/scans/*`
- **API Testing scanner**: `/scanner/api`
- **Vulnerabilities feed**: `/vulnerabilities/*`
- **Assets**: `/assets/*`
- **Subdomains CRUD**: `/subdomain/*`
- **MinIO event webhook**: `/minio/event`

### Environment variables

These are required for a healthy setup:

- **Database**
  - `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`
  - `POSTGRES_HOST` (default `localhost`)
  - `POSTGRES_PORT` (default `15432`)

- **JWT Auth**
  - `JWT_SECRET` (**required**; not auto-generated)
  - `JWT_EXPIRES_MINUTES` (default `240`)
  - `AUTH_TENANT` (default `default`)

- **MinIO**
  - `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`
  - `MINIO_API_PORT`, `MINIO_CONSOLE_PORT`
  - `MINIO_ENDPOINT` (default `localhost:9000`)

### Swagger / API testing

- Open Swagger UI using:
  - `/docs` (redirect) or `/swagger` (redirect)
  - Direct path: `/api/v1alpha1/backend/docs`

