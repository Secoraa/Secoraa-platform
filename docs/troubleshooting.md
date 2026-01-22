## Troubleshooting

### Backend won’t start (database env vars missing)

If you see logs like “Database environment variables not set”, create a repo-root `.env` and set:

- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_HOST` (usually `localhost`)
- `POSTGRES_PORT` (usually `15432`)

Then restart backend.

### Postgres connection refused

- Ensure Docker is running
- Start Postgres:

```bash
docker-compose up -d postgres
```

### MinIO errors / missing credentials

MinIO needs:
- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`

Start MinIO:

```bash
docker-compose up -d minio
```

### JWT_SECRET missing

Auth requires:
- `JWT_SECRET`

Set it in `.env` (local) and in env vars (prod). It is not auto-generated.

### “UndefinedColumn …” errors

Your DB schema may be behind the current model code. Run:

```bash
python app/scripts/create_tables.py
```

This script adds missing columns to some tables (including `api_scan_reports` and `vulnerabilities`) without dropping data.

