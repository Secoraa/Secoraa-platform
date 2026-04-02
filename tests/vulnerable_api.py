"""
Intentionally vulnerable FastAPI application for end-to-end scanner validation.

DO NOT deploy this anywhere — it has real vulnerabilities on purpose.
"""
from __future__ import annotations

import sqlite3
import subprocess
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse


DB_PATH = "/tmp/vuln_test.db"


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            role TEXT
        )
    """)
    c.executemany("INSERT INTO users (id, username, email, role) VALUES (?, ?, ?, ?)", [
        (1, "admin", "admin@example.com", "admin"),
        (2, "alice", "alice@example.com", "user"),
        (3, "bob", "bob@example.com", "user"),
        (4, "charlie", "charlie@example.com", "viewer"),
    ])
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_db()
    yield
    try:
        os.remove(DB_PATH)
    except OSError:
        pass


app = FastAPI(title="Vuln Test API", lifespan=lifespan)


# ── CORS: wildcard + credentials (critical misconfiguration) ──────────────
@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin", "")
    if origin:
        # BUG: reflects ANY origin back
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
    response.headers["Access-Control-Allow-Headers"] = "*"
    # BUG: leaks server version
    response.headers["Server"] = "Apache/2.4.49"
    response.headers["X-Powered-By"] = "Express 4.17.1"
    # BUG: missing security headers (no X-Frame-Options, no CSP, no HSTS, etc.)
    return response


# ── GET /users — SQL injection in search param ────────────────────────────
@app.get("/users")
async def list_users(search: str = Query(default="")):
    if not search:
        return {"users": [{"id": 1, "username": "admin"}, {"id": 2, "username": "alice"}]}
    # BUG: string concatenation into SQL
    conn = sqlite3.connect(DB_PATH)
    try:
        query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search}%'"
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        return {"users": [{"id": r[0], "username": r[1], "email": r[2]} for r in rows]}
    except Exception as e:
        # BUG: leaks SQL error to client
        return JSONResponse(status_code=500, content={"error": str(e), "detail": "SQL query failed"})
    finally:
        conn.close()


# ── GET /users/{id} — BOLA (no auth check on resource) ───────────────────
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}
        return JSONResponse(status_code=404, content={"error": "User not found"})
    finally:
        conn.close()


# ── POST /users — mass assignment (accepts role field) ────────────────────
@app.post("/users")
async def create_user(request: Request):
    body = await request.json()
    username = body.get("username", "")
    email = body.get("email", "")
    role = body.get("role", "user")  # BUG: accepts role from client input
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("INSERT INTO users (username, email, role) VALUES (?, ?, ?)", (username, email, role))
        conn.commit()
        return {"status": "created", "username": username, "role": role}
    finally:
        conn.close()


# ── GET /ping — command injection in host param ──────────────────────────
@app.get("/ping")
async def ping_host(host: str = Query(default="127.0.0.1")):
    # BUG: command injection via shell=True
    try:
        result = subprocess.run(
            f"echo pinging {host}",
            shell=True, capture_output=True, text=True, timeout=5
        )
        return {"output": result.stdout.strip(), "status": "ok"}
    except subprocess.TimeoutExpired:
        return {"output": "", "status": "timeout"}


# ── GET /fetch — SSRF via url parameter ──────────────────────────────────
@app.get("/fetch")
async def fetch_url(url: str = Query(default="")):
    if not url:
        return {"error": "url parameter required"}
    # BUG: no URL validation, fetches arbitrary URLs
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnBot/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            return {"status": resp.status, "body": body[:1000]}
    except Exception as e:
        return {"error": str(e)}


# ── POST /render — SSTI via template parameter ──────────────────────────
@app.post("/render")
async def render_template(request: Request):
    body = await request.json()
    template_str = body.get("template", "Hello")
    name = body.get("name", "World")
    # BUG: evaluates template expressions
    try:
        # Simulate Jinja2-like evaluation for math expressions
        import re
        result = template_str
        # Replace {{expr}} with eval result
        for match in re.finditer(r"\{\{(.+?)\}\}", template_str):
            expr = match.group(1).strip()
            try:
                val = eval(expr)  # BUG: arbitrary code execution
                result = result.replace(match.group(0), str(val))
            except Exception:
                pass
        return {"rendered": result}
    except Exception as e:
        return {"error": str(e)}


# ── POST /upload — XXE via XML body ──────────────────────────────────────
@app.post("/upload")
async def upload_xml(request: Request):
    content_type = request.headers.get("content-type", "")
    raw = await request.body()
    raw_str = raw.decode("utf-8", errors="replace")
    if "xml" in content_type.lower() or raw_str.strip().startswith("<?xml") or raw_str.strip().startswith("<!"):
        # BUG: parse XML without disabling external entities
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(raw_str)
            return {"parsed": root.tag, "text": root.text or ""}
        except ET.ParseError as e:
            return JSONResponse(status_code=400, content={"error": f"XML parse error: {e}"})
    return {"status": "received", "size": len(raw)}


# ── GET /admin — no auth on admin endpoint ────────────────────────────────
@app.get("/admin")
async def admin_panel():
    return {"admin": True, "users_count": 4, "secret_key": "sk_live_fake_key_12345"}


# ── GET /debug — information disclosure ──────────────────────────────────
@app.get("/debug")
async def debug_info():
    return {
        "env": "production",
        "db_host": "db.internal.example.com:5432",
        "redis": "redis://internal:6379",
        "aws_region": "us-east-1",
        "version": "2.1.0-beta",
        "python": os.sys.version,
    }


# ── POST /login — no rate limiting ──────────────────────────────────────
@app.post("/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    # BUG: no rate limiting, no account lockout
    if username == "admin" and password == "admin123":
        return {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fake"}
    return JSONResponse(status_code=401, content={"error": "Invalid credentials"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9876)
