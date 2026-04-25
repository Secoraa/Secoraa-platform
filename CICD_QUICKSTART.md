# Secoraa API Security Scanner — CI/CD Quickstart

Add automated API security scanning to your GitHub repository. Every push and pull request gets scanned for OWASP API Top 10 vulnerabilities. Results show up in:

- The pull request as a comment
- GitHub's **Security** tab (Code scanning alerts)
- The **Secoraa platform** → **Scans** → **CI/CD Scans** (centralized history across all your repos)

---

## Prerequisites

- A GitHub repository for the API you want to scan
- An OpenAPI / Swagger specification for your API (`openapi.json`, `openapi.yaml`, or Postman collection)
- A target URL for the API (staging environment recommended — see [Targeting your API](#targeting-your-api))

---

## Setup (3 steps)

### Step 1 — Generate a Secoraa API key

1. Sign in to your Secoraa platform account: <https://secoraa-frontend.onrender.com/>
2. Go to **Settings** → **API Keys**
3. Click **Create new key**, give it a name (e.g. `github-actions`)
4. Copy the `sec_...` key. You will not see it again.

### Step 2 — Add the key as a GitHub secret

In your **target repository** (the one with the API):

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `SECORAA_API_KEY`
4. Value: the `sec_...` key from Step 1
5. Click **Add secret**

### Step 3 — Add the workflow file

Create `.github/workflows/secoraa-scan.yml` in your repository with the contents below.

```yaml
name: Secoraa API Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write       # for posting PR comments
      security-events: write     # for SARIF upload to Security tab

    steps:
      - name: Checkout repo
        uses: actions/checkout@v4

      - name: Run Secoraa Security Scan
        uses: Secoraa/Secoraa-platform@v1
        with:
          target-url: https://staging.your-api.com   # CHANGE THIS
          openapi-spec: ./openapi.json               # path to your spec, or 'auto'
          severity-threshold: HIGH                   # block PRs on HIGH+ findings
          fail-on-findings: true                     # fail the build when threshold hit
          secoraa-api-key: ${{ secrets.SECORAA_API_KEY }}

      - name: Upload SARIF to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: secoraa-results.sarif
```

Edit the two lines marked `CHANGE THIS` to point at your API and OpenAPI spec, commit, and push. The first scan kicks off automatically.

---

## Targeting your API

The scanner runs inside a GitHub-hosted runner — a remote VM. It cannot reach `localhost` on your laptop. You have three options:

### Option A — Staging URL (recommended)

If you have a deployed staging environment, just point at it:

```yaml
target-url: https://staging.your-api.com
```

### Option B — Boot your API in the runner (no staging required)

Start your API as a previous step in the same workflow, then scan `localhost`:

```yaml
- name: Start API in background
  run: |
    pip install -r requirements.txt
    python -m uvicorn main:app --host 0.0.0.0 --port 8000 &
    for i in 1 2 3 4 5 6 7 8 9 10; do
      curl -sf http://localhost:8000/health && break
      sleep 2
    done

- name: Run Secoraa Security Scan
  uses: Secoraa/Secoraa-platform@v1
  with:
    target-url: http://localhost:8000
    openapi-spec: ./openapi.json
    secoraa-api-key: ${{ secrets.SECORAA_API_KEY }}
```

### Option C — Docker compose

```yaml
- name: Start API
  run: docker compose up -d && sleep 10

- name: Run Secoraa Security Scan
  uses: Secoraa/Secoraa-platform@v1
  with:
    target-url: http://localhost:8000
    openapi-spec: ./openapi.json
    secoraa-api-key: ${{ secrets.SECORAA_API_KEY }}
```

---

## Configuration reference

All inputs for the action:

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `target-url` | Yes | — | Base URL of the API to scan |
| `openapi-spec` | No | `auto` | Path to OpenAPI/Swagger spec, or `auto` to detect `openapi.{json,yaml}` / `swagger.*` |
| `auth-token` | No | `''` | Bearer/API key/basic token for authenticated endpoints |
| `auth-type` | No | `bearer` | `bearer`, `api_key`, or `basic` |
| `secondary-token` | No | `''` | Second low-privilege token for BOLA/BFLA cross-user tests |
| `scan-mode` | No | `active` | `active` (sends payloads) or `passive` (observation only) |
| `severity-threshold` | No | `HIGH` | Fail on findings at or above: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `fail-on-findings` | No | `true` | Exit with code 1 if threshold hit (blocks PR merge) |
| `ignore-rules` | No | `''` | Comma-separated OWASP categories to skip (e.g. `API8:2023,API9:2023`) |
| `output-format` | No | `sarif` | `sarif` or `json` |
| `output-file` | No | `secoraa-results.sarif` | Where to write the result file |
| `pr-comment` | No | `true` | Post a scan summary comment on the PR |
| `github-token` | No | `${{ github.token }}` | Token for PR comments |
| `secoraa-url` | No | `https://secoraa-backend.onrender.com` | Platform URL for result sync |
| `secoraa-api-key` | No | `''` | API key for platform sync (no sync if empty) |

---

## Scanning authenticated endpoints

Most APIs require a token to test endpoints meaningfully. Add an auth token as a GitHub secret, then pass it:

```yaml
- name: Run Secoraa Security Scan
  uses: Secoraa/Secoraa-platform@v1
  with:
    target-url: https://staging.your-api.com
    openapi-spec: ./openapi.json
    auth-token: ${{ secrets.API_AUTH_TOKEN }}
    auth-type: bearer
    secoraa-api-key: ${{ secrets.SECORAA_API_KEY }}
```

For BOLA/BFLA tests across user boundaries, also pass `secondary-token`:

```yaml
    secondary-token: ${{ secrets.API_LOW_PRIV_TOKEN }}
```

---

## Active vs passive scans

- **Passive** — observes responses only. Safe to run against production. Catches missing security headers, CORS misconfig, info disclosure, exposed admin paths.
- **Active** (default) — sends attack payloads (SQLi, BOLA, auth bypass, mass assignment, etc.). **Only run against staging or test environments.**

```yaml
scan-mode: passive   # safe for prod
scan-mode: active    # staging only — sends payloads
```

---

## Configuration via `.secoraa.yml`

Instead of (or in addition to) action inputs, drop a `.secoraa.yml` at your repo root:

```yaml
scan:
  target: https://staging.your-api.com
  spec: ./docs/openapi.yaml
  mode: active
  auth:
    type: bearer
    token_env: API_AUTH_TOKEN

gate:
  severity_threshold: HIGH
  fail_on_findings: true
  ignore_rules:
    - API8:2023

report:
  format: sarif
  output_file: secoraa-results.sarif
```

CLI flags > env vars > `.secoraa.yml` > defaults.

---

## What you'll see after a successful scan

1. **GitHub Actions tab** — green check on the run, downloadable SARIF artifact
2. **Pull request** — automated comment summarizing findings by severity
3. **Repository → Security tab → Code scanning** — each finding rendered as an alert with file/line context
4. **Secoraa platform → Scans → CI/CD Scans** — full scan history across all your repos, with CVSS scoring, trend tracking, and remediation guidance

---

## Troubleshooting

**`unable to find image 'ghcr.io/secoraa/api-security-scanner:v1'`**
The Secoraa scanner image is unavailable. Check status at <https://github.com/Secoraa/Secoraa-platform>.

**`OpenAPI spec not found`**
Confirm the path in `openapi-spec` exists in the checkout. Use `openapi-spec: auto` to let the scanner discover `openapi.{json,yaml}` or `swagger.*` automatically.

**Scan finds 0 endpoints**
Most endpoints require auth. Provide `auth-token` and `auth-type`, or your spec may not list authentication requirements correctly.

**Findings appear in GitHub Security tab but not in Secoraa platform**
Verify `SECORAA_API_KEY` is a real `sec_...` key (not a placeholder) and is reachable from the runner. The scan succeeds even when sync fails — check the action logs for sync errors.

**Connection timeout to target**
If your API is on a free-tier host that sleeps (Render, Heroku), add a wake-up step before the scan:

```yaml
- name: Wake up API
  run: |
    for i in 1 2 3 4 5 6 7 8 9 10; do
      curl -sf https://staging.your-api.com/health && break
      sleep 10
    done
```

---

## Support

- Issues: <https://github.com/Secoraa/Secoraa-platform/issues>
- Platform: <https://secoraa-frontend.onrender.com/>
