## Scanners

This repo contains multiple scanners under `app/scanners/`.

### 1) Domain Discovery (DD)

**Purpose**: Find subdomains for a root domain and store results.

- **Implementation**: `app/scanners/dd_scanner.py`
- **Registry key**: `dd` (see `app/scanners/registry.py`)
- **Run via API**: `POST /scans/` with `scan_type="dd"`

Payload:

```json
{
  "scan_name": "my-dd-scan",
  "scan_type": "dd",
  "payload": { "domain": "example.com" }
}
```

Results:
- `GET /scans/{scan_id}/results` returns subdomains list + count
- Also saved in `scan_results/` and uploaded to MinIO

### 2) Subdomain Scan

**Purpose**: For a selected subdomain (or list), run validation + vulnerability checks and persist findings.

- **Implementation**:
  - Core pipeline: `app/scanners/subdomain_scanner/scan.py`
  - `/scans/` plugin wrapper: `app/scanners/subdomain_scanner/scanner.py`
- **Registry key**: `subdomain` (see `app/scanners/registry.py`)

Run via API:

```json
{
  "scan_name": "my-subdomain-scan",
  "scan_type": "subdomain",
  "payload": {
    "domain": "example.com",
    "subdomains": ["api.example.com"]
  }
}
```

What it checks (high level):
- **Exposure**: exposed paths/resources (see `vulnerabilities/exposure.py`)
- **Misconfiguration**: missing security headers / server signals (see `vulnerabilities/misconfig.py`)
- **Takeover**: takeover fingerprints via CNAME checks (see `vulnerabilities/takeover.py`)

Where results show up:
- **Scan Results page** (frontend): vulnerabilities grouped by subdomain
- **Vulnerability page**: findings merged into `GET /vulnerabilities/findings`

### 3) API Testing Scanner

**Purpose**: Documentation-driven API testing (OpenAPI/Postman/Custom docs) + findings.

- **Backend API**: `POST /scanner/api`
- **Reports**: stored in MinIO + referenced in DB (`api_scan_reports`)
- **Vulnerability page**: shown via API findings and combined feed (`/vulnerabilities/*`)

### Storage

- **Local**: `scan_results/<scan_type>_<scan_name>_<scan_id>.json`
- **MinIO bucket**: `secoraa-scan-outputs`

