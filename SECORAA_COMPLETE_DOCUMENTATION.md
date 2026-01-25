# Secoraa Platform - Complete Documentation

## Overview

This document provides a complete backup and recreation guide for the Secoraa Platform. It includes all components, dependencies, configuration, and setup instructions needed to recreate the entire system from scratch.

## System Architecture

The Secoraa Platform is a comprehensive security scanning platform consisting of:

1. **Backend API** (FastAPI) - RESTful API service
2. **Frontend** (React) - Web-based user interface
3. **Scanners** - Multiple security scanning modules
4. **Database** (PostgreSQL) - Data storage
5. **Object Storage** (MinIO) - Scan results storage
6. **Message Queue** (Kafka) - Event streaming

## Complete File Structure

```
Secoraa-platform/
├── .env.example                    # Environment template
├── .gitignore                      # Git ignore rules
├── .streamlit/                     # Streamlit configuration
├── .vscode/                        # VSCode settings
├── README.md                       # Main README
├── docker-compose.yml              # Docker services
├── main.py                         # Main entry point
├── migration_add_discovery_source.sql  # DB migration
├── requirements.txt                # Python dependencies
├── SECORAA_COMPLETE_DOCUMENTATION.md  # This file
├── app/                            # Backend application
│   ├── api/                        # API endpoints
│   │   ├── api_scanner.py          # API scanning endpoints
│   │   ├── auth.py                 # Authentication endpoints
│   │   ├── reports.py              # Report endpoints
│   │   ├── scans.py                # Scan management endpoints
│   │   └── vulnerabilities.py      # Vulnerability endpoints
│   ├── database/                   # Database models and session
│   │   ├── models.py               # SQLAlchemy models
│   │   └── session.py              # Database session management
│   ├── endpoints/                  # Additional endpoints
│   │   ├── assets.py               # Asset management
│   │   ├── docs.py                 # Documentation endpoints
│   │   ├── minio_events.py         # MinIO event handlers
│   │   ├── request_body.py         # Request body validation
│   │   ├── subdomain.py            # Subdomain endpoints
│   │   └── subdomain_scan.py       # Subdomain scan endpoints
│   ├── events/                     # Event handling
│   │   └── producer.py             # Kafka event producer
│   ├── scanners/                   # Scanner implementations
│   │   ├── api_scanner/            # API scanner
│   │   │   ├── engine/              # API scanning engine
│   │   │   ├── parser/              # API specification parsers
│   │   │   ├── reporter/            # Report generation
│   │   │   ├── tests/               # Tests
│   │   │   ├── __init__.py          # Module initialization
│   │   │   └── main.py              # Main scanner logic
│   │   ├── subdomain_scanner/      # Subdomain scanner
│   │   │   ├── discovery/           # Subdomain discovery
│   │   │   ├── fingerprint/         # Service fingerprinting
│   │   │   ├── reporter/            # Reporting
│   │   │   ├── scoring/             # Vulnerability scoring
│   │   │   ├── utils/               # Utilities
│   │   │   ├── validation/          # Validation logic
│   │   │   ├── vulnerabilities/     # Vulnerability checks
│   │   │   ├── scan.py              # Scan orchestration
│   │   │   └── scanner.py           # Scanner interface
│   │   ├── base.py                 # Base scanner class
│   │   ├── dd_scanner.py           # Domain discovery scanner
│   │   └── registry.py             # Scanner registry
│   ├── schema_design/              # Schema documentation
│   │   └── asset_schema.md         # Asset schema
│   ├── schemas/                    # Pydantic schemas
│   │   ├── dd.py                   # Domain discovery schemas
│   │   └── scan.py                 # Scan schemas
│   ├── scripts/                    # Utility scripts
│   │   ├── add_discovery_source.py # Add discovery source
│   │   ├── add_discovery_source_column.py # Add column
│   │   ├── create_tables.py        # Create database tables
│   │   └── migrate_scan_results_to_subdomains.py # Migration
│   ├── services/                   # Services
│   │   └── minio_ingestion.py      # MinIO ingestion service
│   ├── storage/                    # Storage clients
│   │   ├── __init__.py             # Storage initialization
│   │   ├── file_storage.py        # File storage
│   │   └── minio_client.py         # MinIO client
│   ├── swagger/                    # Swagger assets
│   │   └── secoraa.jpg             # Logo
│   ├── API_SCANNER_MASTER_SPEC.md  # API scanner spec
│   ├── custom_swagger.py          # Custom swagger UI
│   ├── main.py                     # FastAPI application
│   └── test.py                     # Tests
├── docs/                           # Documentation
│   ├── auth.md                     # Authentication docs
│   ├── backend.md                  # Backend docs
│   ├── frontend-react.md           # Frontend docs
│   ├── index.md                    # Documentation index
│   ├── scanners.md                 # Scanner docs
│   └── troubleshooting.md          # Troubleshooting
├── frontend/                       # Legacy frontend (Streamlit)
│   ├── ui/                         # UI components
│   │   └── theme.py                # Theme configuration
│   ├── views/                      # Views
│   │   ├── asset_discovery.py      # Asset discovery view
│   │   └── scan.py                 # Scan view
│   ├── api_client.py               # API client
│   ├── app.py                      # Streamlit app
│   └── package-lock.json           # npm dependencies
├── frontend-react/                  # React frontend
│   ├── node_modules/               # npm packages
│   ├── public/                     # Public assets
│   │   ├── images/                 # Images
│   │   │   ├── README.md            # Image README
│   │   │   └── secoraa-logo.jpg     # Logo
│   │   └── index.html              # HTML template
│   ├── src/                        # Source code
│   │   ├── api/                    # API clients
│   │   │   └── apiClient.js         # API client
│   │   ├── components/             # React components
│   │   │   ├── ASMIcon.jsx          # Icons
│   │   │   ├── BellIcon.jsx         # Icons
│   │   │   │   ...                   # More icons
│   │   │   ├── Header.css           # Header styles
│   │   │   ├── Header.jsx           # Header component
│   │   │   ├── Notification.css     # Notification styles
│   │   │   ├── Notification.jsx     # Notification component
│   │   │   ├── Sidebar.css         # Sidebar styles
│   │   │   └── Sidebar.jsx         # Sidebar component
│   │   ├── pages/                  # Pages
│   │   │   ├── AssetDiscovery.css  # Asset discovery styles
│   │   │   ├── AssetDiscovery.jsx   # Asset discovery page
│   │   │   ├── Auth.css             # Auth styles
│   │   │   ├── Auth.jsx             # Auth page
│   │   │   ├── DomainGraph.css      # Domain graph styles
│   │   │   ├── DomainGraph.jsx      # Domain graph page
│   │   │   ├── Reporting.css        # Reporting styles
│   │   │   ├── Reporting.jsx        # Reporting page
│   │   │   ├── Scan.css             # Scan styles
│   │   │   ├── Scan.jsx             # Scan page
│   │   │   ├── ScanResults.css      # Scan results styles
│   │   │   ├── ScanResults.jsx      # Scan results page
│   │   │   ├── Vulnerability.css    # Vulnerability styles
│   │   │   └── Vulnerability.jsx    # Vulnerability page
│   │   ├── styles/                 # Global styles
│   │   │   ├── index.css           # Main styles
│   │   │   └── theme.css           # Theme styles
│   │   ├── App.css                 # App styles
│   │   ├── App.jsx                 # App component
│   │   └── main.jsx                # Entry point
│   ├── .babelrc                    # Babel config
│   ├── .gitignore                  # Git ignore
│   ├── package-lock.json           # npm lockfile
│   ├── package.json                # npm packages
│   ├── README.md                   # Frontend README
│   └── webpack.config.js           # Webpack config
├── scan_results/                   # Scan result files
│   ├── *.json                      # Scan result JSON files
└── test_minio_connection.py        # MinIO connection test
```

## Environment Configuration

### Required Environment Variables

Create a `.env` file in the root directory with the following variables:

```bash
# PostgreSQL Configuration
POSTGRES_DB=secoraa
POSTGRES_USER=secoraa
POSTGRES_PASSWORD=secoraa
POSTGRES_HOST=localhost
POSTGRES_PORT=15432

# MinIO Configuration
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin
MINIO_API_PORT=9000
MINIO_CONSOLE_PORT=9001
MINIO_ENDPOINT=localhost:9000

# Authentication Configuration
AUTH_TENANT=default
JWT_SECRET=change-me-in-local-and-prod
JWT_EXPIRES_MINUTES=240
```

## Dependencies

### Python Dependencies (requirements.txt)

```
aiohappyeyeballs==2.6.1
aiohttp==3.10.11
aiosignal==1.4.0
altair==5.5.0
annotated-doc==0.0.4
annotated-types==0.7.0
anyio==4.12.0
argon2-cffi==25.1.0
argon2-cffi-bindings==25.1.0
async-timeout==5.0.1
attrs==25.4.0
blinker==1.9.0
cachetools==6.2.4
certifi==2026.1.4
cffi==2.0.0
charset-normalizer==3.4.4
click==8.1.8
colorama==0.4.6
et_xmlfile==2.0.0
eval_type_backport==0.3.1
exceptiongroup==1.3.1
fastapi==0.128.0
frozenlist==1.8.0
fpdf2==2.7.9
gitdb==4.0.12
GitPython==3.1.46
googleapis-common-protos==1.72.0
h11==0.16.0
httpcore==1.0.9
httpx==0.28.1
idna==3.11
importlib_metadata==8.7.1
invoke==2.2.1
Jinja2==3.1.6
jsonschema==4.25.1
jsonschema-specifications==2025.9.1
kafka-python==2.0.2
markdown-it-py==3.0.0
MarkupSafe==3.0.3
mdurl==0.1.2
minio==7.2.20
mistralai==1.10.0
multidict==6.7.0
dnspython==2.6.1
narwhals==2.14.0
numpy==2.0.2
openpyxl==3.1.5
opentelemetry-api==1.38.0
opentelemetry-exporter-otlp-proto-common==1.38.0
opentelemetry-exporter-otlp-proto-http==1.38.0
opentelemetry-proto==1.38.0
opentelemetry-sdk==1.38.0
opentelemetry-semantic-conventions==0.59b0
packaging==25.0
pandas==2.3.3
pillow==11.3.0
propcache==0.4.1
protobuf==6.33.2
psycopg2-binary==2.9.11
pyarrow==21.0.0
pycparser==2.23
pycryptodome==3.23.0
pydantic==2.12.5
pydantic_core==2.41.5
pydeck==0.9.1
Pygments==2.19.2
python-dateutil==2.9.0.post0
python-dotenv==1.0.0
pytz==2025.2
PyYAML==6.0.3
PyJWT==2.10.1
referencing==0.36.2
requests==2.32.5
rich==14.2.0
rpds-py==0.27.1
six==1.17.0
smmap==5.0.2
SQLAlchemy==2.0.45
starlette==0.49.3
streamlit==1.50.0
tenacity==9.1.2
termcolor==3.1.0
toml==0.10.2
tornado==6.5.4
typing-inspection==0.4.2
typing_extensions==4.15.0
tzdata==2025.3
urllib3==2.6.2
uvicorn==0.39.0
yarl==1.22.0
zipp==3.23.0
```

### Frontend Dependencies (frontend-react/package.json)

**Dependencies:**
```json
"react": "^18.2.0"
"react-dom": "^18.2.0"
"react-router-dom": "^6.20.0"
"axios": "^1.6.2"
"xlsx": "^0.18.5"
```

**Dev Dependencies:**
```json
"@babel/core": "^7.23.5"
"@babel/preset-env": "^7.23.5"
"@babel/preset-react": "^7.23.0"
"@types/react": "^18.2.43"
"@types/react-dom": "^18.2.17"
"babel-loader": "^9.1.3"
"css-loader": "^6.8.1"
"html-webpack-plugin": "^5.5.3"
"style-loader": "^3.3.3"
"webpack": "^5.89.0"
"webpack-cli": "^5.1.4"
"webpack-dev-server": "^4.15.1"
```

### Docker Services

The `docker-compose.yml` defines the following services:

1. **PostgreSQL** (secoraa-postgres)
   - Image: `postgres:15`
   - Port: `15432:5432`
   - Volume: `postgres_data`

2. **MinIO** (secoraa-minio)
   - Image: `minio/minio:latest`
   - Ports: `9000:9000` (API), `9001:9001` (Console)
   - Volume: `minio_data`

3. **Zookeeper** (secoraa-zookeeper)
   - Image: `confluentinc/cp-zookeeper:7.5.0`
   - Port: `2181:2181`

4. **Kafka** (secoraa-kafka)
   - Image: `confluentinc/cp-kafka:7.5.0`
   - Port: `9092:9092`

## Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd Secoraa-platform
```

### 2. Create Environment File

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Start Docker Services

```bash
docker-compose up -d postgres minio zookeeper kafka
```

### 4. Set Up Database

```bash
python app/scripts/create_tables.py
```

### 5. Install Python Dependencies

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 6. Install Frontend Dependencies

```bash
cd frontend-react
npm install
cd ..
```

### 7. Start Backend

```bash
uvicorn app.main:app --reload --port 8000
```

### 8. Start Frontend

```bash
cd frontend-react
npm run dev
```

## API Endpoints

### Authentication

- `POST /auth/signup` - Create a new user
- `POST /auth/login` - Login and get JWT token
- `GET /auth/token` - Validate JWT token

### Scans

- `POST /scans/` - Create a new scan
- `GET /scans/` - List all scans
- `GET /scans/{scan_id}` - Get scan details
- `GET /scans/{scan_id}/results` - Get scan results

### API Scanner

- `POST /scanner/api` - Run API scan
- `GET /scanner/api/reports` - List API scan reports

### Vulnerabilities

- `GET /vulnerabilities/findings` - Get all vulnerability findings
- `GET /vulnerabilities/findings/{finding_id}` - Get specific finding

### Assets

- `GET /assets/` - List all assets
- `POST /assets/` - Create new asset
- `GET /assets/{asset_id}` - Get asset details

### Subdomains

- `GET /subdomain/` - List all subdomains
- `POST /subdomain/` - Create new subdomain
- `GET /subdomain/{subdomain_id}` - Get subdomain details

### Reports

- `GET /reports/` - List all reports
- `GET /reports/{report_id}` - Get report details

## Scanner Types

### 1. Domain Discovery (DD) Scanner

**Purpose**: Discover subdomains for a given domain.

**API Request:**
```json
{
  "scan_name": "my-dd-scan",
  "scan_type": "dd",
  "payload": { "domain": "example.com" }
}
```

**Results**: List of discovered subdomains with metadata.

### 2. Subdomain Scanner

**Purpose**: Scan subdomains for vulnerabilities and misconfigurations.

**API Request:**
```json
{
  "scan_name": "my-subdomain-scan",
  "scan_type": "subdomain",
  "payload": {
    "domain": "example.com",
    "subdomains": ["api.example.com", "mail.example.com"]
  }
}
```

**Checks Performed:**
- Exposure checks (exposed paths/resources)
- Misconfiguration checks (security headers, server signals)
- Takeover checks (CNAME fingerprinting)

### 3. API Testing Scanner

**Purpose**: Test API endpoints based on OpenAPI/Postman specifications.

**API Request:**
```json
{
  "scan_name": "my-api-scan",
  "scan_type": "api",
  "payload": {
    "target_url": "https://api.example.com",
    "specification": "openapi",
    "spec_url": "https://api.example.com/openapi.json"
  }
}
```

**Results**: API test results with vulnerabilities and recommendations.

## Database Schema

### Main Tables

1. **users** - User authentication
2. **scans** - Scan metadata
3. **scan_results** - Scan results
4. **subdomains** - Discovered subdomains
5. **vulnerabilities** - Vulnerability findings
6. **api_scan_reports** - API scan reports
7. **assets** - Asset inventory

### Key Relationships

- Scans → Scan Results (one-to-many)
- Scans → Vulnerabilities (one-to-many)
- Assets → Subdomains (one-to-many)
- Users → Scans (many-to-many via tenant)

## Frontend Pages

### 1. Asset Discovery
- Manage domains, subdomains, IPs, and URLs
- View asset inventory
- Import/export assets

### 2. Scan
- Run new scans (DD, API, Subdomain)
- View scan history
- View scan results
- Download reports

### 3. Vulnerability
- Unified view of all vulnerability findings
- Filter by severity, type, status
- View vulnerability details
- Export findings

### 4. Domain Insight
- Visual graph of domains and subdomains
- Relationship mapping
- Interactive exploration

### 5. Reporting
- Generate comprehensive reports
- Custom report templates
- Export to PDF/Excel

## Storage

### Local Storage
- Scan results stored in `scan_results/` directory
- JSON format with scan metadata and results

### MinIO Storage
- Bucket: `secoraa-scan-outputs`
- Stores scan results, reports, and artifacts
- Accessible via MinIO console at `http://localhost:9001`

## Event System

### Kafka Topics
- `scan-events` - Scan lifecycle events
- `vulnerability-events` - Vulnerability findings
- `asset-events` - Asset changes

### Event Producer
- Located in `app/events/producer.py`
- Publishes events to Kafka topics
- Used by scanners and API endpoints

## Security Features

### Authentication
- JWT Bearer token authentication
- Argon2 password hashing
- Tenant-based isolation

### Authorization
- Role-based access control (planned)
- Tenant isolation
- API rate limiting (planned)

### Data Protection
- Encrypted credentials in environment variables
- Secure storage of scan results
- Audit logging (planned)

## Troubleshooting

### Common Issues

**1. Database connection refused**
- Ensure Docker is running
- Check PostgreSQL container status: `docker ps`
- Verify `.env` has correct credentials

**2. MinIO credentials missing**
- Ensure `.env` has `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD`
- Restart MinIO container: `docker-compose restart minio`

**3. JWT_SECRET missing**
- Set `JWT_SECRET` in `.env`
- Must be a strong, random string

**4. UndefinedColumn errors**
- Run database migration: `python app/scripts/create_tables.py`
- This adds missing columns without data loss

**5. Frontend connection issues**
- Verify backend is running on `http://localhost:8000`
- Check CORS settings in `app/main.py`
- Verify `REACT_APP_API_URL` in frontend `.env`

### Debugging Tips

1. **Check logs**:
   ```bash
   docker logs secoraa-postgres
   docker logs secoraa-minio
   ```

2. **Test connections**:
   ```bash
   python test_minio_connection.py
   ```

3. **Verify environment**:
   ```bash
   env | grep POSTGRES
   env | grep MINIO
   ```

4. **Database inspection**:
   ```bash
   psql -h localhost -p 15432 -U secoraa -d secoraa
   ```

## Deployment

### Production Checklist

1. [ ] Set strong `JWT_SECRET`
2. [ ] Configure production database
3. [ ] Set up MinIO with proper credentials
4. [ ] Configure proper CORS for production domains
5. [ ] Set up HTTPS
6. [ ] Configure backup for PostgreSQL and MinIO
7. [ ] Set up monitoring and logging
8. [ ] Configure proper resource limits

### Docker Production

```bash
# Build production image
DOCKER_BUILDKIT=1 docker build -t secoraa-backend .

# Run with environment
docker run -d \
  --name secoraa-backend \
  --env-file .env \
  --network host \
  -p 8000:8000 \
  secoraa-backend
```

### Frontend Production Build

```bash
cd frontend-react
npm run build
# Serve the dist/ directory with nginx or similar
```

## Backup and Recovery

### Database Backup

```bash
# Backup PostgreSQL
pg_dump -h localhost -p 15432 -U secoraa -d secoraa -F c -f secoraa_backup.dump
```

### MinIO Backup

```bash
# Use MinIO client mc to backup
mc mb local/secoraa-backup
mc cp minio/secoraa-scan-outputs local/secoraa-backup/
```

### Full System Backup

1. Backup database
2. Backup MinIO buckets
3. Backup configuration files
4. Backup scan_results directory
5. Backup .env file

## Performance Considerations

### Database Optimization
- Use connection pooling
- Add indexes to frequently queried columns
- Consider read replicas for reporting

### Scanner Optimization
- Limit concurrent scans
- Implement scan queueing
- Cache scan results
- Use efficient subdomain discovery methods

### Frontend Optimization
- Implement pagination for large datasets
- Lazy load components
- Cache API responses
- Optimize image assets

## Future Enhancements

### Planned Features
- Role-based access control
- API rate limiting
- Audit logging
- Scheduled scans
- Integration with vulnerability databases
- Custom vulnerability rules
- Team collaboration features
- Advanced reporting and dashboards

## Contact and Support

For issues or questions, please refer to:
- Documentation in the `docs/` directory
- Git history for changes
- Issue tracker for bugs and feature requests

---

This documentation provides a complete reference for recreating the Secoraa Platform. All configuration, dependencies, and setup instructions are included to ensure the system can be rebuilt exactly as it was originally implemented.
