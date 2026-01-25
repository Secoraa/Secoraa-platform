# Secoraa Platform - Complete Replication Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Dependencies](#dependencies)
4. [Setup Instructions](#setup-instructions)
5. [Database Schema](#database-schema)
6. [API Documentation](#api-documentation)
7. [Scanner Architecture](#scanner-architecture)
8. [Frontend Architecture](#frontend-architecture)
9. [Configuration](#configuration)
10. [Development Workflow](#development-workflow)

---

## System Overview

**Secoraa Platform** is a comprehensive cybersecurity platform for asset discovery and vulnerability assessment. It consists of:

- **Backend**: FastAPI-based REST API with PostgreSQL database
- **Frontend**: React 18 web application with Webpack bundler
- **Scanners**: Modular security scanning system (Domain Discovery, Subdomain Scanner, API Security Testing)
- **Infrastructure**: Docker Compose with PostgreSQL, MinIO, Kafka, and Zookeeper

### Core Features
- Multi-tenant architecture with JWT authentication
- Domain and subdomain discovery
- API security testing and vulnerability assessment
- Real-time scan results and reporting
- Event-driven processing with Kafka
- File storage with MinIO integration

---

## Architecture

### High-Level Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React App     │    │   FastAPI       │    │   PostgreSQL    │
│   (Port 8501)   │◄──►│   (Port 8000)   │◄──►│   (Port 15432)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Scanner       │
                       │   Modules       │
                       └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   MinIO/Kafka   │
                       │   (Storage/Msg) │
                       └─────────────────┘
```

### Directory Structure
```
Secoraa-platform/
├── app/                          # FastAPI backend
│   ├── api/                      # API route handlers
│   │   ├── auth.py              # Authentication endpoints
│   │   ├── scans.py             # Scan management
│   │   ├── api_scanner.py       # API scanning endpoints
│   │   ├── vulnerabilities.py   # Vulnerability management
│   │   └── reports.py           # Report generation
│   ├── database/                 # Database layer
│   │   ├── models.py            # SQLAlchemy models
│   │   └── session.py           # Database session management
│   ├── endpoints/                # Additional API endpoints
│   │   ├── assets.py            # Asset management
│   │   ├── subdomain.py         # Subdomain operations
│   │   ├── docs.py              # Documentation endpoints
│   │   └── minio_events.py      # MinIO webhook handlers
│   ├── scanners/                 # Security scanning modules
│   │   ├── subdomain_scanner/   # Subdomain discovery scanner
│   │   ├── api_scanner/         # API security testing
│   │   ├── dd_scanner.py        # Domain discovery scanner
│   │   └── registry.py          # Scanner registry
│   ├── services/                 # Business logic services
│   ├── storage/                  # File storage abstraction
│   ├── schemas/                  # Pydantic data schemas
│   ├── scripts/                  # Utility and migration scripts
│   └── main.py                   # FastAPI application entry point
├── frontend-react/               # React web application
│   ├── src/
│   │   ├── components/          # React components
│   │   ├── pages/              # Page components
│   │   ├── api/                # API client
│   │   ├── App.jsx             # Main App component
│   │   └── main.jsx            # Entry point
│   ├── public/                  # Static assets
│   │   ├── index.html          # HTML template
│   │   └── images/             # Images and logos
│   └── webpack.config.js        # Webpack configuration
├── docs/                         # Documentation
├── scan_results/                 # Scan result storage
├── .env                          # Environment configuration
├── docker-compose.yml            # Infrastructure definition
├── requirements.txt              # Python dependencies
└── README.md                     # Project documentation
```

---

## Dependencies

### Python Backend Dependencies (requirements.txt)
```txt
fastapi==0.128.0
uvicorn[standard]==0.25.0
sqlalchemy==2.0.45
psycopg2-binary==2.9.9
pydantic==2.12.5
pydantic-settings==2.1.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
minio==7.2.20
kafka-python==2.0.2
streamlit==1.50.0
mistralai==1.10.0
opentelemetry-api==1.21.0
opentelemetry-sdk==1.21.0
requests==2.31.0
aiofiles==23.2.1
python-dotenv==1.0.0
```

### Frontend Dependencies (package.json)
```json
{
  "name": "secoraa-frontend",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "axios": "^1.6.2",
    "xlsx": "^0.18.5"
  },
  "devDependencies": {
    "@babel/core": "^7.23.5",
    "@babel/preset-env": "^7.23.5",
    "@babel/preset-react": "^7.23.0",
    "@types/react": "^18.2.43",
    "@types/react-dom": "^18.2.17",
    "babel-loader": "^9.1.3",
    "css-loader": "^6.8.1",
    "html-webpack-plugin": "^5.5.3",
    "style-loader": "^3.3.3",
    "webpack": "^5.89.0",
    "webpack-cli": "^5.1.4",
    "webpack-dev-server": "^4.15.1"
  }
}
```

### Infrastructure Dependencies
- **PostgreSQL**: 15 (Docker)
- **MinIO**: Latest (Docker)
- **Kafka**: 7.5.0 (Docker)
- **Zookeeper**: 7.5.0 (Docker)

---

## Setup Instructions

### Prerequisites
- Python 3.9+
- Node.js 16+
- Docker & Docker Compose
- Git

### Step 1: Clone Repository
```bash
git clone <repository-url>
cd Secoraa-platform
```

### Step 2: Environment Configuration
Create `.env` file in repository root:

```bash
# Database Configuration
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

# Authentication
AUTH_TENANT=default
JWT_SECRET=change-me-in-local-and-prod
JWT_EXPIRES_MINUTES=240

# Frontend API URL
REACT_APP_API_URL=http://localhost:8000
```

### Step 3: Start Infrastructure Services
```bash
docker-compose up -d postgres minio zookeeper kafka
```

### Step 4: Setup Python Backend
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create database tables
python app/scripts/create_tables.py

# Start backend server
uvicorn app.main:app --reload --port 8000
```

### Step 5: Setup Frontend
```bash
cd frontend-react

# Install dependencies
npm install

# Start development server
npm run dev
```

### Step 6: Verify Setup
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/api/v1alpha1/backend/docs
- Frontend: http://localhost:8501
- MinIO Console: http://localhost:9001

---

## Database Schema

### Core Tables

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,
    tenant VARCHAR NOT NULL DEFAULT 'default',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Domains Table
```sql
CREATE TABLE domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_name VARCHAR UNIQUE NOT NULL,
    tags VARCHAR[],
    discovery_source VARCHAR DEFAULT 'manual',
    is_reachable BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    is_archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR,
    updated_by VARCHAR
);
```

#### Subdomains Table
```sql
CREATE TABLE subdomains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    subdomain_name VARCHAR NOT NULL,
    tags VARCHAR[],
    is_reachable BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    is_archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR,
    updated_by VARCHAR,
    UNIQUE(domain_id, subdomain_name)
);
```

#### Scans Table
```sql
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_name VARCHAR UNIQUE NOT NULL,
    scan_type VARCHAR NOT NULL,
    status VARCHAR NOT NULL DEFAULT 'Running',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR
);
```

#### Vulnerabilities Table
```sql
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id UUID REFERENCES domains(id) ON DELETE CASCADE,
    subdomain_id UUID REFERENCES subdomains(id) ON DELETE CASCADE,
    vuln_name VARCHAR NOT NULL,
    description TEXT,
    cvss_score INTEGER,
    cvss_vector INTEGER,
    recommendation TEXT,
    reference TEXT,
    severity VARCHAR,
    tags VARCHAR[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR,
    updated_by VARCHAR
);
```

#### Findings Table
```sql
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_name VARCHAR NOT NULL,
    description TEXT,
    severity VARCHAR NOT NULL DEFAULT 'MEDIUM',
    risk_score INTEGER,
    is_patched BOOLEAN DEFAULT FALSE,
    is_manual BOOLEAN DEFAULT FALSE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    domain_id UUID REFERENCES domains(id) ON DELETE SET NULL,
    subdomain_id UUID REFERENCES subdomains(id) ON DELETE SET NULL,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR,
    updated_by VARCHAR
);
```

### Additional Tables
- **api_scan_reports**: API scan report storage
- **reports**: Generated reports (ASM, WEB, API)
- **ipaddress**: IP address assets
- **urls**: URL assets
- **scan_results**: Scan result storage

---

## API Documentation

### Authentication Endpoints
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/auth/me` - Get current user

### Scan Management Endpoints
- `GET /api/scans` - List all scans
- `POST /api/scans` - Create new scan
- `GET /api/scans/{scan_id}` - Get scan details
- `DELETE /api/scans/{scan_id}` - Delete scan

### Asset Management Endpoints
- `GET /api/assets/domains` - List domains
- `POST /api/assets/domains` - Create domain
- `GET /api/assets/subdomains` - List subdomains
- `POST /api/assets/subdomains` - Create subdomain

### Vulnerability Endpoints
- `GET /api/vulnerabilities` - List vulnerabilities
- `POST /api/vulnerabilities` - Create vulnerability
- `GET /api/vulnerabilities/{vuln_id}` - Get vulnerability details

### Scanner Endpoints
- `POST /api/scanner/subdomain` - Start subdomain scan
- `POST /api/scanner/api` - Start API security scan
- `GET /api/scanner/status/{scan_id}` - Get scan status

### Report Endpoints
- `GET /api/reports` - List reports
- `POST /api/reports` - Generate report
- `GET /api/reports/{report_id}/download` - Download report

### MinIO Webhook Endpoints
- `POST /api/webhooks/minio` - MinIO event handler

---

## Scanner Architecture

### Scanner Registry Pattern
The platform uses a pluggable scanner architecture with a registry pattern:

```python
# app/scanners/registry.py
class ScannerRegistry:
    def __init__(self):
        self.scanners = {}
    
    def register(self, name: str, scanner_class):
        self.scanners[name] = scanner_class
    
    def get_scanner(self, name: str):
        return self.scanners.get(name)
```

### Available Scanners

#### 1. Domain Discovery (DD) Scanner
- **File**: `app/scanners/dd_scanner.py`
- **Purpose**: Discover domains for a given organization
- **Methods**: Passive discovery, DNS enumeration

#### 2. Subdomain Scanner
- **Directory**: `app/scanners/subdomain_scanner/`
- **Components**:
  - `discovery/` - Subdomain discovery algorithms
  - `fingerprint/` - Technology fingerprinting
  - `vulnerabilities/` - Vulnerability detection
  - `scoring/` - Risk assessment
  - `validation/` - Result validation

#### 3. API Security Scanner
- **Directory**: `app/scanners/api_scanner/`
- **Components**:
  - `engine/` - Core scanning engine
  - `parser/` - API definition parsing
  - `tests/` - Security test modules
  - `reporter/` - Report generation

### Scanner Integration
Each scanner implements the base scanner interface:
```python
class BaseScanner:
    def __init__(self, config):
        self.config = config
    
    async def scan(self, target):
        raise NotImplementedError
    
    def generate_report(self, results):
        raise NotImplementedError
```

---

## Frontend Architecture

### React Application Structure
```
frontend-react/src/
├── components/          # Reusable components
├── pages/              # Page components
├── api/                # API client utilities
├── styles/             # CSS styles
├── App.jsx             # Main application component
└── main.jsx            # Application entry point
```

### Key Components
- **App.jsx**: Main application with routing
- **API Client**: Axios-based HTTP client
- **Authentication**: JWT token management
- **Dashboard**: Scan results and asset overview

### Webpack Configuration
- **Entry Point**: `src/main.jsx`
- **Output**: `dist/bundle.[contenthash].js`
- **Development Server**: Port 8501 with hot reload
- **Proxy**: API requests proxied to localhost:8000

### Build Process
```bash
# Development
npm run dev

# Production build
npm run build

# Preview production build
npm run preview
```

---

## Configuration

### Environment Variables
All configuration is managed through environment variables in the `.env` file:

#### Database Configuration
```bash
POSTGRES_DB=secoraa
POSTGRES_USER=secoraa
POSTGRES_PASSWORD=secoraa
POSTGRES_HOST=localhost
POSTGRES_PORT=15432
```

#### MinIO Configuration
```bash
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin
MINIO_API_PORT=9000
MINIO_CONSOLE_PORT=9001
MINIO_ENDPOINT=localhost:9000
```

#### Authentication Configuration
```bash
AUTH_TENANT=default
JWT_SECRET=change-me-in-local-and-prod
JWT_EXPIRES_MINUTES=240
```

#### Frontend Configuration
```bash
REACT_APP_API_URL=http://localhost:8000
```

### Database Configuration
Database connection is configured through SQLAlchemy:
```python
# app/database/session.py
DATABASE_URL = f"postgresql://{user}:{password}@{host}:{port}/{database}"
engine = create_async_engine(DATABASE_URL)
SessionLocal = sessionmaker(engine, class=AsyncSession, expire_on_commit=False)
```

### MinIO Configuration
MinIO client configuration:
```python
# app/storage/minio_client.py
client = Minio(
    endpoint,
    access_key=minio_root_user,
    secret_key=minio_root_password,
    secure=False
)
```

---

## Development Workflow

### Adding New Scanners
1. Create scanner module in `app/scanners/`
2. Implement base scanner interface
3. Register scanner in registry
4. Add API endpoints in `app/api/`
5. Update frontend components

### Database Migrations
1. Create migration script in `app/scripts/`
2. Update models in `app/database/models.py`
3. Run migration script
4. Test with existing data

### API Development
1. Define Pydantic schemas in `app/schemas/`
2. Implement endpoints in `app/api/`
3. Add authentication if required
4. Update API documentation

### Frontend Development
1. Create components in `frontend-react/src/components/`
2. Add pages in `frontend-react/src/pages/`
3. Update routing in `App.jsx`
4. Test with backend API

### Testing
```bash
# Backend tests
pytest app/tests/

# Frontend tests
npm test

# Integration tests
pytest integration_tests/
```

### Deployment
```bash
# Build frontend
cd frontend-react && npm run build

# Start production services
docker-compose -f docker-compose.prod.yml up -d

# Run database migrations
python app/scripts/create_tables.py
```

---

## Production Considerations

### Security
- Change default JWT secret
- Use HTTPS in production
- Implement rate limiting
- Secure MinIO with proper credentials

### Performance
- Optimize database queries
- Implement caching
- Use connection pooling
- Monitor resource usage

### Monitoring
- Implement logging
- Add health checks
- Monitor Kafka queues
- Track scan performance

### Backup
- Regular database backups
- MinIO bucket replication
- Configuration backups
- Disaster recovery plan

---

## Troubleshooting

### Common Issues

#### Database Connection
```bash
# Check PostgreSQL status
docker-compose ps postgres

# Check database logs
docker-compose logs postgres
```

#### MinIO Connection
```bash
# Check MinIO status
docker-compose ps minio

# Test MinIO connection
python -c "from app.storage.minio_client import client; print(client.list_buckets())"
```

#### Frontend Build Issues
```bash
# Clear node modules
rm -rf node_modules package-lock.json
npm install

# Clear webpack cache
npm run build -- --clean
```

#### Scanner Issues
```bash
# Check scanner logs
docker-compose logs app

# Test scanner manually
python -c "from app.scanners.dd_scanner import DDScanner; scanner = DDScanner({}); print(scanner.scan('example.com'))"
```

### Debug Mode
Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## Conclusion

This documentation provides a complete blueprint for replicating the Secoraa Platform. Follow the setup instructions step by step, ensure all dependencies are installed correctly, and verify each component before proceeding to the next.

For any issues or questions, refer to the troubleshooting section or check the logs for detailed error information.

**Note**: Always change default passwords and secrets before deploying to production.