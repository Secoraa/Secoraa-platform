# Secoraa Platform - Complete Dependencies & Deployment Guide

This file contains all dependencies and deployment information for the Secoraa Platform.

## Project Structure
- **Backend**: Python/FastAPI application
- **Frontend**: React application
- **Database**: PostgreSQL
- **Storage**: MinIO (S3-compatible)
- **Message Queue**: Apache Kafka

## Dependencies

### Backend (Python) - requirements.txt
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

### Frontend (React) - package.json
```json
{
  "name": "secoraa-frontend",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "start": "webpack serve --mode development",
    "dev": "webpack serve --mode development",
    "build": "webpack --mode production",
    "preview": "serve -s dist"
  },
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

### Infrastructure - docker-compose.yml
```yaml
version: "3.9"

services:
  postgres:
    image: postgres:15
    container_name: secoraa-postgres
    restart: unless-stopped
    env_file:
      - .env
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "15432:5432"

  minio:
    image: minio/minio:latest
    container_name: secoraa-minio
    restart: unless-stopped
    env_file:
      - .env
    command: server /data --console-address ":${MINIO_CONSOLE_PORT}"
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    volumes:
      - minio_data:/data
    ports:
      - "${MINIO_API_PORT}:9000"
      - "${MINIO_CONSOLE_PORT}:9001"

  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    container_name: secoraa-zookeeper
    restart: unless-stopped
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - "2181:2181"

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    container_name: secoraa-kafka
    restart: unless-stopped
    depends_on:
      - zookeeper
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1

volumes:
  postgres_data:
  minio_data:
```

## Deployment Options

### 1. Docker Deployment (Recommended)
```bash
# Build and run all services
docker-compose up -d

# Build frontend
cd frontend-react
npm install
npm run build

# Run backend
cd ..
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 2. Cloud Deployment Options

#### Heroku
- Backend: Deploy Python app to Heroku
- Frontend: Deploy React build to Heroku or Netlify
- Database: Use Heroku PostgreSQL
- Storage: Use AWS S3 or Heroku Buckets

#### AWS
- Backend: EC2 or Lambda
- Frontend: S3 + CloudFront
- Database: RDS PostgreSQL
- Storage: S3
- Message Queue: Amazon MSK (Kafka)

#### Vercel + Railway/Render
- Frontend: Vercel (React)
- Backend: Railway/Render (Python)
- Database: Railway/Render PostgreSQL
- Storage: AWS S3

### 3. Environment Variables (.env)
```
# Database
POSTGRES_DB=secoraa_db
POSTGRES_USER=secoraa_user
POSTGRES_PASSWORD=your_password

# MinIO
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin
MINIO_API_PORT=9000
MINIO_CONSOLE_PORT=9001

# Backend
API_PORT=8000
SECRET_KEY=your_secret_key

# Frontend
REACT_APP_API_URL=http://localhost:8000
```

## Quick Start Commands

```bash
# 1. Install dependencies
pip install -r requirements.txt
cd frontend-react && npm install

# 2. Start infrastructure
docker-compose up -d

# 3. Run backend
uvicorn main:app --reload

# 4. Run frontend (in new terminal)
cd frontend-react && npm start
```

## Production Deployment Checklist

1. **Security**: 
   - Change all default passwords
   - Use HTTPS/SSL certificates
   - Set up firewalls

2. **Performance**:
   - Enable production builds
   - Set up reverse proxy (Nginx)
   - Configure load balancing

3. **Monitoring**:
   - Set up logging
   - Monitor resource usage
   - Health checks

4. **Backup**:
   - Database backups
   - File storage backups
   - Disaster recovery plan