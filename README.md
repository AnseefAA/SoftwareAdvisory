# Advisory Intelligence API

A streamlined vulnerability intelligence platform with AI-powered analysis, focusing on essential APIs for advisory remediation and intelligence gathering.

## Overview

This project is a simplified version of the SoftwareAdvisory platform, containing only the 4 essential APIs:

1. **Advisory Remediation Generation** - `/api/v1/advisory/remediation/generate`
2. **Intelligence Assessment** - `/api/v1/intelligence/assess`
3. **Structured Intelligence** - `/api/v1/intelligence/structured`
4. **Intelligence Fetch** - `/api/v1/intelligence/fetch`

## Features

- 🤖 **AI-Powered Remediation**: Generate step-by-step remediation plans using IBM WatsonX AI
- 🔍 **Multi-Source Intelligence**: Aggregate CVE data from NVD, MITRE, GitHub CVE Project, and OSV.dev
- 📊 **Structured Data**: Convert raw intelligence into database-ready structured format
- 💾 **Intelligent Caching**: Save and reuse intelligence data to minimize API calls
- 🗄️ **Database Integration**: PostgreSQL/SQLite support for persistent storage

## Project Structure

```
Advisory_Intelligence/
├── app/
│   ├── core/              # Core configuration
│   ├── db/                # Database models and operations
│   ├── models.py          # Pydantic models
│   ├── routes/            # API routes
│   │   └── v1/
│   │       ├── advisory_routes.py
│   │       └── intelligence_routes.py
│   ├── services/          # AI services
│   │   └── ai/
│   │       ├── llm_service.py
│   │       └── prompts.py
│   ├── utils/             # Utility functions
│   │   ├── httputil.py
│   │   └── intelligence_helpers.py
│   ├── data/              # Data storage
│   │   ├── intelligence/  # Raw intelligence JSON files
│   │   └── intelligence_db/  # Structured intelligence DB
│   └── main.py            # FastAPI application
├── requirements.txt
├── .env.example
└── README.md
```

## Installation

### Prerequisites

- Python 3.9+
- PostgreSQL (optional, can use SQLite for development)
- IBM WatsonX AI account and API key

### Setup

1. **Clone the repository**
   ```bash
   cd Advisory_Intelligence
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

5. **Set up database** (optional, SQLite is used by default)
   ```bash
   # For PostgreSQL, update DATABASE_URL in .env
   # DATABASE_URL=postgresql://user:password@localhost:5432/advisory_intelligence
   ```

## Configuration

Edit `.env` file with your credentials:

```env
# WatsonX AI Configuration
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_API_KEY=your_api_key_here
WATSONX_API_PROJECT_ID=your_project_id_here

# Database Configuration (SQLite for development)
DB_TYPE=sqlite
DB_NAME=./advisory_intelligence.db

# For PostgreSQL (production):
# DB_TYPE=postgresql
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=advisory_intelligence
# DB_USERNAME=postgres
# DB_PASSWORD=your_password
```

## Running the Application

### Development Server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

The API will be available at:
- **API Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health

## API Endpoints

### 1. Advisory Remediation Generation

Generate AI-powered remediation steps for a security advisory.

**Endpoint**: `POST /api/v1/advisory/remediation/generate`

**Request**:
```json
{
  "advisory_id": "RHSA-2024:1234"
}
```

**Response**:
```json
{
  "advisory_id": "RHSA-2024:1234",
  "vendor": "Red Hat",
  "title": "Security Advisory Title",
  "severity": "CRITICAL",
  "remediation_steps": [
    {
      "step_id": 1,
      "title": "Identify Affected Systems",
      "description": "Check if your system is affected...",
      "commands": ["rpm -qa | grep package-name"],
      "expected_output": "package-name-1.2.3",
      "automation_possible": true
    }
  ],
  "generated_at": "2024-01-15T10:30:00Z",
  "saved_to_database": true
}
```

### 2. Intelligence Fetch

Fetch and save CVE intelligence from multiple sources.

**Endpoint**: `POST /api/v1/intelligence/fetch`

**Request**:
```json
{
  "cveId": "CVE-2024-21626"
}
```

**Response**:
```json
{
  "status": "success",
  "cve_id": "CVE-2024-21626",
  "file_path": "app/data/intelligence/CVE-2024-21626.json",
  "sources_fetched": ["NVD", "MITRE", "GitHub CVE Project", "OSV.dev"],
  "fetched_at": "2024-01-15T10:30:00Z"
}
```

### 3. Intelligence Assessment

Assess CVE intelligence and return structured data.

**Endpoint**: `POST /api/v1/intelligence/assess`

**Request**:
```json
{
  "cveId": "CVE-2024-21626"
}
```

**Response**: Returns `StructuredIntelligenceResponse` with complete vulnerability data.

### 4. Structured Intelligence

Get structured CVE intelligence for database storage.

**Endpoint**: `POST /api/v1/intelligence/structured`

**Request**:
```json
{
  "cveId": "CVE-2024-21626"
}
```

**Response**: Returns structured data including CVE records, products, patches, lifecycle info, etc.

## Data Sources

The platform aggregates intelligence from:

- **NVD** (National Vulnerability Database)
- **MITRE CVE AWG**
- **GitHub CVE Project**
- **OSV.dev** (Open Source Vulnerabilities)

## Database Schema

### Advisory Table
- advisory_id, vendor, title, severity
- advisory_url, published_date
- remediation_plan (JSON)

### Vulnerability Table
- cve_id, description, cvss_score, severity
- is_exploitable, is_patch_available
- published_date, last_modified_date

### CVEAdvisory Table
- Links CVEs to Advisories (many-to-many)

## Development

### Adding New Features

1. Add models to `app/models.py`
2. Create route handlers in `app/routes/v1/`
3. Add utility functions in `app/utils/`
4. Update `app/main.py` to include new routers

### Testing

```bash
# Run with test database
DATABASE_URL=sqlite:///./test.db uvicorn app.main:app --reload
```

## Differences from SoftwareAdvisory

This streamlined version:

✅ **Includes**:
- Advisory remediation generation
- Multi-source intelligence aggregation
- Structured intelligence extraction
- Database operations for advisories

❌ **Excludes**:
- GraphQL API
- Exposure/SAST remediation
- File upload functionality
- CVE feedback system
- Project metadata management
- Concert integration
- WCA token management
- Fuzzy matching utilities

## License

[Your License Here]

## Support

For issues and questions, please open an issue in the repository.