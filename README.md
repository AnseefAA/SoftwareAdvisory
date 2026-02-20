# AdvisoryIntelligence

A simplified FastAPI-based service that provides **targeted remediation generation** for security advisories using IBM WatsonX AI.

## Overview

AdvisoryIntelligence is a streamlined version of the Advisory_Intelligence project, containing only the **Targeted Remediation API**. It generates comprehensive, step-by-step remediation instructions for specific product/package combinations within security advisories.

## Features

- **Single API Endpoint**: `/api/v1/advisory/remediation/generate-targeted`
- **AI-Powered Remediation**: Uses IBM WatsonX AI (Granite-3-8b-instruct model)
- **Comprehensive Steps**: Generates 14 detailed remediation steps including:
  - Pre-requisite checks
  - Backup procedures
  - Package updates
  - Service restarts
  - Verification steps
  - Rollback procedures
- **Smart Metadata**: Automatically calculates:
  - Reboot requirements
  - Maintenance window needs
  - Risk levels
  - Package scope (kernel/system/library/application)
  - Estimated downtime
- **Database Integration**: Fetches advisory and CVE data from PostgreSQL
- **Automatic CVE Discovery**: Retrieves all related CVEs from the database

## Architecture

```
AdvisoryIntelligence/
├── app/
│   ├── main.py                          # FastAPI application
│   ├── models.py                        # Pydantic models
│   ├── core/
│   │   ├── config.py                    # Configuration
│   │   └── db.py                        # Database connection
│   ├── db/
│   │   ├── models.py                    # SQLAlchemy models
│   │   └── operations.py                # Database operations
│   ├── routes/
│   │   └── v1/
│   │       └── advisory_routes.py       # Targeted remediation endpoint
│   ├── services/
│   │   └── ai/
│   │       ├── llm_service.py          # WatsonX AI integration
│   │       └── prompts.py              # AI prompts
│   └── utils/
│       └── httputil.py                  # HTTP utilities
├── db.sql                               # Database schema
├── requirements.txt                     # Python dependencies
├── .env.example                         # Environment variables template
├── start.sh                             # Start script
└── README.md                            # This file
```

## Prerequisites

- Python 3.9+
- PostgreSQL database (with schema from `db.sql`)
- IBM WatsonX AI credentials
- Advisory data populated in database (from Advisory_Intelligence project)

## Installation

### 1. Clone and Setup

```bash
cd AdvisoryIntelligence
```

### 2. Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your settings:

```env
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# IBM WatsonX AI Configuration
WATSONX_API_KEY=your_api_key_here
WATSONX_PROJECT_ID=your_project_id_here
WATSONX_URL=https://us-south.ml.cloud.ibm.com
```

### 5. Setup Database

Run the database schema:

```bash
psql -U your_user -d your_database -f db.sql
```

**Note**: You need to populate the database with advisory data first using the Advisory_Intelligence project's assess API.

## Usage

### Start the Server

```bash
./start.sh
```

Or manually:

```bash
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at:
- **API**: http://0.0.0.0:8000
- **Documentation**: http://0.0.0.0:8000/docs
- **Health Check**: http://0.0.0.0:8000/health

### API Endpoint

#### POST `/api/v1/advisory/remediation/generate-targeted`

Generate targeted remediation steps for a specific product/package combination.

**Request Body:**

```json
{
  "advisory_id": "ALAS-2024-1234",
  "product": "Amazon Linux 2",
  "package": "runc"
}
```

**Response:**

```json
{
  "advisory_id": "ALAS-2024-1234",
  "vendor": "Amazon",
  "title": "Important: runc security update",
  "severity": "IMPORTANT",
  "product": "Amazon Linux 2",
  "package": "runc",
  "cve_ids": ["CVE-2024-21626"],
  "remediation_steps": [
    {
      "step_id": 1,
      "title": "Pre-Remediation Assessment",
      "description": "Verify system requirements and current package version",
      "action_type": "verification",
      "commands": [
        "rpm -qa | grep runc",
        "docker --version",
        "systemctl status docker"
      ],
      "files_to_check": ["/etc/docker/daemon.json"],
      "directories_to_navigate": ["/var/lib/docker"],
      "expected_output": "Current runc version displayed",
      "verification_steps": [
        "Confirm runc is installed",
        "Check Docker service status"
      ],
      "automation_possible": true,
      "requires_sudo": true,
      "estimated_time_minutes": 2
    }
    // ... 13 more steps
  ],
  "is_reboot_required": false,
  "requires_maintenance_window": true,
  "risk_level": "HIGH",
  "package_scope": "application",
  "estimated_downtime_minutes": 2,
  "generated_at": "2024-01-15T10:30:00.000Z",
  "saved_to_database": true
}
```

### Example cURL Request

```bash
curl -X POST "http://0.0.0.0:8000/api/v1/advisory/remediation/generate-targeted" \
  -H "Content-Type: application/json" \
  -d '{
    "advisory_id": "ALAS-2024-1234",
    "product": "Amazon Linux 2",
    "package": "runc"
  }'
```

## Response Fields

### Remediation Step Fields

- **step_id**: Sequential step number
- **title**: Step title
- **description**: Detailed description
- **action_type**: Type of action (command, verification, backup, configuration)
- **commands**: List of commands to execute
- **files_to_check**: Files that should be checked/modified
- **directories_to_navigate**: Directories to navigate to
- **expected_output**: Expected command output
- **verification_steps**: Steps to verify success
- **automation_possible**: Whether step can be automated
- **requires_sudo**: Whether sudo/root access is needed
- **estimated_time_minutes**: Estimated time to complete

### Metadata Fields

- **is_reboot_required**: Whether system reboot is needed
- **requires_maintenance_window**: Whether maintenance window is recommended
- **risk_level**: CRITICAL, HIGH, MEDIUM, or LOW
- **package_scope**: kernel, system, library, or application
- **estimated_downtime_minutes**: Estimated downtime in minutes

## Database Schema

The project uses the same database schema as Advisory_Intelligence. Key tables:

- **advisory**: Security advisories
- **vulnerability**: CVE records
- **product**: Product information
- **package**: Package information
- **vulnerability_advisories**: CVE-Advisory relationships
- **advisories_products**: Advisory-Product relationships
- **vulnerability_packages**: CVE-Package relationships

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `WATSONX_API_KEY` | IBM WatsonX AI API key | Yes |
| `WATSONX_PROJECT_ID` | IBM WatsonX project ID | Yes |
| `WATSONX_URL` | WatsonX API endpoint | Yes |

### AI Model Configuration

The API uses the **IBM Granite-3-8b-instruct** model with:
- **Max Tokens**: 8000 (for comprehensive responses)
- **Temperature**: 0.3 (for consistent, focused output)

## Error Handling

The API provides detailed error messages:

- **404**: Advisory not found in database
- **503**: Database connection error
- **500**: AI processing error or internal server error

## Differences from Advisory_Intelligence

AdvisoryIntelligence is a **simplified version** with:

✅ **Included:**
- Targeted remediation API
- Database integration
- WatsonX AI integration
- Same architecture and code quality

❌ **Excluded:**
- Intelligence assessment API
- Intelligence fetch API
- Intelligence structured API
- CVE enrichment API
- Advisory enrichment API
- Product enrichment API
- Query APIs
- All other endpoints

## Dependencies

Key dependencies:
- **FastAPI**: Web framework
- **SQLAlchemy**: Database ORM
- **asyncpg**: Async PostgreSQL driver
- **ibm-watsonx-ai**: IBM WatsonX AI SDK
- **langchain-core**: LLM prompt management
- **pydantic**: Data validation

See `requirements.txt` for complete list.

## Development

### Running in Development Mode

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### API Documentation

FastAPI automatically generates interactive API documentation:
- **Swagger UI**: http://0.0.0.0:8000/docs
- **ReDoc**: http://0.0.0.0:8000/redoc

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -U your_user -d your_database -c "SELECT 1;"
```

### Advisory Not Found

Make sure to populate the database first using Advisory_Intelligence:

```bash
# In Advisory_Intelligence project
curl -X POST "http://0.0.0.0:8000/api/v1/intelligence/assess" \
  -H "Content-Type: application/json" \
  -d '{"advisory_id": "ALAS-2024-1234"}'
```

### WatsonX AI Errors

- Verify API key and project ID in `.env`
- Check WatsonX service status
- Ensure sufficient API quota

## License

Same as Advisory_Intelligence project.

## Support

For issues or questions, refer to the Advisory_Intelligence project documentation.

---

**Made with Bob** 🤖