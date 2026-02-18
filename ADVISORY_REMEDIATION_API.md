# Advisory Remediation API Guide

## Overview

The Advisory Remediation API generates step-by-step remediation plans for security advisories using WatsonX AI. It fetches advisory data from a PostgreSQL database, generates actionable remediation steps, and stores them back in the database.

## Features

- ✅ Fetch advisory details from PostgreSQL database
- ✅ Generate AI-powered remediation steps using WatsonX
- ✅ Store remediation plans in database (JSONB column)
- ✅ Return cached remediation plans if already generated
- ✅ Support for multiple CVEs per advisory
- ✅ OS-specific commands (dnf, apt, yum, etc.)
- ✅ Automation flags for scriptable steps

## Prerequisites

1. **Database Setup**: PostgreSQL database with advisory data
2. **Environment Variables**: DATABASE_URL configured in `.env`
3. **Dependencies**: Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## API Endpoints

### 1. Generate Remediation Steps

**Endpoint**: `POST /api/v1/advisory/remediation/generate`

**Description**: Generates remediation steps for a specific advisory using WatsonX AI.

**Request Body**:
```json
{
  "advisory_id": "ALAS2023-2026-1421"
}
```

**Response**:
```json
{
  "advisory_id": "ALAS2023-2026-1421",
  "vendor": "Amazon",
  "title": "Security Advisory for soci-snapshotter",
  "severity": "HIGH",
  "remediation_steps": [
    {
      "step_id": 1,
      "title": "Identify affected systems",
      "description": "Determine whether the system is impacted by CVEs referenced in ALAS2023-2026-1421.",
      "commands": [
        "dnf updateinfo info --cve CVE-2025-61726",
        "dnf updateinfo list cves | grep CVE-2025-61726"
      ],
      "expected_output": "Lists affected packages and advisory IDs (ALAS2023-2026-1421).",
      "automation_possible": true
    },
    {
      "step_id": 2,
      "title": "Locate vulnerable package",
      "description": "Verify whether soci-snapshotter is installed and determine its version.",
      "commands": [
        "rpm -qa | grep -i soci-snapshotter",
        "dnf list installed | grep -i soci-snapshotter"
      ],
      "expected_output": "Shows installed package version of soci-snapshotter.",
      "automation_possible": true
    },
    {
      "step_id": 3,
      "title": "Retrieve Amazon Linux advisory details",
      "description": "Fetch advisory information including fixed version and severity.",
      "commands": [
        "dnf updateinfo info ALAS2023-2026-1421"
      ],
      "expected_output": "Displays severity, affected package versions, and fixed release version.",
      "automation_possible": true
    },
    {
      "step_id": 4,
      "title": "Apply security update",
      "description": "Update soci-snapshotter to the patched release.",
      "commands": [
        "dnf update soci-snapshotter --releasever 2023.10.20260202",
        "dnf update --advisory ALAS2023-2026-1421"
      ],
      "expected_output": "Package updated to fixed version.",
      "automation_possible": true
    },
    {
      "step_id": 5,
      "title": "Verify patch installation",
      "description": "Confirm the patched version is installed.",
      "commands": [
        "rpm -q soci-snapshotter",
        "dnf updateinfo info --cve CVE-2025-61726"
      ],
      "expected_output": "System shows vulnerability as resolved.",
      "automation_possible": true
    },
    {
      "step_id": 6,
      "title": "Restart affected services",
      "description": "Restart container services using soci-snapshotter if required.",
      "commands": [
        "systemctl restart containerd",
        "systemctl restart soci-snapshotter"
      ],
      "expected_output": "Services restart successfully without errors.",
      "automation_possible": true
    },
    {
      "step_id": 7,
      "title": "Reboot system if required",
      "description": "Reboot if core Go runtime or system libraries were updated.",
      "commands": [
        "needs-restarting -r",
        "reboot"
      ],
      "expected_output": "System reboots with updated components.",
      "automation_possible": true
    },
    {
      "step_id": 8,
      "title": "Apply temporary mitigations (if patch unavailable)",
      "description": "Restrict access to exposed container services until patch is applied.",
      "commands": [
        "firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"<trusted-ip>\" accept'",
        "firewall-cmd --reload"
      ],
      "expected_output": "Network access restricted.",
      "automation_possible": false
    },
    {
      "step_id": 9,
      "title": "Validate remediation",
      "description": "Re-scan the host to ensure CVEs are resolved.",
      "commands": [
        "dnf updateinfo list cves | grep CVE-2025-61726"
      ],
      "expected_output": "CVE no longer listed as applicable.",
      "automation_possible": true
    }
  ],
  "generated_at": "2026-02-18T09:00:00.000000",
  "saved_to_database": true
}
```

### 2. Get Advisory Details

**Endpoint**: `GET /api/v1/advisory/{advisory_id}`

**Description**: Retrieves advisory details including remediation plan if available.

**Example**:
```bash
curl -X GET "http://localhost:8000/api/v1/advisory/ALAS2023-2026-1421"
```

**Response**:
```json
{
  "id": "uuid-here",
  "advisory_id": "ALAS2023-2026-1421",
  "vendor": "Amazon",
  "title": "Security Advisory for soci-snapshotter",
  "severity": "HIGH",
  "advisory_url": "https://alas.aws.amazon.com/AL2023/ALAS-2023-1421.html",
  "advisory_type": "Security",
  "advisory_status": "final",
  "published_date": "2026-02-02T00:00:00+00:00",
  "metadata": {
    "packages": ["soci-snapshotter"],
    "release_version": "2023.10.20260202"
  },
  "remediation_plan": [...],
  "cves": [
    {
      "cve_id": "CVE-2025-61726",
      "title": "Vulnerability in soci-snapshotter",
      "description": "...",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
      "is_exploitable": false,
      "is_patch_available": true,
      "published_date": "2026-01-15T00:00:00+00:00"
    }
  ]
}
```

## Usage Examples

### Using cURL

```bash
# Generate remediation steps
curl -X POST "http://localhost:8000/api/v1/advisory/remediation/generate" \
  -H "Content-Type: application/json" \
  -d '{"advisory_id": "ALAS2023-2026-1421"}'

# Get advisory details
curl -X GET "http://localhost:8000/api/v1/advisory/ALAS2023-2026-1421"
```

### Using Python

```python
import requests

# Generate remediation steps
response = requests.post(
    "http://localhost:8000/api/v1/advisory/remediation/generate",
    json={"advisory_id": "ALAS2023-2026-1421"}
)

remediation = response.json()
print(f"Generated {len(remediation['remediation_steps'])} steps")

# Print each step
for step in remediation['remediation_steps']:
    print(f"\nStep {step['step_id']}: {step['title']}")
    print(f"Description: {step['description']}")
    print(f"Commands: {', '.join(step['commands'])}")
    print(f"Automation possible: {step['automation_possible']}")
```

### Using JavaScript/Node.js

```javascript
const axios = require('axios');

async function generateRemediation(advisoryId) {
  try {
    const response = await axios.post(
      'http://localhost:8000/api/v1/advisory/remediation/generate',
      { advisory_id: advisoryId }
    );
    
    console.log(`Generated ${response.data.remediation_steps.length} steps`);
    
    response.data.remediation_steps.forEach(step => {
      console.log(`\nStep ${step.step_id}: ${step.title}`);
      console.log(`Commands: ${step.commands.join(', ')}`);
    });
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

generateRemediation('ALAS2023-2026-1421');
```

## Database Schema

### Advisories Table

```sql
CREATE TABLE concert_advisory.advisories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id TEXT UNIQUE NOT NULL,
    vendor TEXT,
    title TEXT,
    aggregate_severity TEXT,
    advisory_url TEXT,
    csaf_version TEXT,
    advisory_type TEXT,
    advisory_status TEXT,
    tlp_label TEXT,
    supersedes TEXT,
    published_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    metadata JSONB,
    remediation_plan JSONB  -- Stores generated remediation steps
);
```

### Remediation Plan Structure

The `remediation_plan` column stores a JSON array of remediation steps:

```json
[
  {
    "step_id": 1,
    "title": "Step title",
    "description": "Detailed description",
    "commands": ["command1", "command2"],
    "expected_output": "What to expect",
    "automation_possible": true
  }
]
```

## Error Handling

### Common Errors

1. **Advisory Not Found (404)**
   ```json
   {
     "detail": "Advisory ALAS2023-2026-1421 not found in database"
   }
   ```

2. **AI Response Parsing Error (500)**
   ```json
   {
     "detail": "Failed to parse AI response: Expecting value: line 1 column 1 (char 0)"
   }
   ```

3. **Database Connection Error (500)**
   ```json
   {
     "detail": "Internal server error: could not connect to server"
   }
   ```

## Configuration

### Environment Variables

Add to `.env` file:

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@host:port/database

# WatsonX AI Configuration
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_API_KEY=your-api-key
WATSONX_API_PROJECT_ID=your-project-id
WATSONX_MAX_NEW_TOKENS=2000
```

## Testing

### Start the Application

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
./start.sh

# Or manually
uvicorn app.main:app --reload --port 8000
```

### Test the API

```bash
# Check API documentation
open http://localhost:8000/docs

# Test health endpoint
curl http://localhost:8000/health

# Test remediation generation
curl -X POST "http://localhost:8000/api/v1/advisory/remediation/generate" \
  -H "Content-Type: application/json" \
  -d '{"advisory_id": "ALAS2023-2026-1421"}'
```

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ POST /api/v1/advisory/remediation/generate
       │
       ▼
┌─────────────────────────────────────────┐
│         FastAPI Application             │
│  ┌───────────────────────────────────┐  │
│  │   advisory_routes.py              │  │
│  │   - generate_advisory_remediation │  │
│  │   - get_advisory                  │  │
│  └───────────┬───────────────────────┘  │
│              │                           │
│              ▼                           │
│  ┌───────────────────────────────────┐  │
│  │   db/operations.py                │  │
│  │   - get_advisory_by_id            │  │
│  │   - update_advisory_remediation   │  │
│  └───────────┬───────────────────────┘  │
│              │                           │
└──────────────┼───────────────────────────┘
               │
               ▼
    ┌──────────────────────┐
    │  PostgreSQL Database │
    │  - advisories table  │
    │  - vulnerabilities   │
    │  - cves_advisories   │
    └──────────────────────┘
               │
               ▼
    ┌──────────────────────┐
    │   WatsonX AI         │
    │   - Generate steps   │
    │   - Parse response   │
    └──────────────────────┘
```

## Best Practices

1. **Caching**: The API automatically caches remediation plans in the database. Subsequent requests return cached data.

2. **Error Handling**: Always check the `saved_to_database` field to ensure data persistence.

3. **Automation**: Use the `automation_possible` flag to determine which steps can be scripted.

4. **Validation**: Validate commands before execution in production environments.

5. **Monitoring**: Log all remediation generation requests for audit purposes.

## Troubleshooting

### Issue: Database connection fails

**Solution**: Check DATABASE_URL in `.env` and ensure PostgreSQL is running.

### Issue: WatsonX AI returns invalid JSON

**Solution**: The API automatically cleans markdown code blocks. Check logs for raw AI response.

### Issue: Advisory not found

**Solution**: Verify the advisory exists in the database:
```sql
SELECT advisory_id, title FROM concert_advisory.advisories;
```

## Support

For issues or questions:
- Check API documentation: http://localhost:8000/docs
- Review logs in the application console
- Verify database connectivity and data

## License

This API is part of the Concert GenAI POC project.