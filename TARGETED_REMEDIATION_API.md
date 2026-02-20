# Targeted Remediation API Documentation

## Overview
The Targeted Remediation API generates product-specific remediation steps for advisories that affect multiple products or CVEs. Unlike the generic remediation API, this endpoint creates tailored remediation plans for a specific product/package/CVE combination.

## Endpoint
**POST** `/api/v1/advisory/remediation/generate-targeted`

## Use Case
When a security advisory affects multiple products or CVEs, the generic remediation API (`/api/v1/advisory/remediation/generate`) provides general steps. The targeted API allows you to generate remediation steps specific to:
- A particular product (e.g., "Red Hat Enterprise Linux 8" vs "Red Hat Enterprise Linux 9")
- A specific package (e.g., "kernel" vs "openssl")
- An individual CVE within a multi-CVE advisory

## Request Format

### Request Body
```json
{
  "advisory_id": "RHSA-2024:7197",
  "product": "Red Hat Enterprise Linux 8",
  "package": "kernel",
  "cve": "CVE-2024-12345"
}
```

### Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `advisory_id` | string | Yes | The advisory identifier (e.g., RHSA-2024:7197) |
| `product` | string | Yes | Specific product name for targeted remediation |
| `package` | string | Yes | Specific package name for targeted remediation |
| `cve` | string | Yes | Specific CVE identifier for targeted remediation |

## Response Format

### Success Response (200 OK)
```json
{
  "advisory_id": "RHSA-2024:7197",
  "vendor": "Red Hat",
  "title": "Important: kernel security update",
  "severity": "IMPORTANT",
  "product": "Red Hat Enterprise Linux 8",
  "package": "kernel",
  "cve": "CVE-2024-12345",
  "remediation_steps": [
    {
      "step_id": 1,
      "title": "Identify Affected Systems",
      "description": "Check if Red Hat Enterprise Linux 8 systems have the vulnerable kernel package installed.",
      "commands": [
        "rpm -q kernel",
        "uname -r",
        "dnf info kernel"
      ],
      "expected_output": "kernel-4.18.0-553.el8_10.x86_64",
      "automation_possible": true
    },
    {
      "step_id": 2,
      "title": "Review CVE-2024-12345 Details",
      "description": "Understand the specific vulnerability affecting the kernel package.",
      "commands": [
        "curl -s https://access.redhat.com/security/cve/CVE-2024-12345"
      ],
      "expected_output": "CVE details and severity information",
      "automation_possible": true
    }
    // ... more steps
  ],
  "generated_at": "2026-02-19T11:30:00.000000",
  "saved_to_database": true
}
```

### Error Responses

#### 404 Not Found
Advisory not found in database:
```json
{
  "detail": "Advisory RHSA-2024:7197 not found in database. Please run the assess API first to populate the database."
}
```

#### 503 Service Unavailable
Database connection error:
```json
{
  "detail": "Database connection error: connection timeout. Please try again later."
}
```

#### 500 Internal Server Error
Processing error:
```json
{
  "detail": "Internal server error: AI service unavailable"
}
```

## Example Usage

### cURL
```bash
curl -X POST "http://localhost:8000/api/v1/advisory/remediation/generate-targeted" \
  -H "Content-Type: application/json" \
  -d '{
    "advisory_id": "RHSA-2024:7197",
    "product": "Red Hat Enterprise Linux 8",
    "package": "kernel",
    "cve": "CVE-2024-12345"
  }'
```

### Python
```python
import requests

url = "http://localhost:8000/api/v1/advisory/remediation/generate-targeted"
payload = {
    "advisory_id": "RHSA-2024:7197",
    "product": "Red Hat Enterprise Linux 8",
    "package": "kernel",
    "cve": "CVE-2024-12345"
}

response = requests.post(url, json=payload)
remediation = response.json()

print(f"Advisory: {remediation['advisory_id']}")
print(f"Product: {remediation['product']}")
print(f"Package: {remediation['package']}")
print(f"CVE: {remediation['cve']}")
print(f"\nRemediation Steps: {len(remediation['remediation_steps'])}")

for step in remediation['remediation_steps']:
    print(f"\nStep {step['step_id']}: {step['title']}")
    print(f"  Description: {step['description']}")
    print(f"  Commands: {', '.join(step['commands'][:2])}")
```

### JavaScript/Node.js
```javascript
const axios = require('axios');

const url = 'http://localhost:8000/api/v1/advisory/remediation/generate-targeted';
const payload = {
  advisory_id: 'RHSA-2024:7197',
  product: 'Red Hat Enterprise Linux 8',
  package: 'kernel',
  cve: 'CVE-2024-12345'
};

axios.post(url, payload)
  .then(response => {
    const remediation = response.data;
    console.log(`Advisory: ${remediation.advisory_id}`);
    console.log(`Product: ${remediation.product}`);
    console.log(`Package: ${remediation.package}`);
    console.log(`CVE: ${remediation.cve}`);
    console.log(`\nRemediation Steps: ${remediation.remediation_steps.length}`);
    
    remediation.remediation_steps.forEach(step => {
      console.log(`\nStep ${step.step_id}: ${step.title}`);
      console.log(`  Description: ${step.description}`);
    });
  })
  .catch(error => {
    console.error('Error:', error.response?.data || error.message);
  });
```

## Comparison with Generic Remediation API

### Generic API (`/api/v1/advisory/remediation/generate`)
- **Input**: Only `advisory_id`
- **Output**: General remediation steps for the entire advisory
- **Use Case**: When you need overall remediation guidance for an advisory
- **Example**: "Update all affected packages to the latest versions"

### Targeted API (`/api/v1/advisory/remediation/generate-targeted`)
- **Input**: `advisory_id`, `product`, `package`, `cve`
- **Output**: Product/package/CVE-specific remediation steps
- **Use Case**: When you need precise remediation for a specific combination
- **Example**: "Update kernel package to version 4.18.0-553.16.1.el8_10 on RHEL 8 systems to address CVE-2024-12345"

## Workflow

1. **Fetch Advisory Data**: API retrieves advisory information from database
2. **Extract CVE Details**: Locates specific CVE information within the advisory
3. **Build Targeted Context**: Creates context with product, package, and CVE specifics
4. **Generate Steps**: Uses IBM WatsonX AI to generate targeted remediation steps
5. **Parse Response**: Validates and structures the AI-generated steps
6. **Save to Database**: Optionally saves the targeted remediation plan
7. **Return Response**: Provides detailed, product-specific remediation steps

## AI Model
- **Model**: IBM Granite-3-8b-instruct
- **Max Tokens**: 4000
- **Temperature**: 0.3 (for consistent, focused responses)

## Features
- ✅ Product-specific command generation
- ✅ Package-specific version checking
- ✅ CVE-focused vulnerability assessment
- ✅ Automated step validation
- ✅ Database persistence
- ✅ JSON truncation handling
- ✅ Comprehensive error handling

## Prerequisites
1. Advisory must exist in database (run `/api/v1/intelligence/assess` first)
2. IBM WatsonX AI credentials configured
3. Database connection established

## Rate Limiting
- AI generation takes ~10-15 seconds per request
- Recommended: Cache results for repeated queries
- Database saves remediation plans for reuse

## Best Practices
1. **Use Targeted API When**:
   - Advisory affects multiple products
   - Need product-specific commands
   - Require CVE-specific remediation
   - Customer environment is homogeneous

2. **Use Generic API When**:
   - Need overview of advisory remediation
   - Advisory affects single product
   - Require general guidance

3. **Optimization**:
   - Check database for existing remediation plans
   - Cache frequently requested combinations
   - Batch similar requests

## Troubleshooting

### Advisory Not Found
**Problem**: `404 - Advisory not found in database`  
**Solution**: Run the assess API first:
```bash
curl -X POST "http://localhost:8000/api/v1/intelligence/assess" \
  -H "Content-Type: application/json" \
  -d '{"advisory_id": "RHSA-2024:7197"}'
```

### CVE Not in Advisory
**Problem**: Specified CVE not found in advisory  
**Solution**: API will use generic CVE information and still generate steps

### Slow Response
**Problem**: Request takes >15 seconds  
**Solution**: Normal for AI generation; consider implementing async processing for production

## Support
For issues or questions:
- Check API logs: `tail -f Advisory_Intelligence/app.log`
- Review database: Check `advisories` and `vulnerabilities` tables
- Test connectivity: `curl http://localhost:8000/health`