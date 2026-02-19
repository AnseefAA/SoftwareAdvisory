# Database Population Functionality

## Overview

The Advisory Intelligence system now includes comprehensive database population functionality that automatically saves intelligence data to PostgreSQL database tables when the `/api/v1/intelligence/assess` API is called.

## Architecture

### Data Flow

```
1. User calls /api/v1/intelligence/assess with CVE ID
2. System fetches intelligence from 5 sources (NVD, MITRE, GitHub, OSV, AWS ALAS)
3. Raw intelligence is cached in intelligence_cache table
4. Structured data is extracted
5. Database population function is triggered
6. Data is saved to multiple related tables:
   - vulnerabilities
   - advisories
   - packages
   - cves_advisories (relationships)
   - cves_packages (relationships)
```

## Database Tables Populated

### 1. vulnerabilities Table
Stores CVE vulnerability information:
- **cve_id**: CVE identifier (e.g., CVE-2024-21626)
- **title**: Short title/summary
- **description**: Full vulnerability description
- **latest_severity**: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
- **latest_cvss_score**: CVSS base score (0.0-10.0)
- **latest_vector_string**: CVSS vector string
- **cvss_metrics**: Complete CVSS metrics (JSON)
- **is_exploitable**: Whether exploits exist
- **is_patch_available**: Whether patches are available
- **cwe_references**: CWE weakness references (JSON array)
- **cpe_references**: CPE product references (JSON array)
- **reference_links**: External reference links (JSON array)
- **raw**: Raw NVD data (JSON)
- **published_date**: CVE publication date
- **last_modified_date**: Last modification date

**Data Source**: Primarily NVD (National Vulnerability Database)

### 2. advisories Table
Stores vendor security advisories:
- **id**: UUID primary key
- **advisory_id**: Advisory identifier (e.g., ALAS-2024-1234)
- **vendor**: Vendor name (e.g., AWS, Red Hat)
- **title**: Advisory title
- **aggregate_severity**: Overall severity
- **advisory_url**: Link to advisory
- **advisory_type**: Type (security, bugfix, enhancement)
- **advisory_status**: Status (published, draft, withdrawn)
- **published_date**: Publication date
- **advisory_metadata**: Additional metadata (JSON)

**Data Source**: AWS ALAS (Amazon Linux Security Advisories)

### 3. packages Table
Stores affected software packages:
- **id**: UUID primary key
- **name**: Package name (e.g., runc, openssl)
- **version**: Package version
- **ecosystem**: Package ecosystem (e.g., PyPI, npm, Go)
- **description**: Package description

**Data Source**: OSV.dev (Open Source Vulnerabilities)

### 4. cves_advisories Table (Junction)
Links CVEs to advisories:
- **cve_id**: CVE identifier (foreign key)
- **advisory_id**: Advisory UUID (foreign key)

### 5. cves_packages Table (Junction)
Links CVEs to affected packages:
- **cve_id**: CVE identifier (foreign key)
- **package_id**: Package UUID (foreign key)

## Implementation Details

### Core Functions

#### 1. `save_vulnerability_to_db(cve_data, raw_intel)`
Saves or updates vulnerability data in the vulnerabilities table.

**Features**:
- Extracts CVSS metrics from NVD data
- Parses CWE weakness references
- Extracts CPE product configurations
- Collects reference links
- Updates existing records or creates new ones

**Example Data Extracted**:
```python
{
    "cve_id": "CVE-2024-21626",
    "description": "runc process.cwd and leaked fds container breakout",
    "latest_severity": "HIGH",
    "latest_cvss_score": 8.6,
    "cvss_metrics": {...},
    "cwe_references": ["CWE-22", "CWE-269"],
    "cpe_references": ["cpe:2.3:a:linuxfoundation:runc:*:*:*:*:*:*:*:*"]
}
```

#### 2. `save_advisory_to_db(advisory_data, cve_id)`
Saves or updates advisory data in the advisories table.

**Features**:
- Extracts advisory metadata from AWS ALAS
- Creates advisory records with proper vendor attribution
- Returns advisory UUID for relationship creation

**Example Data Extracted**:
```python
{
    "advisory_id": "ALAS-2024-1234",
    "vendor": "AWS",
    "title": "Important: runc security update",
    "aggregate_severity": "IMPORTANT",
    "advisory_url": "https://alas.aws.amazon.com/AL2/ALAS-2024-1234.html"
}
```

#### 3. `save_package_to_db(package_data)`
Saves or updates package data in the packages table.

**Features**:
- Extracts package information from OSV data
- Handles version ranges
- Supports multiple ecosystems (PyPI, npm, Go, etc.)

**Example Data Extracted**:
```python
{
    "name": "runc",
    "version": "1.1.0",
    "ecosystem": "Go",
    "description": "CLI tool for spawning and running containers"
}
```

#### 4. `link_cve_to_advisory(cve_id, advisory_uuid)`
Creates relationships between CVEs and advisories.

**Features**:
- Prevents duplicate relationships
- Uses raw SQL for junction table operations

#### 5. `link_cve_to_package(cve_id, package_uuid)`
Creates relationships between CVEs and packages.

**Features**:
- Prevents duplicate relationships
- Links vulnerabilities to affected packages

#### 6. `populate_database_from_intelligence(cve_id, raw_intel)`
Main orchestration function that coordinates all database operations.

**Process**:
1. Extract CVE data from NVD source
2. Save vulnerability record
3. Process AWS ALAS advisories
4. Save advisory records
5. Create CVE-Advisory relationships
6. Process OSV package data
7. Save package records
8. Create CVE-Package relationships
9. Return comprehensive results

**Returns**:
```python
{
    "cve_id": "CVE-2024-21626",
    "vulnerability_saved": True,
    "advisories_saved": ["ALAS-2024-1234", "ALAS2-2024-5678"],
    "packages_saved": ["runc@1.1.0", "runc@1.1.1"],
    "relationships_created": {
        "cve_advisory": ["ALAS-2024-1234", "ALAS2-2024-5678"],
        "cve_package": ["runc@1.1.0", "runc@1.1.1"]
    },
    "errors": []
}
```

## API Integration

### /api/v1/intelligence/assess

The assess API now includes automatic database population:

```python
@router.post("/intelligence/assess")
async def assess_intelligence(payload: Models.MitigationRequest):
    # Step 1: Load or fetch intelligence
    # Step 2: Extract structured data
    # Step 3: Update cache
    # Step 4: Populate database tables ← NEW!
    population_results = await populate_database_from_intelligence(
        payload.cveId, 
        aggregated_intel
    )
    # Step 5: Return structured response
```

## Usage Example

### Request
```bash
curl -X POST "http://localhost:8000/api/v1/intelligence/assess" \
  -H "Content-Type: application/json" \
  -d '{"cveId": "CVE-2024-21626"}'
```

### What Happens
1. Intelligence is fetched from 5 sources
2. Data is cached in `intelligence_cache` table
3. Structured data is extracted
4. Database population begins:
   - ✓ Vulnerability saved to `vulnerabilities` table
   - ✓ 2 advisories saved to `advisories` table
   - ✓ 3 packages saved to `packages` table
   - ✓ 2 CVE-Advisory relationships created
   - ✓ 3 CVE-Package relationships created
5. Structured response returned to client

### Database State After
```sql
-- vulnerabilities table
SELECT cve_id, latest_severity, latest_cvss_score 
FROM concert_advisory.vulnerabilities 
WHERE cve_id = 'CVE-2024-21626';
-- Result: CVE-2024-21626 | HIGH | 8.6

-- advisories table
SELECT advisory_id, vendor, aggregate_severity 
FROM concert_advisory.advisories 
WHERE advisory_id LIKE 'ALAS%';
-- Result: ALAS-2024-1234 | AWS | IMPORTANT

-- cves_advisories relationships
SELECT * FROM concert_advisory.cves_advisories 
WHERE cve_id = 'CVE-2024-21626';
-- Result: Links to 2 advisories

-- packages table
SELECT name, version, ecosystem 
FROM concert_advisory.packages 
WHERE name = 'runc';
-- Result: runc | 1.1.0 | Go

-- cves_packages relationships
SELECT * FROM concert_advisory.cves_packages 
WHERE cve_id = 'CVE-2024-21626';
-- Result: Links to 3 package versions
```

## Error Handling

The system includes comprehensive error handling:

1. **Transaction Safety**: Each save operation is wrapped in try-catch with rollback
2. **Duplicate Prevention**: Checks for existing records before insertion
3. **Partial Success**: Continues processing even if some operations fail
4. **Error Reporting**: All errors are logged and included in results
5. **Graceful Degradation**: Returns partial results if some data sources fail

## Logging

Detailed logging at each step:

```
INFO: Saving vulnerability data for CVE-2024-21626
INFO: ✓ Vulnerability saved: CVE-2024-21626
INFO: Processing 2 AWS ALAS advisories
INFO: ✓ Advisory saved: ALAS-2024-1234
INFO: ✓ Linked CVE to advisory: CVE-2024-21626 <-> ALAS-2024-1234
INFO: Processing OSV package data
INFO: ✓ Package saved: runc@1.1.0
INFO: ✓ Linked CVE to package: CVE-2024-21626 <-> runc@1.1.0
INFO: Database population complete for CVE-2024-21626:
  - Vulnerability: ✓
  - Advisories: 2
  - Packages: 3
  - CVE-Advisory links: 2
  - CVE-Package links: 3
  - Errors: 0
```

## Data Sources

### 1. NVD (National Vulnerability Database)
- **URL**: https://services.nvd.nist.gov/rest/json/cves/2.0
- **Provides**: CVE descriptions, CVSS scores, CWE/CPE references, metrics
- **Used For**: vulnerabilities table

### 2. AWS ALAS (Amazon Linux Security Advisories)
- **URLs**: 
  - https://alas.aws.amazon.com/AL2/alas.html
  - https://alas.aws.amazon.com/AL2023/alas.html
  - https://alas.aws.amazon.com/alas.html
- **Provides**: Security advisories, severity ratings, patch information
- **Used For**: advisories table

### 3. OSV.dev (Open Source Vulnerabilities)
- **URL**: https://api.osv.dev/v1/vulns/{cve_id}
- **Provides**: Package information, affected versions, ecosystems
- **Used For**: packages table

### 4. MITRE CVE
- **URL**: https://cveawg.mitre.org/api/cve/{cve_id}
- **Provides**: Additional CVE metadata
- **Used For**: Supplementary vulnerability data

### 5. GitHub CVE Project
- **URL**: https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{id}.json
- **Provides**: Community-maintained CVE data
- **Used For**: Supplementary vulnerability data

## Performance Considerations

1. **Async Operations**: All database operations are async for better performance
2. **Batch Processing**: Multiple sources fetched in parallel using asyncio.gather
3. **Smart Merging**: Existing records are updated rather than duplicated
4. **Connection Pooling**: SQLAlchemy connection pool for efficient DB access
5. **Selective Updates**: Only modified fields are updated

## Future Enhancements

Potential improvements:
- [ ] Add product table population from CPE data
- [ ] Extract patch information from advisories
- [ ] Add lifecycle data extraction
- [ ] Implement compatibility matrix population
- [ ] Add support for more advisory sources (Red Hat, Ubuntu, Debian)
- [ ] Implement bulk CVE processing
- [ ] Add data validation and quality checks
- [ ] Implement incremental updates for existing records

## Troubleshooting

### Common Issues

**Issue**: "Failed to save vulnerability"
- **Cause**: Database connection issue or invalid data
- **Solution**: Check database connectivity and data format

**Issue**: "No advisories found"
- **Cause**: CVE not present in AWS ALAS bulletins
- **Solution**: Normal behavior, not all CVEs have AWS advisories

**Issue**: "Duplicate key violation"
- **Cause**: Race condition in concurrent requests
- **Solution**: System handles this gracefully with update logic

## Testing

To test the database population:

```bash
# 1. Start the server
cd Advisory_Intelligence
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 2. Call the assess API
curl -X POST "http://localhost:8000/api/v1/intelligence/assess" \
  -H "Content-Type: application/json" \
  -d '{"cveId": "CVE-2024-21626"}'

# 3. Verify database records
psql -h theme-advisory1.fyre.ibm.com -U 12b12b08b15b95822f82407b -d advisory_db

# Check vulnerabilities
SELECT * FROM concert_advisory.vulnerabilities WHERE cve_id = 'CVE-2024-21626';

# Check advisories
SELECT * FROM concert_advisory.advisories WHERE advisory_id LIKE 'ALAS%';

# Check relationships
SELECT * FROM concert_advisory.cves_advisories WHERE cve_id = 'CVE-2024-21626';
```

## Conclusion

The database population functionality provides a complete, automated solution for storing intelligence data in a structured, queryable format. It handles data from multiple sources, creates proper relationships, and includes comprehensive error handling and logging.