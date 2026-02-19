"""
Database operations for advisory remediation
"""
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker, Session
from typing import Optional, Dict, Any, List
import os
import logging
import json
from app.db.models import Advisory, Vulnerability, CVEAdvisory, Product, Package, IntelligenceCache
from datetime import datetime

logger = logging.getLogger(__name__)

# Build database URL from individual environment variables
def get_database_url() -> str:
    """
    Construct database URL from environment variables
    
    Environment Variables:
        DB_TYPE: Database type (sqlite or postgresql)
        DB_HOST: Database host (for postgresql)
        DB_PORT: Database port (for postgresql)
        DB_NAME: Database name or file path (for sqlite)
        DB_USERNAME: Database username (for postgresql)
        DB_PASSWORD: Database password (for postgresql)
    
    Returns:
        str: Database URL
    """
    db_type = os.getenv("DB_TYPE", "sqlite")
    
    if db_type == "sqlite":
        db_name = os.getenv("DB_NAME", "./advisory_intelligence.db")
        return f"sqlite:///{db_name}"
    elif db_type == "postgresql":
        db_host = os.getenv("DB_HOST", "localhost")
        db_port = os.getenv("DB_PORT", "5432")
        db_name = os.getenv("DB_NAME", "advisory_intelligence")
        db_username = os.getenv("DB_USERNAME", "postgres")
        db_password = os.getenv("DB_PASSWORD", "")
        
        return f"postgresql://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}"
    else:
        logger.warning(f"Unknown DB_TYPE: {db_type}, defaulting to SQLite")
        return "sqlite:///./advisory_intelligence.db"

# Get database URL
DATABASE_URL = get_database_url()
logger.info(f"Using database: {DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL}")

# Database schema
DB_SCHEMA = os.getenv("DB_SCHEMA", "concert_advisory")

# Connection pool settings
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))
DB_CONNECT_TIMEOUT = int(os.getenv("DB_CONNECT_TIMEOUT", "10"))

# Create engine with schema search path and connection pooling for PostgreSQL
if "postgresql" in DATABASE_URL:
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        pool_size=DB_POOL_SIZE,
        max_overflow=DB_MAX_OVERFLOW,
        pool_timeout=DB_POOL_TIMEOUT,
        pool_recycle=DB_POOL_RECYCLE,
        pool_pre_ping=True,  # Verify connections before using them
        connect_args={
            "options": f"-csearch_path={DB_SCHEMA}",
            "client_encoding": "utf8",
            "connect_timeout": DB_CONNECT_TIMEOUT
        }
    )
    logger.info(f"Using PostgreSQL schema: {DB_SCHEMA}")
    logger.info(f"Client encoding set to UTF8 for SQL_ASCII database compatibility")
    logger.info(f"Connection pool: size={DB_POOL_SIZE}, max_overflow={DB_MAX_OVERFLOW}, timeout={DB_POOL_TIMEOUT}s")
else:
    engine = create_engine(DATABASE_URL, echo=False)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db_session() -> Session:
    """Get database session"""
    return SessionLocal()

async def get_advisory_by_id(advisory_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch advisory details from database by advisory_id
    
    Args:
        advisory_id: Advisory ID (e.g., ALAS2023-2026-1421)
    
    Returns:
        Dictionary containing advisory details or None if not found
    
    Raises:
        Exception: Re-raises database connection errors for better error handling
    """
    session = None
    try:
        session = get_db_session()
        
        # Query advisory
        stmt = select(Advisory).where(Advisory.advisory_id == advisory_id)
        result = session.execute(stmt)
        advisory = result.scalar_one_or_none()
        
        if not advisory:
            logger.warning(f"Advisory {advisory_id} not found in database")
            session.close()
            return None
        
        # Get associated CVEs
        cve_stmt = select(CVEAdvisory.cve_id).where(CVEAdvisory.advisory_id == advisory.id)
        cve_result = session.execute(cve_stmt)
        cve_ids = [row[0] for row in cve_result.fetchall()]
        
        # Get CVE details
        cves = []
        if cve_ids:
            vuln_stmt = select(Vulnerability).where(Vulnerability.cve_id.in_(cve_ids))
            vuln_result = session.execute(vuln_stmt)
            vulnerabilities = vuln_result.scalars().all()
            
            for vuln in vulnerabilities:
                cves.append({
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "description": vuln.description,
                    "severity": vuln.latest_severity,
                    "cvss_score": vuln.latest_cvss_score,
                    "cvss_vector": vuln.latest_vector_string,
                    "is_exploitable": vuln.is_exploitable,
                    "is_patch_available": vuln.is_patch_available,
                    "published_date": vuln.published_date.isoformat() if vuln.published_date else None
                })
        
        # Build response
        advisory_data = {
            "id": str(advisory.id),
            "advisory_id": advisory.advisory_id,
            "vendor": advisory.vendor,
            "title": advisory.title,
            "severity": advisory.aggregate_severity,
            "advisory_url": advisory.advisory_url,
            "advisory_type": advisory.advisory_type,
            "advisory_status": advisory.advisory_status,
            "published_date": advisory.published_date.isoformat() if advisory.published_date else None,
            "metadata": advisory.advisory_metadata,
            "remediation_plan": advisory.remediation_plan,
            "cves": cves
        }
        
        session.close()
        return advisory_data
        
    except Exception as e:
        logger.error(f"Database error fetching advisory {advisory_id}: {type(e).__name__}: {str(e)}")
        if session:
            session.close()
        # Re-raise the exception so the caller can handle it appropriately
        raise

async def update_advisory_remediation(advisory_id: str, remediation_plan: List[Dict[str, Any]]) -> bool:
    """
    Update advisory with generated remediation plan
    
    Args:
        advisory_id: Advisory ID
        remediation_plan: List of remediation steps
    
    Returns:
        True if successful, False otherwise
    """
    try:
        session = get_db_session()
        
        # Update advisory
        stmt = (
            update(Advisory)
            .where(Advisory.advisory_id == advisory_id)
            .values(remediation_plan=remediation_plan)
        )
        
        result = session.execute(stmt)
        session.commit()
        
        if result.rowcount > 0:
            logger.info(f"Updated remediation plan for advisory {advisory_id}")
            session.close()
            return True
        else:
            logger.warning(f"No advisory found with ID {advisory_id}")
            session.close()
            return False
            
    except Exception as e:
        logger.error(f"Error updating advisory {advisory_id}: {str(e)}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return False

# Made with Bob


async def save_intelligence_cache(
    identifier: str,
    identifier_type: str,
    raw_data: Dict[str, Any],
    structured_data: Optional[Dict[str, Any]] = None,
    sources_fetched: List[str] = None,
    is_complete: bool = False,
    fetch_errors: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Save or update intelligence cache with merge logic
    
    Args:
        identifier: CVE ID or Advisory ID
        identifier_type: 'cve' or 'advisory'
        raw_data: Complete aggregated intelligence
        structured_data: Structured intelligence response
        sources_fetched: List of source names
        is_complete: Whether all sources were successfully fetched
        fetch_errors: Any errors encountered during fetch
    
    Returns:
        True if successful, False otherwise
    """
    try:
        session = get_db_session()
        
        # Check if record exists
        stmt = select(IntelligenceCache).where(
            IntelligenceCache.identifier == identifier,
            IntelligenceCache.identifier_type == identifier_type
        )
        result = session.execute(stmt)
        existing = result.scalar_one_or_none()
        
        if existing:
            # Merge logic for existing record
            logger.info(f"Updating existing intelligence cache for {identifier}")
            
            # Parse existing JSON data from TEXT columns
            existing_raw = json.loads(existing.raw_data) if existing.raw_data else {}
            existing_errors = json.loads(existing.fetch_errors) if existing.fetch_errors else {}
            
            # Deep merge raw_data
            merged_raw_data = deep_merge_dicts(existing_raw, raw_data)
            
            # Merge sources_fetched (unique values)
            existing_sources = set(existing.sources_fetched or [])
            new_sources = set(sources_fetched or [])
            merged_sources = list(existing_sources.union(new_sources))
            
            # Merge fetch_errors
            merged_errors = existing_errors.copy()
            if fetch_errors:
                merged_errors.update(fetch_errors)
            
            # Update record (serialize JSON to TEXT)
            existing.raw_data = json.dumps(merged_raw_data)
            existing.structured_data = json.dumps(structured_data) if structured_data else existing.structured_data
            existing.sources_fetched = merged_sources
            existing.last_updated_at = datetime.utcnow()
            existing.fetch_count = (existing.fetch_count or 0) + 1
            existing.is_complete = is_complete
            existing.fetch_errors = json.dumps(merged_errors) if merged_errors else None
            
            session.commit()
            logger.info(f"Updated intelligence cache for {identifier} (fetch count: {existing.fetch_count})")
            
        else:
            # Create new record
            logger.info(f"Creating new intelligence cache for {identifier}")
            
            new_cache = IntelligenceCache(
                identifier=identifier,
                identifier_type=identifier_type,
                raw_data=json.dumps(raw_data),  # Serialize to JSON string
                structured_data=json.dumps(structured_data) if structured_data else None,
                sources_fetched=sources_fetched or [],
                is_complete=is_complete,
                fetch_errors=json.dumps(fetch_errors) if fetch_errors else None
            )
            
            session.add(new_cache)
            session.commit()
            logger.info(f"Created intelligence cache for {identifier}")
        
        session.close()
        return True
        
    except Exception as e:
        logger.error(f"Error saving intelligence cache for {identifier}: {str(e)}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return False

async def get_intelligence_cache(identifier: str, identifier_type: str = "cve") -> Optional[Dict[str, Any]]:
    """
    Retrieve intelligence cache from database
    
    Args:
        identifier: CVE ID or Advisory ID
        identifier_type: 'cve' or 'advisory'
    
    Returns:
        Dictionary containing cached intelligence or None if not found
    """
    try:
        session = get_db_session()
        
        stmt = select(IntelligenceCache).where(
            IntelligenceCache.identifier == identifier,
            IntelligenceCache.identifier_type == identifier_type
        )
        result = session.execute(stmt)
        cache = result.scalar_one_or_none()
        
        if not cache:
            logger.info(f"No intelligence cache found for {identifier}")
            session.close()
            return None
        
        # Build response (deserialize JSON from TEXT columns)
        cache_data = {
            "id": str(cache.id),
            "identifier": cache.identifier,
            "identifier_type": cache.identifier_type,
            "raw_data": json.loads(cache.raw_data) if cache.raw_data else None,
            "structured_data": json.loads(cache.structured_data) if cache.structured_data else None,
            "sources_fetched": cache.sources_fetched,
            "first_fetched_at": cache.first_fetched_at.isoformat() if cache.first_fetched_at else None,
            "last_updated_at": cache.last_updated_at.isoformat() if cache.last_updated_at else None,
            "fetch_count": cache.fetch_count,
            "is_complete": cache.is_complete,
            "fetch_errors": json.loads(cache.fetch_errors) if cache.fetch_errors else None
        }
        
        session.close()
        return cache_data
        
    except Exception as e:
        logger.error(f"Error retrieving intelligence cache for {identifier}: {str(e)}")
        return None

def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries, preserving all data
    dict2 values take precedence over dict1 for conflicts
    
    Args:
        dict1: Base dictionary
        dict2: Dictionary to merge (takes precedence)
    
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursively merge nested dictionaries
            result[key] = deep_merge_dicts(result[key], value)
        elif key in result and isinstance(result[key], list) and isinstance(value, list):
            # Merge lists (append unique items)
            result[key] = result[key] + [item for item in value if item not in result[key]]
        else:
            # Override with new value
            result[key] = value
    
    return result


# ============================================================================
# DATABASE POPULATION FUNCTIONS
# ============================================================================

async def save_vulnerability_to_db(cve_data: Dict[str, Any], raw_intel: Dict[str, Any]) -> Optional[str]:
    """
    Save or update vulnerability data in the vulnerabilities table
    
    Args:
        cve_data: Processed CVE data with standard fields
        raw_intel: Raw intelligence data from all sources
    
    Returns:
        CVE ID if successful, None otherwise
    """
    try:
        session = get_db_session()
        
        cve_id = cve_data.get("cve_id")
        if not cve_id:
            logger.error("No CVE ID provided")
            return None
        
        # Check if vulnerability already exists
        stmt = select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        result = session.execute(stmt)
        existing = result.scalar_one_or_none()
        
        # Extract data from NVD source
        nvd_data = raw_intel.get("sources", {}).get("nvd", {})
        
        # Extract CVSS metrics
        cvss_metrics = {}
        if nvd_data and "metrics" in nvd_data:
            cvss_metrics = nvd_data["metrics"]
        
        # Extract CWE references
        cwe_refs = []
        if nvd_data and "weaknesses" in nvd_data:
            for weakness in nvd_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("value"):
                        cwe_refs.append(desc.get("value"))
        
        # Extract CPE references
        cpe_refs = []
        if nvd_data and "configurations" in nvd_data:
            for config in nvd_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("criteria"):
                            cpe_refs.append(cpe_match.get("criteria"))
        
        # Extract reference links
        ref_links = []
        if nvd_data and "references" in nvd_data:
            for ref in nvd_data.get("references", []):
                if ref.get("url"):
                    ref_links.append({
                        "url": ref.get("url"),
                        "source": ref.get("source"),
                        "tags": ref.get("tags", [])
                    })
        
        # Prepare vulnerability data
        vuln_data = {
            "cve_id": cve_id,
            "title": cve_data.get("description", "")[:200] if cve_data.get("description") else None,
            "description": cve_data.get("description"),
            "latest_severity": cve_data.get("severity"),
            "latest_cvss_score": cve_data.get("cvss_score"),
            "latest_vector_string": cvss_metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("vectorString") if cvss_metrics else None,
            "cvss_metrics": json.dumps(cvss_metrics) if cvss_metrics else None,
            "is_exploitable": cve_data.get("exploit_maturity") is not None,
            "is_patch_available": False,  # Will be updated when we find patches
            "cwe_references": json.dumps(cwe_refs) if cwe_refs else None,
            "cpe_references": json.dumps(cpe_refs) if cpe_refs else None,
            "reference_links": json.dumps(ref_links) if ref_links else None,
            "raw": json.dumps(nvd_data) if nvd_data else None,
            "published_date": datetime.fromisoformat(nvd_data.get("published").replace("Z", "+00:00")) if nvd_data.get("published") else None,
            "last_modified_date": datetime.fromisoformat(nvd_data.get("lastModified").replace("Z", "+00:00")) if nvd_data.get("lastModified") else None
        }
        
        if existing:
            # Update existing vulnerability
            logger.info(f"Updating existing vulnerability: {cve_id}")
            for key, value in vuln_data.items():
                if key != "cve_id" and value is not None:
                    setattr(existing, key, value)
        else:
            # Create new vulnerability
            logger.info(f"Creating new vulnerability: {cve_id}")
            new_vuln = Vulnerability(**vuln_data)
            session.add(new_vuln)
        
        session.commit()
        session.close()
        logger.info(f"Successfully saved vulnerability: {cve_id}")
        return cve_id
        
    except Exception as e:
        logger.error(f"Error saving vulnerability {cve_data.get('cve_id')}: {str(e)}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return None


async def save_advisory_to_db(advisory_data: Dict[str, Any], cve_id: str) -> Optional[str]:
    """
    Save or update advisory data in the advisories table
    
    Args:
        advisory_data: Advisory information from AWS ALAS or other sources
        cve_id: Associated CVE ID
    
    Returns:
        Advisory UUID if successful, None otherwise
    """
    try:
        session = get_db_session()
        
        advisory_id_text = advisory_data.get("advisory_id")
        if not advisory_id_text:
            logger.error("No advisory ID provided")
            return None
        
        # Check if advisory already exists
        stmt = select(Advisory).where(Advisory.advisory_id == advisory_id_text)
        result = session.execute(stmt)
        existing = result.scalar_one_or_none()
        
        # Prepare advisory data
        adv_data = {
            "advisory_id": advisory_id_text,
            "vendor": advisory_data.get("vendor", "AWS"),
            "title": advisory_data.get("description", "")[:200] if advisory_data.get("description") else advisory_id_text,
            "aggregate_severity": advisory_data.get("severity", "UNKNOWN"),
            "advisory_url": advisory_data.get("advisory_url"),
            "advisory_type": "security",
            "advisory_status": "published",
            "published_date": datetime.utcnow(),  # Use current time if not provided
            "advisory_metadata": json.dumps({
                "source_url": advisory_data.get("source_url"),
                "cve_id": cve_id,
                "description": advisory_data.get("description")
            })
        }
        
        advisory_uuid = None
        
        if existing:
            # Update existing advisory
            logger.info(f"Updating existing advisory: {advisory_id_text}")
            for key, value in adv_data.items():
                if key != "advisory_id" and value is not None:
                    setattr(existing, key, value)
            advisory_uuid = str(existing.id)
        else:
            # Create new advisory
            logger.info(f"Creating new advisory: {advisory_id_text}")
            new_advisory = Advisory(**adv_data)
            session.add(new_advisory)
            session.flush()  # Get the ID
            advisory_uuid = str(new_advisory.id)
        
        session.commit()
        session.close()
        logger.info(f"Successfully saved advisory: {advisory_id_text}")
        return advisory_uuid
        
    except Exception as e:
        logger.error(f"Error saving advisory {advisory_data.get('advisory_id')}: {str(e)}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return None


async def save_package_to_db(package_data: Dict[str, Any]) -> Optional[str]:
    """
    Save or update package data in the packages table
    
    Args:
        package_data: Package information from OSV or other sources
    
    Returns:
        Package UUID if successful, None otherwise
    """
    try:
        session = get_db_session()
        
        package_name = package_data.get("name")
        package_version = package_data.get("version")
        ecosystem = package_data.get("ecosystem")
        
        if not package_name:
            logger.error("No package name provided")
            return None
        
        # Check if package already exists
        stmt = select(Package).where(
            Package.name == package_name,
            Package.version == package_version,
            Package.ecosystem == ecosystem
        )
        result = session.execute(stmt)
        existing = result.scalar_one_or_none()
        
        package_uuid = None
        
        if existing:
            logger.info(f"Package already exists: {package_name}@{package_version}")
            package_uuid = str(existing.id)
        else:
            # Create new package
            logger.info(f"Creating new package: {package_name}@{package_version}")
            new_package = Package(
                name=package_name,
                version=package_version,
                ecosystem=ecosystem,
                description=package_data.get("description")
            )
            session.add(new_package)
            session.flush()
            package_uuid = str(new_package.id)
        
        session.commit()
        session.close()
        return package_uuid
        
    except Exception as e:
        logger.error(f"Error saving package {package_data.get('name')}: {str(e)}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return None


async def link_cve_to_advisory(cve_id: str, advisory_uuid: str) -> bool:
    """
    Create relationship between CVE and Advisory in cves_advisories table
    
    Args:
        cve_id: CVE ID (text)
        advisory_uuid: Advisory UUID
    
    Returns:
        True if successful, False otherwise
    """
    try:
        session = get_db_session()
        
        # Check if relationship already exists
        from sqlalchemy import text
        check_stmt = text("""
            SELECT 1 FROM concert_advisory.cves_advisories 
            WHERE cve_id = :cve_id AND advisory_id = :advisory_id
        """)
        result = session.execute(check_stmt, {"cve_id": cve_id, "advisory_id": advisory_uuid})
        
        if result.fetchone():
            logger.info(f"Relationship already exists: {cve_id} <-> {advisory_uuid}")
            session.close()
            return True
        
        # Create relationship
        insert_stmt = text("""
            INSERT INTO concert_advisory.cves_advisories (cve_id, advisory_id)
            VALUES (:cve_id, :advisory_id)
        """)
        session.execute(insert_stmt, {"cve_id": cve_id, "advisory_id": advisory_uuid})
        session.commit()
        session.close()
        
        logger.info(f"Linked CVE to advisory: {cve_id} <-> {advisory_uuid}")
        return True
        
    except Exception as e:
        logger.error(f"Error linking CVE to advisory: {str(e)}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return False


async def link_cve_to_package(cve_id: str, package_uuid: str) -> bool:
    """
    Create relationship between CVE and Package in cves_packages table
    
    Args:
        cve_id: CVE ID (text)
        package_uuid: Package UUID
    
    Returns:
        True if successful, False otherwise
    """
    try:
        session = get_db_session()
        
        # Check if relationship already exists
        from sqlalchemy import text
        check_stmt = text("""
            SELECT 1 FROM concert_advisory.cves_packages 
            WHERE cve_id = :cve_id AND package_id = :package_id
        """)
        result = session.execute(check_stmt, {"cve_id": cve_id, "package_id": package_uuid})
        
        if result.fetchone():
            logger.info(f"Relationship already exists: {cve_id} <-> {package_uuid}")
            session.close()
            return True
        
        # Create relationship
        insert_stmt = text("""
            INSERT INTO concert_advisory.cves_packages (cve_id, package_id)
            VALUES (:cve_id, :package_id)
        """)
        session.execute(insert_stmt, {"cve_id": cve_id, "package_id": package_uuid})
        session.commit()
        session.close()
        
        logger.info(f"Linked CVE to package: {cve_id} <-> {package_uuid}")
        return True
        
    except Exception as e:
        logger.error(f"Error linking CVE to package: {str(e)}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return False



async def populate_database_from_intelligence(cve_id: str, raw_intel: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main function to populate database with intelligence data
    
    Extracts and saves:
    - Vulnerability data
    - Advisory data (from AWS ALAS)
    - Package data (from OSV)
    - Relationships between entities
    
    Args:
        cve_id: CVE ID to process
        raw_intel: Raw intelligence data from all sources
    
    Returns:
        Dictionary with population results
    """
    results = {
        "cve_id": cve_id,
        "vulnerability_saved": False,
        "advisories_saved": [],
        "packages_saved": [],
        "relationships_created": {
            "cve_advisory": [],
            "cve_package": []
        },
        "errors": []
    }
    
    try:
        sources = raw_intel.get("sources", {})
        
        # Extract basic CVE data for vulnerability table
        cve_data = {
            "cve_id": cve_id,
            "description": None,
            "severity": None,
            "cvss_score": None,
            "exploit_maturity": None
        }
        
        # Get description from NVD
        nvd_data = sources.get("nvd", {})
        if nvd_data and "descriptions" in nvd_data:
            for desc in nvd_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    cve_data["description"] = desc.get("value")
                    break
        
        # Get CVSS score and severity from NVD
        if nvd_data and "metrics" in nvd_data:
            metrics = nvd_data.get("metrics", {})
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_v3 = metrics["cvssMetricV31"][0].get("cvssData", {})
                cve_data["cvss_score"] = cvss_v3.get("baseScore")
                cve_data["severity"] = cvss_v3.get("baseSeverity")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_v2 = metrics["cvssMetricV2"][0].get("cvssData", {})
                cve_data["cvss_score"] = cvss_v2.get("baseScore")
        
        # Step 1: Save vulnerability
        logger.info(f"Saving vulnerability data for {cve_id}")
        saved_cve = await save_vulnerability_to_db(cve_data, raw_intel)
        if saved_cve:
            results["vulnerability_saved"] = True
            logger.info(f"✓ Vulnerability saved: {cve_id}")
        else:
            results["errors"].append("Failed to save vulnerability")
            logger.error(f"✗ Failed to save vulnerability: {cve_id}")
        
        # Step 2: Save advisories from AWS ALAS
        aws_data = sources.get("aws_alas", {})
        if aws_data and "advisories" in aws_data:
            logger.info(f"Processing {len(aws_data['advisories'])} AWS ALAS advisories")
            for advisory in aws_data.get("advisories", []):
                advisory_uuid = await save_advisory_to_db(advisory, cve_id)
                if advisory_uuid:
                    results["advisories_saved"].append(advisory.get("advisory_id"))
                    logger.info(f"✓ Advisory saved: {advisory.get('advisory_id')}")
                    
                    # Link CVE to Advisory
                    if await link_cve_to_advisory(cve_id, advisory_uuid):
                        results["relationships_created"]["cve_advisory"].append(advisory.get("advisory_id"))
                        logger.info(f"✓ Linked CVE to advisory: {cve_id} <-> {advisory.get('advisory_id')}")
                else:
                    results["errors"].append(f"Failed to save advisory: {advisory.get('advisory_id')}")
        
        # Step 3: Save packages from OSV
        osv_data = sources.get("osv", {})
        if osv_data and "affected" in osv_data:
            logger.info(f"Processing OSV package data")
            for affected in osv_data.get("affected", []):
                package_info = affected.get("package", {})
                if package_info:
                    package_data = {
                        "name": package_info.get("name"),
                        "ecosystem": package_info.get("ecosystem"),
                        "version": None,  # OSV provides version ranges, not specific versions
                        "description": osv_data.get("summary")
                    }
                    
                    # Extract affected versions
                    ranges = affected.get("ranges", [])
                    if ranges:
                        # Use the first range as representative version
                        events = ranges[0].get("events", [])
                        if events and "introduced" in events[0]:
                            package_data["version"] = events[0]["introduced"]
                    
                    if package_data["name"]:
                        package_uuid = await save_package_to_db(package_data)
                        if package_uuid:
                            package_key = f"{package_data['name']}@{package_data['version']}"
                            results["packages_saved"].append(package_key)
                            logger.info(f"✓ Package saved: {package_key}")
                            
                            # Link CVE to Package
                            if await link_cve_to_package(cve_id, package_uuid):
                                results["relationships_created"]["cve_package"].append(package_key)
                                logger.info(f"✓ Linked CVE to package: {cve_id} <-> {package_key}")
                        else:
                            results["errors"].append(f"Failed to save package: {package_data['name']}")
        
        # Summary
        # Step 4: Enrich products from CPE data and external APIs
        logger.info(f"Enriching product data for {cve_id}")
        product_results = await enrich_products_from_intelligence(cve_id, raw_intel)
        
        results['products_from_cpe'] = product_results.get('products_from_cpe', [])
        results['products_enriched'] = product_results.get('products_enriched', [])
        results['releases_saved'] = product_results.get('releases_saved', 0)
        results['dependencies_saved'] = product_results.get('dependencies_saved', 0)
        
        if product_results.get('errors'):
            results['errors'].extend(product_results['errors'])
        
        logger.info(f"""
Database population complete for {cve_id}:
  - Vulnerability: {'✓' if results['vulnerability_saved'] else '✗'}
  - Advisories: {len(results['advisories_saved'])}
  - Packages: {len(results['packages_saved'])}
  - Products (from CPE): {len(results.get('products_from_cpe', []))}
  - Products (enriched): {len(results.get('products_enriched', []))}
  - Product releases: {results.get('releases_saved', 0)}
  - CVE-Advisory links: {len(results['relationships_created']['cve_advisory'])}
  - CVE-Package links: {len(results['relationships_created']['cve_package'])}
  - Errors: {len(results['errors'])}
        """)
        
        return results
        
    except Exception as e:
        error_msg = f"Error populating database for {cve_id}: {str(e)}"
        logger.error(error_msg)
        results["errors"].append(error_msg)
        return results


# ============================================================================
# PRODUCT ENRICHMENT FUNCTIONS
# ============================================================================

from app.db.models import Product, ProductRelease, ProductDependency
from app.utils.product_enrichment import (
    extract_products_from_cpe_list,
    enrich_product_with_lifecycle,
    fetch_package_dependencies
)


async def save_product_from_cpe(product_data: Dict[str, Any]) -> Optional[str]:
    """
    Save product extracted from CPE to database
    
    Args:
        product_data: Product information from CPE parsing
    
    Returns:
        Product UUID if successful, None otherwise
    """
    try:
        session = get_db_session()
        
        name = product_data.get('name')
        vendor = product_data.get('vendor')
        version = product_data.get('version')
        
        if not name:
            logger.error("No product name provided")
            return None
        
        # Check if product exists
        stmt = select(Product).where(
            Product.name == name,
            Product.vendor == vendor,
            Product.version == version
        )
        result = session.execute(stmt)
        existing = result.scalar_one_or_none()
        
        if existing:
            logger.info(f"Product already exists: {name} ({vendor}) v{version}")
            return str(existing.id)
        
        # Create new product
        logger.info(f"Creating new product: {name} ({vendor}) v{version}")
        new_product = Product(
            name=name,
            vendor=vendor,
            version=version,
            product_family=product_data.get('product_family')
        )
        session.add(new_product)
        session.flush()
        product_uuid = str(new_product.id)
        
        session.commit()
        session.close()
        return product_uuid
        
    except Exception as e:
        logger.error(f"Error saving product from CPE: {e}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return None


async def save_product_releases(product_id: str, releases_data: List[Dict[str, Any]]) -> int:
    """
    Save product release information to database
    
    Args:
        product_id: Product UUID
        releases_data: List of release information from endoflife.date
    
    Returns:
        Number of releases saved
    """
    try:
        session = get_db_session()
        saved_count = 0
        
        for release in releases_data:
            try:
                # Check if release already exists
                stmt = select(ProductRelease).where(
                    ProductRelease.product_id == product_id,
                    ProductRelease.full_version == release.get('full_version', [])
                )
                result = session.execute(stmt)
                existing = result.scalar_one_or_none()
                
                if existing:
                    # Update existing release
                    if release.get('eol_date'):
                        existing.eol_date = release['eol_date']
                    if release.get('release_date'):
                        existing.release_date = release['release_date']
                    if release.get('extended_support') is not None:
                        existing.extended_support = release['extended_support']
                else:
                    # Create new release
                    new_release = ProductRelease(
                        product_id=product_id,
                        full_version=release.get('full_version', []),
                        major_version=release.get('major_version'),
                        minor_version=release.get('minor_version'),
                        patch_version=release.get('patch_version'),
                        release_date=release.get('release_date'),
                        eol_date=release.get('eol_date'),
                        extended_support=release.get('extended_support', False)
                    )
                    session.add(new_release)
                
                saved_count += 1
                
            except Exception as e:
                logger.warning(f"Failed to save release {release.get('cycle')}: {e}")
                continue
        
        session.commit()
        session.close()
        logger.info(f"Saved {saved_count} releases for product {product_id}")
        return saved_count
        
    except Exception as e:
        logger.error(f"Error saving product releases: {e}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return 0


async def save_product_dependency(parent_id: str, dependency_id: str, dep_info: Dict[str, Any]) -> bool:
    """
    Save product dependency relationship
    
    Args:
        parent_id: Parent product UUID
        dependency_id: Dependency product UUID
        dep_info: Dependency information (type, version range)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        session = get_db_session()
        
        # Check if dependency already exists
        stmt = select(ProductDependency).where(
            ProductDependency.parent_product_id == parent_id,
            ProductDependency.dependency_product_id == dependency_id
        )
        result = session.execute(stmt)
        existing = result.scalar_one_or_none()
        
        if existing:
            logger.info(f"Dependency already exists: {parent_id} -> {dependency_id}")
            session.close()
            return True
        
        # Create new dependency
        new_dep = ProductDependency(
            parent_product_id=parent_id,
            dependency_product_id=dependency_id,
            dependent_type=dep_info.get('kind', 'runtime'),
            supported_version_range=dep_info.get('requirements')
        )
        session.add(new_dep)
        session.commit()
        session.close()
        
        logger.info(f"Saved dependency: {parent_id} -> {dependency_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving product dependency: {e}")
        if 'session' in locals():
            session.rollback()
            session.close()
        return False


async def enrich_products_from_intelligence(cve_id: str, raw_intel: Dict[str, Any], libraries_io_api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Enrich product data using CPE parsing and external APIs
    
    Combines:
    1. CPE parsing for basic product info
    2. endoflife.date API for lifecycle data
    3. Libraries.io API for dependencies (if API key provided)
    
    Args:
        cve_id: CVE ID
        raw_intel: Raw intelligence data
        libraries_io_api_key: Optional Libraries.io API key
    
    Returns:
        Dictionary with enrichment results
    """
    results = {
        'cve_id': cve_id,
        'products_from_cpe': [],
        'products_enriched': [],
        'releases_saved': 0,
        'dependencies_saved': 0,
        'errors': []
    }
    
    try:
        # Step 1: Extract products from CPE references
        nvd_data = raw_intel.get('sources', {}).get('nvd', {})
        cpe_refs = []
        
        if nvd_data and 'configurations' in nvd_data:
            for config in nvd_data.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('criteria'):
                            cpe_refs.append(cpe_match.get('criteria'))
        
        if not cpe_refs:
            logger.info(f"No CPE references found for {cve_id}")
            return results
        
        logger.info(f"Found {len(cpe_refs)} CPE references for {cve_id}")
        
        # Parse CPE references
        products = extract_products_from_cpe_list(cpe_refs)
        
        # Step 2: Save products and enrich with lifecycle data
        for product_data in products:
            try:
                # Save basic product from CPE
                product_uuid = await save_product_from_cpe(product_data)
                
                if product_uuid:
                    results['products_from_cpe'].append(product_data['name'])
                    
                    # Step 3: Enrich with lifecycle data from endoflife.date
                    product_name = product_data['name']
                    lifecycle_data = await enrich_product_with_lifecycle(product_name)
                    
                    if lifecycle_data and lifecycle_data.get('releases'):
                        logger.info(f"Enriching {product_name} with {len(lifecycle_data['releases'])} releases")
                        
                        # Save releases
                        releases_saved = await save_product_releases(product_uuid, lifecycle_data['releases'])
                        results['releases_saved'] += releases_saved
                        results['products_enriched'].append(product_name)
                    else:
                        logger.info(f"No lifecycle data available for {product_name}")
                    
                    # Step 4: Fetch dependencies if API key provided
                    if libraries_io_api_key:
                        # Try to determine ecosystem from product name
                        ecosystem_hints = {
                            'python': 'pypi',
                            'node': 'npm',
                            'nodejs': 'npm',
                            'java': 'maven',
                            'ruby': 'rubygems',
                            'go': 'go',
                            'rust': 'cargo'
                        }
                        
                        ecosystem = ecosystem_hints.get(product_name.lower())
                        if ecosystem:
                            deps_data = await fetch_package_dependencies(
                                product_name,
                                ecosystem,
                                libraries_io_api_key
                            )
                            
                            if deps_data and 'dependencies' in deps_data:
                                logger.info(f"Found {len(deps_data['dependencies'])} dependencies for {product_name}")
                                # Dependencies would be saved here
                                # (requires creating dependency products first)
                                results['dependencies_saved'] += len(deps_data['dependencies'])
                
            except Exception as e:
                error_msg = f"Failed to process product {product_data.get('name')}: {e}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
                continue
        
        logger.info(f"""
Product enrichment complete for {cve_id}:
  - Products from CPE: {len(results['products_from_cpe'])}
  - Products enriched: {len(results['products_enriched'])}
  - Releases saved: {results['releases_saved']}
  - Dependencies saved: {results['dependencies_saved']}
  - Errors: {len(results['errors'])}
        """)
        
        return results
        
    except Exception as e:
        error_msg = f"Error enriching products for {cve_id}: {str(e)}"
        logger.error(error_msg)
        results['errors'].append(error_msg)
        return results


# ============================================================================
# QUERY FUNCTIONS - Retrieve data with relationships
# ============================================================================

async def get_advisory_with_details(advisory_id: str) -> Optional[Dict[str, Any]]:
    """
    Get advisory details with all related data
    
    Includes:
    - Advisory information
    - Related CVEs
    - Related products
    
    Args:
        advisory_id: Advisory ID (e.g., 'ALAS-2024-1234')
    
    Returns:
        Dictionary with complete advisory details or None if not found
    """
    try:
        session = get_db_session()
        
        # Get advisory
        stmt = select(Advisory).where(Advisory.advisory_id == advisory_id)
        result = session.execute(stmt)
        advisory = result.scalar_one_or_none()
        
        if not advisory:
            logger.warning(f"Advisory not found: {advisory_id}")
            session.close()
            return None
        
        # Get related CVEs
        from sqlalchemy import text
        cve_stmt = text("""
            SELECT v.* 
            FROM concert_advisory.vulnerabilities v
            JOIN concert_advisory.cves_advisories ca ON v.cve_id = ca.cve_id
            WHERE ca.advisory_id = :advisory_id
        """)
        cve_result = session.execute(cve_stmt, {"advisory_id": str(advisory.id)})
        cves = []
        for row in cve_result:
            cves.append({
                "cve_id": row.cve_id,
                "title": row.title,
                "description": row.description,
                "severity": row.latest_severity,
                "cvss_score": row.latest_cvss_score,
                "published_date": row.published_date.isoformat() if row.published_date else None
            })
        
        # Get related products
        product_stmt = text("""
            SELECT p.* 
            FROM concert_advisory.product p
            JOIN concert_advisory.advisories_products ap ON p.id = ap.product_id
            WHERE ap.advisory_id = :advisory_id
        """)
        product_result = session.execute(product_stmt, {"advisory_id": str(advisory.id)})
        products = []
        for row in product_result:
            products.append({
                "id": str(row.id),
                "name": row.name,
                "vendor": row.vendor,
                "version": row.version,
                "eol_date": row.eol_date.isoformat() if row.eol_date else None
            })
        
        session.close()
        
        # Build response
        response = {
            "advisory_id": advisory.advisory_id,
            "vendor": advisory.vendor,
            "title": advisory.title,
            "severity": advisory.aggregate_severity,
            "advisory_url": advisory.advisory_url,
            "advisory_type": advisory.advisory_type,
            "advisory_status": advisory.advisory_status,
            "published_date": advisory.published_date.isoformat() if advisory.published_date else None,
            "metadata": json.loads(advisory.advisory_metadata) if advisory.advisory_metadata else None,
            "related_cves": cves,
            "related_products": products,
            "total_cves": len(cves),
            "total_products": len(products)
        }
        
        logger.info(f"Retrieved advisory {advisory_id} with {len(cves)} CVEs and {len(products)} products")
        return response
        
    except Exception as e:
        logger.error(f"Error retrieving advisory {advisory_id}: {e}")
        if 'session' in locals():
            session.close()
        return None


async def get_cve_with_details(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Get CVE details with all related data
    
    Includes:
    - CVE/vulnerability information
    - Related advisories
    - Related products
    - Related packages
    
    Args:
        cve_id: CVE ID (e.g., 'CVE-2024-21626')
    
    Returns:
        Dictionary with complete CVE details or None if not found
    """
    try:
        session = get_db_session()
        
        # Get CVE
        stmt = select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        result = session.execute(stmt)
        cve = result.scalar_one_or_none()
        
        if not cve:
            logger.warning(f"CVE not found: {cve_id}")
            session.close()
            return None
        
        # Get related advisories
        from sqlalchemy import text
        advisory_stmt = text("""
            SELECT a.* 
            FROM concert_advisory.advisories a
            JOIN concert_advisory.cves_advisories ca ON a.id = ca.advisory_id
            WHERE ca.cve_id = :cve_id
        """)
        advisory_result = session.execute(advisory_stmt, {"cve_id": cve_id})
        advisories = []
        for row in advisory_result:
            advisories.append({
                "advisory_id": row.advisory_id,
                "vendor": row.vendor,
                "title": row.title,
                "severity": row.aggregate_severity,
                "advisory_url": row.advisory_url,
                "published_date": row.published_date.isoformat() if row.published_date else None
            })
        
        # Get related products (from CPE)
        product_stmt = text("""
            SELECT DISTINCT p.* 
            FROM concert_advisory.product p
            WHERE p.name IN (
                SELECT DISTINCT jsonb_array_elements_text(v.cpe_references::jsonb)
                FROM concert_advisory.vulnerabilities v
                WHERE v.cve_id = :cve_id
            )
            LIMIT 50
        """)
        try:
            product_result = session.execute(product_stmt, {"cve_id": cve_id})
            products = []
            for row in product_result:
                products.append({
                    "id": str(row.id),
                    "name": row.name,
                    "vendor": row.vendor,
                    "version": row.version,
                    "eol_date": row.eol_date.isoformat() if row.eol_date else None
                })
        except Exception as e:
            logger.warning(f"Could not fetch products for {cve_id}: {e}")
            products = []
        
        # Get related packages
        package_stmt = text("""
            SELECT pkg.* 
            FROM concert_advisory.packages pkg
            JOIN concert_advisory.cves_packages cp ON pkg.id = cp.package_id
            WHERE cp.cve_id = :cve_id
        """)
        package_result = session.execute(package_stmt, {"cve_id": cve_id})
        packages = []
        for row in package_result:
            packages.append({
                "id": str(row.id),
                "name": row.name,
                "version": row.version,
                "ecosystem": row.ecosystem,
                "description": row.description
            })
        
        session.close()
        
        # Build response
        response = {
            "cve_id": cve.cve_id,
            "title": cve.title,
            "description": cve.description,
            "severity": cve.latest_severity,
            "cvss_score": cve.latest_cvss_score,
            "cvss_vector": cve.latest_vector_string,
            "cvss_metrics": json.loads(cve.cvss_metrics) if cve.cvss_metrics else None,
            "is_exploitable": cve.is_exploitable,
            "is_patch_available": cve.is_patch_available,
            "cwe_references": json.loads(cve.cwe_references) if cve.cwe_references else [],
            "cpe_references": json.loads(cve.cpe_references) if cve.cpe_references else [],
            "reference_links": json.loads(cve.reference_links) if cve.reference_links else [],
            "published_date": cve.published_date.isoformat() if cve.published_date else None,
            "last_modified_date": cve.last_modified_date.isoformat() if cve.last_modified_date else None,
            "related_advisories": advisories,
            "related_products": products,
            "related_packages": packages,
            "total_advisories": len(advisories),
            "total_products": len(products),
            "total_packages": len(packages)
        }
        
        logger.info(f"Retrieved CVE {cve_id} with {len(advisories)} advisories, {len(products)} products, {len(packages)} packages")
        return response
        
    except Exception as e:
        logger.error(f"Error retrieving CVE {cve_id}: {e}")
        if 'session' in locals():
            session.close()
        return None


async def get_product_with_details(product_name: str) -> Optional[Dict[str, Any]]:
    """
    Get product details with all related data
    
    Includes:
    - Product information
    - Product releases (versions with EOL dates)
    - Related advisories
    - Related CVEs
    - Product dependencies
    
    Args:
        product_name: Product name (e.g., 'runc', 'python', 'postgresql')
    
    Returns:
        Dictionary with complete product details or None if not found
    """
    try:
        session = get_db_session()
        
        # Get all products matching the name (may have multiple versions)
        stmt = select(Product).where(Product.name == product_name)
        result = session.execute(stmt)
        products = result.scalars().all()
        
        if not products:
            logger.warning(f"Product not found: {product_name}")
            session.close()
            return None
        
        # Get all product IDs
        product_ids = [str(p.id) for p in products]
        
        # Get product releases using IN clause instead of ANY
        from sqlalchemy import text
        release_stmt = text("""
            SELECT *
            FROM concert_advisory.product_release
            WHERE product_id::text IN :product_ids
            ORDER BY release_date DESC
        """)
        release_result = session.execute(release_stmt, {"product_ids": tuple(product_ids)})
        releases = []
        for row in release_result:
            releases.append({
                "version": row.full_version[0] if row.full_version else None,
                "major_version": row.major_version,
                "minor_version": row.minor_version,
                "patch_version": row.patch_version,
                "release_date": row.release_date.isoformat() if row.release_date else None,
                "eol_date": row.eol_date.isoformat() if row.eol_date else None,
                "extended_support": row.extended_support
            })
        
        # Get related advisories using IN clause
        advisory_stmt = text("""
            SELECT DISTINCT a.*
            FROM concert_advisory.advisories a
            JOIN concert_advisory.advisories_products ap ON a.id = ap.advisory_id
            WHERE ap.product_id::text IN :product_ids
        """)
        advisory_result = session.execute(advisory_stmt, {"product_ids": tuple(product_ids)})
        advisories = []
        for row in advisory_result:
            advisories.append({
                "advisory_id": row.advisory_id,
                "vendor": row.vendor,
                "title": row.title,
                "severity": row.aggregate_severity,
                "advisory_url": row.advisory_url,
                "published_date": row.published_date.isoformat() if row.published_date else None
            })
        
        # Get related CVEs (through advisories) using IN clause
        cve_stmt = text("""
            SELECT DISTINCT v.*
            FROM concert_advisory.vulnerabilities v
            JOIN concert_advisory.cves_advisories ca ON v.cve_id = ca.cve_id
            JOIN concert_advisory.advisories_products ap ON ca.advisory_id = ap.advisory_id
            WHERE ap.product_id::text IN :product_ids
            ORDER BY v.published_date DESC
            LIMIT 100
        """)
        cve_result = session.execute(cve_stmt, {"product_ids": tuple(product_ids)})
        cves = []
        for row in cve_result:
            cves.append({
                "cve_id": row.cve_id,
                "title": row.title,
                "severity": row.latest_severity,
                "cvss_score": row.latest_cvss_score,
                "published_date": row.published_date.isoformat() if row.published_date else None
            })
        
        # Get product dependencies using IN clause
        dep_stmt = text("""
            SELECT pd.*, p.name as dependency_name, p.vendor as dependency_vendor
            FROM concert_advisory.product_dependency pd
            JOIN concert_advisory.product p ON pd.dependency_product_id = p.id
            WHERE pd.parent_product_id::text IN :product_ids
        """)
        dep_result = session.execute(dep_stmt, {"product_ids": tuple(product_ids)})
        dependencies = []
        for row in dep_result:
            dependencies.append({
                "dependency_name": row.dependency_name,
                "dependency_vendor": row.dependency_vendor,
                "dependency_type": row.dependent_type,
                "version_range": row.supported_version_range
            })
        
        session.close()
        
        # Build response with first product as primary
        primary_product = products[0]
        response = {
            "product_name": primary_product.name,
            "vendor": primary_product.vendor,
            "product_family": primary_product.product_family,
            "total_versions": len(products),
            "versions": [
                {
                    "version": p.version,
                    "release_date": p.release_date.isoformat() if p.release_date else None,
                    "eol_date": p.eol_date.isoformat() if p.eol_date else None,
                    "extended_support": p.extended_support
                }
                for p in products
            ],
            "releases": releases,
            "related_advisories": advisories,
            "related_cves": cves,
            "dependencies": dependencies,
            "total_releases": len(releases),
            "total_advisories": len(advisories),
            "total_cves": len(cves),
            "total_dependencies": len(dependencies)
        }
        
        logger.info(f"Retrieved product {product_name} with {len(releases)} releases, {len(advisories)} advisories, {len(cves)} CVEs")
        return response
        
    except Exception as e:
        logger.error(f"Error retrieving product {product_name}: {e}")
        if 'session' in locals():
            session.close()
        return None
