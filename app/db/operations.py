"""
Database operations for advisory remediation
Minimal version - only functions needed for targeted remediation API
"""
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker, Session
from typing import Optional, Dict, Any, List
import os
import logging
from app.db.models import Advisory, Vulnerability, VulnerabilityAdvisory
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
DB_SCHEMA = os.getenv("DB_SCHEMA", "public")

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
        cve_stmt = select(VulnerabilityAdvisory.vulnerability_id).where(VulnerabilityAdvisory.advisory_id == advisory.id)
        cve_result = session.execute(cve_stmt)
        cve_ids = [row[0] for row in cve_result.fetchall()]
        
        # Get CVE details
        cves = []
        if cve_ids:
            vuln_stmt = select(Vulnerability).where(Vulnerability.id.in_(cve_ids))
            vuln_result = session.execute(vuln_stmt)
            vulnerabilities = vuln_result.scalars().all()
            
            for vuln in vulnerabilities:
                cves.append({
                    "cve_id": vuln.id,
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
    session = None
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
        logger.error(f"Error updating remediation plan for {advisory_id}: {str(e)}")
        if session:
            session.rollback()
            session.close()
        return False


# Made with Bob
