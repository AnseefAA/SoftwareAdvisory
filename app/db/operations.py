"""
Database operations for advisory remediation
"""
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker, Session
from typing import Optional, Dict, Any, List
import os
import logging
from app.db.models import Advisory, Vulnerability, CVEAdvisory, Product, Package

logger = logging.getLogger(__name__)

# Get database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

# Create engine
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
    """
    try:
        session = get_db_session()
        
        # Query advisory
        stmt = select(Advisory).where(Advisory.advisory_id == advisory_id)
        result = session.execute(stmt)
        advisory = result.scalar_one_or_none()
        
        if not advisory:
            logger.warning(f"Advisory {advisory_id} not found in database")
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
        logger.error(f"Error fetching advisory {advisory_id}: {str(e)}")
        return None

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
        session.rollback()
        session.close()
        return False

async def get_all_advisories(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """
    Get all advisories with pagination
    
    Args:
        limit: Maximum number of records to return
        offset: Number of records to skip
    
    Returns:
        List of advisory dictionaries
    """
    try:
        session = get_db_session()
        
        stmt = select(Advisory).limit(limit).offset(offset)
        result = session.execute(stmt)
        advisories = result.scalars().all()
        
        advisory_list = []
        for advisory in advisories:
            advisory_list.append({
                "id": str(advisory.id),
                "advisory_id": advisory.advisory_id,
                "vendor": advisory.vendor,
                "title": advisory.title,
                "severity": advisory.aggregate_severity,
                "published_date": advisory.published_date.isoformat() if advisory.published_date else None,
                "has_remediation_plan": advisory.remediation_plan is not None
            })
        
        session.close()
        return advisory_list
        
    except Exception as e:
        logger.error(f"Error fetching advisories: {str(e)}")
        return []