"""
Intelligence API routes
APIs:
- /api/v1/intelligence/assess
- /api/v1/intelligence/structured
- /api/v1/intelligence/fetch
"""
from fastapi import APIRouter, HTTPException
import logging
from app import models as Models
from app.utils.intelligence_helpers import (
    aggregate_cve_intelligence,
    extract_structured_intelligence
)
from app.db.operations import (
    save_intelligence_cache,
    get_intelligence_cache,
    populate_database_from_intelligence
)

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/intelligence/fetch")
async def fetch_intelligence(payload: Models.MitigationRequest) -> dict:
    """
    Fetch CVE/Advisory intelligence from multiple sources and save to database.
    
    This endpoint aggregates intelligence from configured sources (NVD, MITRE, GitHub CVE Project,
    OSV.dev) and saves the raw data to the intelligence_cache table with merge logic.
    
    Args:
        payload (Models.MitigationRequest): Request containing CVE ID or Advisory ID
    
    Returns:
        dict: Confirmation with database record metadata
        
    Example:
        POST /api/v1/intelligence/fetch
        {
            "cveId": "CVE-2024-21626"
        }
        
        Response:
        {
            "status": "success",
            "cve_id": "CVE-2024-21626",
            "sources_fetched": ["NVD", "MITRE", "GitHub CVE Project", "OSV.dev"],
            "fetched_at": "2024-01-15T10:30:00Z",
            "saved_to_database": true,
            "is_update": false
        }
    """
    try:
        logger.info(f"Fetching intelligence for {payload.cveId} from multiple sources")
        
        # Step 1: Check if intelligence already exists in database
        existing_cache = await get_intelligence_cache(payload.cveId, "cve")
        is_update = existing_cache is not None
        
        if is_update:
            logger.info(f"Found existing intelligence cache for {payload.cveId}, will merge data")
        
        # Step 2: Aggregate intelligence from all configured sources
        aggregated_intel = await aggregate_cve_intelligence(payload.cveId)
        
        # Step 3: Extract metadata
        sources_used = aggregated_intel.get("metadata", {}).get("sources_available", [])
        metadata = aggregated_intel.get("metadata", {})
        fetch_errors = aggregated_intel.get("metadata", {}).get("errors", {})
        is_complete = len(fetch_errors) == 0
        
        # Step 4: Save to database (with merge logic)
        saved = await save_intelligence_cache(
            identifier=payload.cveId,
            identifier_type="cve",
            raw_data=aggregated_intel,
            structured_data=None,  # Will be populated by assess endpoint
            sources_fetched=sources_used,
            is_complete=is_complete,
            fetch_errors=fetch_errors if fetch_errors else None
        )
        
        if not saved:
            raise HTTPException(status_code=500, detail="Failed to save intelligence to database")
        
        logger.info(f"Intelligence {'updated' if is_update else 'saved'} for {payload.cveId} in database")
        
        return {
            "status": "success",
            "cve_id": payload.cveId,
            "sources_fetched": sources_used,
            "fetched_at": metadata.get("fetched_at"),
            "saved_to_database": True,
            "is_update": is_update,
            "is_complete": is_complete,
            "message": f"Intelligence data successfully {'updated' if is_update else 'fetched and saved'} for {payload.cveId}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching intelligence: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch intelligence: {str(e)}")


@router.post("/intelligence/assess")
async def assess_intelligence(payload: Models.MitigationRequest) -> Models.StructuredIntelligenceResponse:
    """
    Assess CVE/Advisory intelligence from database cache or fetch if not available.
    
    This endpoint first attempts to load intelligence data from the database cache.
    If not found, it fetches the data from sources, saves it to database, and then processes it.
    The processed data is returned in a structured format ready for database storage.
    
    Args:
        payload (Models.MitigationRequest): Request containing CVE ID or Advisory ID
    
    Returns:
        StructuredIntelligenceResponse: Structured intelligence data with:
            - CVE record (ID, description, CVSS score, severity)
            - Affected products and versions
            - Vendor advisories and patches
            - Lifecycle data (EOL dates, support status)
            - Compatibility information
            - License policies
            - Data sources used
            
    Example:
        POST /api/v1/intelligence/assess
        {
            "cveId": "CVE-2024-21626"
        }
        
        Response: StructuredIntelligenceResponse with complete vulnerability intelligence
    """
    try:
        logger.info(f"Assessing intelligence for {payload.cveId}")
        
        # Step 1: Try to load from database cache
        cache_data = await get_intelligence_cache(payload.cveId, "cve")
        
        # Step 2: If not found, fetch from sources and save
        if not cache_data or not cache_data.get("raw_data"):
            logger.info(f"No cached intelligence found for {payload.cveId}, fetching from sources")
            aggregated_intel = await aggregate_cve_intelligence(payload.cveId)
            
            # Extract metadata
            sources_used = aggregated_intel.get("metadata", {}).get("sources_available", [])
            fetch_errors = aggregated_intel.get("metadata", {}).get("errors", {})
            is_complete = len(fetch_errors) == 0
            
            # Save to database
            await save_intelligence_cache(
                identifier=payload.cveId,
                identifier_type="cve",
                raw_data=aggregated_intel,
                structured_data=None,
                sources_fetched=sources_used,
                is_complete=is_complete,
                fetch_errors=fetch_errors if fetch_errors else None
            )
            logger.info(f"Intelligence fetched and saved to database for {payload.cveId}")
        else:
            logger.info(f"Loaded intelligence from database cache for {payload.cveId}")
            aggregated_intel = cache_data.get("raw_data")
        
        # Step 3: Extract structured data
        structured_data = await extract_structured_intelligence(aggregated_intel)
        
        # Step 4: Update cache with structured data
        if cache_data:
            await save_intelligence_cache(
                identifier=payload.cveId,
                identifier_type="cve",
                raw_data=aggregated_intel,
                structured_data=structured_data.dict(),
                sources_fetched=cache_data.get("sources_fetched", []),
                is_complete=cache_data.get("is_complete", False),
                fetch_errors=cache_data.get("fetch_errors")
            )
            logger.info(f"Updated structured intelligence in database for {payload.cveId}")
        
        # Step 5: Populate database tables with structured data
        logger.info(f"Populating database tables for {payload.cveId}")
        population_results = await populate_database_from_intelligence(payload.cveId, aggregated_intel)
        
        logger.info(f"Database population complete for {payload.cveId}:")
        logger.info(f"  - Vulnerability saved: {population_results['vulnerability_saved']}")
        logger.info(f"  - Advisories saved: {len(population_results['advisories_saved'])}")
        logger.info(f"  - Packages saved: {len(population_results['packages_saved'])}")
        logger.info(f"  - CVE-Advisory links: {len(population_results['relationships_created']['cve_advisory'])}")
        logger.info(f"  - CVE-Package links: {len(population_results['relationships_created']['cve_package'])}")
        if population_results['errors']:
            logger.warning(f"  - Errors: {len(population_results['errors'])}")
            for error in population_results['errors']:
                logger.warning(f"    - {error}")
        
        logger.info(f"Intelligence assessed for {payload.cveId}")
        logger.info(f"Found {len(structured_data.products)} products, "
                   f"{len(structured_data.vendor_advisories)} advisories, "
                   f"{len(structured_data.patches)} patches, "
                   f"{len(structured_data.lifecycle)} lifecycle records")
        
        return structured_data
        
    except Exception as e:
        logger.error(f"Error assessing intelligence: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to assess intelligence: {str(e)}")


@router.post("/intelligence/structured")
async def get_structured_intelligence(payload: Models.MitigationRequest) -> Models.StructuredIntelligenceResponse:
    """
    Get structured, quantitative CVE intelligence for database storage.
    
    Returns database-ready structured data including:
    - CVE record (cve_id, description, cvss_score, severity, exploit_maturity, kev_listed)
    - Product records (product_id, product_name, vendor, product_family)
    - CVE-Product mappings (affected_version_range, vendor_severity)
    - Vendor advisories (advisory_id, severity, advisory_url, published_date)
    - Patch records (patch_id, fixed_version, reboot_required, patch_release_date)
    - Compatibility records (source_product, dependent_product, certification_status)
    - Lifecycle records (version, release_date, eol_date, extended_support)
    - Policy records (version_policy, license_policy)
    
    This endpoint provides quantitative data suitable for:
    - Database storage
    - Analytics and reporting
    - Automated decision-making
    - Compliance tracking
    
    Args:
        payload (Models.MitigationRequest): Request containing CVE ID and filename
    
    Returns:
        StructuredIntelligenceResponse: Complete structured intelligence data
    """
    try:
        logger.info(f"Fetching structured intelligence for {payload.cveId}")
        
        # Step 1: Aggregate intelligence from multiple sources
        aggregated_intel = await aggregate_cve_intelligence(payload.cveId)
        
        # Step 2: Extract structured data
        structured_data = await extract_structured_intelligence(aggregated_intel)
        
        logger.info(f"Structured intelligence extracted for {payload.cveId}")
        logger.info(f"Found {len(structured_data.products)} products, {len(structured_data.vendor_advisories)} advisories, {len(structured_data.patches)} patches")
        
        return structured_data
        
    except Exception as e:
        logger.error(f"Error fetching structured intelligence: {str(e)}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")


@router.get("/intelligence/cache")
async def list_intelligence_cache() -> dict:
    """
    List all cached intelligence records from database.
    
    Returns a list of all CVE/Advisory intelligence records that have been cached,
    including metadata like sources fetched, fetch count, and last updated date.
    
    Returns:
        dict: List of cached intelligence records with metadata
        
    Example:
        GET /api/v1/intelligence/cache
        
        Response:
        {
            "total_records": 5,
            "records": [
                {
                    "identifier": "CVE-2024-21626",
                    "identifier_type": "cve",
                    "sources_fetched": ["NVD", "MITRE"],
                    "fetch_count": 3,
                    "is_complete": true,
                    "last_updated_at": "2024-01-15T10:30:00"
                },
                ...
            ]
        }
    """
    try:
        from app.db.operations import get_db_session
        from app.db.models import IntelligenceCache
        from sqlalchemy import select
        
        session = get_db_session()
        
        # Query all intelligence cache records
        stmt = select(IntelligenceCache).order_by(IntelligenceCache.last_updated_at.desc())
        result = session.execute(stmt)
        caches = result.scalars().all()
        
        records = []
        for cache in caches:
            records.append({
                "id": str(cache.id),
                "identifier": cache.identifier,
                "identifier_type": cache.identifier_type,
                "sources_fetched": cache.sources_fetched,
                "fetch_count": cache.fetch_count,
                "is_complete": cache.is_complete,
                "has_structured_data": cache.structured_data is not None,
                "first_fetched_at": cache.first_fetched_at.isoformat() if cache.first_fetched_at else None,
                "last_updated_at": cache.last_updated_at.isoformat() if cache.last_updated_at else None
            })
        
        session.close()
        
        return {
            "total_records": len(records),
            "records": records
        }
        
    except Exception as e:
        logger.error(f"Error listing intelligence cache: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list cache: {str(e)}")

# Made with Bob
