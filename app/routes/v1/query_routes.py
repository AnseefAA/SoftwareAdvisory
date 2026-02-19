"""
Query API routes for retrieving data from database
APIs:
- GET /api/v1/query/advisory/{advisory_id}
- GET /api/v1/query/cve/{cve_id}
- GET /api/v1/query/product/{product_name}
"""
from fastapi import APIRouter, HTTPException, Path
import logging
from app.db.operations import (
    get_advisory_with_details,
    get_cve_with_details,
    get_product_with_details
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/query/advisory/{advisory_id}")
async def get_advisory(
    advisory_id: str = Path(..., description="Advisory ID (e.g., ALAS-2024-1234)")
) -> dict:
    """
    Get advisory details with all related data
    
    Returns:
    - Advisory information (ID, vendor, title, severity, URL, etc.)
    - Related CVEs (all vulnerabilities associated with this advisory)
    - Related products (all products affected by this advisory)
    
    Example:
        GET /api/v1/query/advisory/ALAS-2024-1234
        
        Response:
        {
            "advisory_id": "ALAS-2024-1234",
            "vendor": "AWS",
            "title": "Important: runc security update",
            "severity": "IMPORTANT",
            "advisory_url": "https://alas.aws.amazon.com/...",
            "published_date": "2024-01-15T10:30:00Z",
            "related_cves": [
                {
                    "cve_id": "CVE-2024-21626",
                    "severity": "HIGH",
                    "cvss_score": 8.6,
                    ...
                }
            ],
            "related_products": [
                {
                    "name": "runc",
                    "vendor": "linuxfoundation",
                    "version": "1.1.0",
                    ...
                }
            ],
            "total_cves": 1,
            "total_products": 1
        }
    """
    try:
        logger.info(f"Querying advisory: {advisory_id}")
        
        result = await get_advisory_with_details(advisory_id)
        
        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Advisory not found: {advisory_id}"
            )
        
        logger.info(f"Successfully retrieved advisory {advisory_id} with {result['total_cves']} CVEs and {result['total_products']} products")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error querying advisory {advisory_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve advisory: {str(e)}"
        )


@router.get("/query/cve/{cve_id}")
async def get_cve(
    cve_id: str = Path(..., description="CVE ID (e.g., CVE-2024-21626)")
) -> dict:
    """
    Get CVE details with all related data
    
    Returns:
    - CVE/vulnerability information (ID, description, CVSS score, severity, etc.)
    - Related advisories (all security advisories that mention this CVE)
    - Related products (all products affected by this CVE)
    - Related packages (all packages affected by this CVE)
    
    Example:
        GET /api/v1/query/cve/CVE-2024-21626
        
        Response:
        {
            "cve_id": "CVE-2024-21626",
            "title": "runc process.cwd and leaked fds container breakout",
            "description": "runc is a CLI tool for spawning...",
            "severity": "HIGH",
            "cvss_score": 8.6,
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
            "is_exploitable": true,
            "is_patch_available": true,
            "cwe_references": ["CWE-22", "CWE-269"],
            "cpe_references": ["cpe:2.3:a:linuxfoundation:runc:1.1.0:*:*:*:*:*:*:*"],
            "published_date": "2024-01-31T22:15:53.780Z",
            "related_advisories": [
                {
                    "advisory_id": "ALAS-2024-1234",
                    "vendor": "AWS",
                    "severity": "IMPORTANT",
                    ...
                }
            ],
            "related_products": [
                {
                    "name": "runc",
                    "vendor": "linuxfoundation",
                    "version": "1.1.0",
                    ...
                }
            ],
            "related_packages": [
                {
                    "name": "runc",
                    "ecosystem": "Go",
                    "version": "1.1.0",
                    ...
                }
            ],
            "total_advisories": 2,
            "total_products": 1,
            "total_packages": 1
        }
    """
    try:
        logger.info(f"Querying CVE: {cve_id}")
        
        result = await get_cve_with_details(cve_id)
        
        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"CVE not found: {cve_id}"
            )
        
        logger.info(f"Successfully retrieved CVE {cve_id} with {result['total_advisories']} advisories, {result['total_products']} products, {result['total_packages']} packages")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error querying CVE {cve_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve CVE: {str(e)}"
        )


@router.get("/query/product/{product_name}")
async def get_product(
    product_name: str = Path(..., description="Product name (e.g., runc, python, postgresql)")
) -> dict:
    """
    Get product details with all related data
    
    Returns:
    - Product information (name, vendor, versions)
    - Product releases (all versions with EOL dates from endoflife.date)
    - Related advisories (all security advisories for this product)
    - Related CVEs (all vulnerabilities affecting this product)
    - Product dependencies (if available)
    
    Example:
        GET /api/v1/query/product/python
        
        Response:
        {
            "product_name": "python",
            "vendor": "python",
            "product_family": null,
            "total_versions": 5,
            "versions": [
                {
                    "version": "3.12",
                    "release_date": "2023-10-02T00:00:00Z",
                    "eol_date": "2028-10-02T00:00:00Z",
                    "extended_support": false
                },
                {
                    "version": "3.11",
                    "release_date": "2022-10-24T00:00:00Z",
                    "eol_date": "2027-10-24T00:00:00Z",
                    "extended_support": false
                }
            ],
            "releases": [
                {
                    "version": "3.12",
                    "major_version": 3,
                    "minor_version": 12,
                    "patch_version": null,
                    "release_date": "2023-10-02T00:00:00Z",
                    "eol_date": "2028-10-02T00:00:00Z",
                    "extended_support": false
                }
            ],
            "related_advisories": [
                {
                    "advisory_id": "RHSA-2024-1234",
                    "vendor": "Red Hat",
                    "severity": "IMPORTANT",
                    ...
                }
            ],
            "related_cves": [
                {
                    "cve_id": "CVE-2024-12345",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    ...
                }
            ],
            "dependencies": [
                {
                    "dependency_name": "openssl",
                    "dependency_vendor": "openssl",
                    "dependency_type": "runtime",
                    "version_range": ">=1.1.1"
                }
            ],
            "total_releases": 10,
            "total_advisories": 5,
            "total_cves": 15,
            "total_dependencies": 3
        }
    """
    try:
        logger.info(f"Querying product: {product_name}")
        
        result = await get_product_with_details(product_name)
        
        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Product not found: {product_name}"
            )
        
        logger.info(f"Successfully retrieved product {product_name} with {result['total_releases']} releases, {result['total_advisories']} advisories, {result['total_cves']} CVEs")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error querying product {product_name}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve product: {str(e)}"
        )

# Made with Bob
