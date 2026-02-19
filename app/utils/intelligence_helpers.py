"""
Helper functions for intelligence aggregation and processing
"""
import logging
import json
import os
from typing import Dict, Any, List
from datetime import datetime
from app.utils.httputil import get, get_html
from app import models as Models

logger = logging.getLogger(__name__)

# Intelligence data directory
INTELLIGENCE_DATA_DIR = "app/data/intelligence"

async def fetch_nvd_cve_data(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE data from NVD API"""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        logger.info(f"Fetching CVE data from NVD: {url}")
        data = await get(url, timeout=30)
        
        if data and "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
            vuln_data = data["vulnerabilities"][0]["cve"]
            logger.info(f"Successfully fetched {cve_id} from NVD")
            return vuln_data
        return {}
    except Exception as e:
        logger.error(f"Error fetching from NVD: {str(e)}")
        return {}

async def fetch_mitre_cve_data(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE data from MITRE CVE AWG API"""
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        logger.info(f"Fetching CVE data from MITRE: {url}")
        data = await get(url, timeout=30)
        
        if data:
            logger.info(f"Successfully fetched {cve_id} from MITRE")
            return data
        return {}
    except Exception as e:
        logger.error(f"Error fetching from MITRE: {str(e)}")
        return {}

async def fetch_github_cve_data(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE data from GitHub CVEProject repository"""
    try:
        parts = cve_id.split("-")
        if len(parts) != 3:
            logger.error(f"Invalid CVE ID format: {cve_id}")
            return {}
        
        year = parts[1]
        number = parts[2]
        
        if len(number) >= 4:
            dir_suffix = number[:-3] + "xxx"
        else:
            dir_suffix = "0xxx"
        
        url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{dir_suffix}/{cve_id}.json"
        logger.info(f"Fetching CVE data from GitHub: {url}")
        data = await get(url, timeout=30)
        
        if data:
            logger.info(f"Successfully fetched {cve_id} from GitHub CVE Project")
            return data
        return {}
    except Exception as e:
        logger.error(f"Error fetching from GitHub CVE Project: {str(e)}")
        return {}

async def fetch_osv_cve_data(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE data from OSV.dev API"""
    try:
        url = f"https://api.osv.dev/v1/vulns/{cve_id}"
        logger.info(f"Fetching CVE data from OSV.dev: {url}")
        data = await get(url, timeout=30)
        
        if data:
            logger.info(f"Successfully fetched {cve_id} from OSV.dev")
            return data
        return {}
    except Exception as e:
        logger.error(f"Error fetching from OSV.dev: {str(e)}")
        return {}

async def fetch_aws_alas_data(cve_id: str) -> Dict[str, Any]:
    """
    Fetch CVE data from AWS ALAS (Amazon Linux Security Advisories)
    Searches across ALAS, ALAS2, and ALAS1 bulletins
    """
    try:
        import re
        from bs4 import BeautifulSoup
        
        AWS_BULLETIN_URLS = [
            'https://alas.aws.amazon.com/',
            'https://alas.aws.amazon.com/alas2.html',
            'https://alas.aws.amazon.com/alas1.html'
        ]
        
        logger.info(f"Searching for {cve_id} in AWS ALAS bulletins")
        
        alas_data = {
            "advisories": [],
            "search_urls": AWS_BULLETIN_URLS
        }
        
        for bulletin_url in AWS_BULLETIN_URLS:
            try:
                logger.info(f"Fetching AWS ALAS bulletin: {bulletin_url}")
                html_content = await get_html(bulletin_url, timeout=30)
                
                if not html_content:
                    continue
                
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Find all advisory entries that mention the CVE
                advisory_rows = soup.find_all('tr')
                
                for row in advisory_rows:
                    row_text = row.get_text()
                    if cve_id in row_text:
                        # Extract advisory details
                        cells = row.find_all('td')
                        if len(cells) >= 3:
                            advisory_id = cells[0].get_text().strip()
                            severity = cells[1].get_text().strip() if len(cells) > 1 else "Unknown"
                            description = cells[2].get_text().strip() if len(cells) > 2 else ""
                            
                            # Try to find advisory link
                            advisory_link = None
                            link_tag = cells[0].find('a')
                            if link_tag and link_tag.get('href'):
                                advisory_link = link_tag.get('href')
                                if not advisory_link.startswith('http'):
                                    advisory_link = f"https://alas.aws.amazon.com/{advisory_link}"
                            
                            advisory_entry = {
                                "advisory_id": advisory_id,
                                "severity": severity,
                                "description": description,
                                "advisory_url": advisory_link,
                                "source_url": bulletin_url,
                                "cve_id": cve_id
                            }
                            
                            alas_data["advisories"].append(advisory_entry)
                            logger.info(f"Found AWS ALAS advisory: {advisory_id} for {cve_id}")
                
            except Exception as e:
                logger.error(f"Error fetching from {bulletin_url}: {str(e)}")
                continue
        
        if alas_data["advisories"]:
            logger.info(f"Successfully fetched {len(alas_data['advisories'])} AWS ALAS advisories for {cve_id}")
        else:
            logger.info(f"No AWS ALAS advisories found for {cve_id}")
        
        return alas_data
        
    except Exception as e:
        logger.error(f"Error fetching from AWS ALAS: {str(e)}")
        return {}

async def aggregate_cve_intelligence(cve_id: str) -> Dict[str, Any]:
    """
    Aggregate CVE intelligence from multiple sources
    """
    try:
        logger.info(f"Starting intelligence aggregation for {cve_id}")
        
        import asyncio
        nvd_data, mitre_data, github_data, osv_data, aws_alas_data = await asyncio.gather(
            fetch_nvd_cve_data(cve_id),
            fetch_mitre_cve_data(cve_id),
            fetch_github_cve_data(cve_id),
            fetch_osv_cve_data(cve_id),
            fetch_aws_alas_data(cve_id),
            return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(nvd_data, Exception):
            logger.error(f"NVD fetch failed: {nvd_data}")
            nvd_data = {}
        if isinstance(mitre_data, Exception):
            logger.error(f"MITRE fetch failed: {mitre_data}")
            mitre_data = {}
        if isinstance(github_data, Exception):
            logger.error(f"GitHub fetch failed: {github_data}")
            github_data = {}
        if isinstance(osv_data, Exception):
            logger.error(f"OSV fetch failed: {osv_data}")
            osv_data = {}
        if isinstance(aws_alas_data, Exception):
            logger.error(f"AWS ALAS fetch failed: {aws_alas_data}")
            aws_alas_data = {}
        
        aggregated = {
            "cve_id": cve_id,
            "metadata": {
                "fetched_at": datetime.utcnow().isoformat(),
                "sources_available": []
            },
            "sources": {
                "nvd": nvd_data if nvd_data else None,
                "mitre": mitre_data if mitre_data else None,
                "github": github_data if github_data else None,
                "osv": osv_data if osv_data else None,
                "aws_alas": aws_alas_data if aws_alas_data else None
            }
        }
        
        # Track which sources returned data
        for source, data in aggregated["sources"].items():
            if data:
                aggregated["metadata"]["sources_available"].append(source)
        
        logger.info(f"Intelligence aggregation complete for {cve_id}")
        return aggregated
        
    except Exception as e:
        logger.error(f"Error in intelligence aggregation: {str(e)}")
        return {"cve_id": cve_id, "error": str(e)}

async def save_intelligence_to_file(cve_id: str, intelligence_data: Dict[str, Any]) -> str:
    """Save intelligence data to JSON file"""
    try:
        os.makedirs(INTELLIGENCE_DATA_DIR, exist_ok=True)
        file_path = os.path.join(INTELLIGENCE_DATA_DIR, f"{cve_id}.json")
        
        with open(file_path, 'w') as f:
            json.dump(intelligence_data, f, indent=2)
        
        logger.info(f"Saved intelligence data to {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"Error saving intelligence to file: {str(e)}")
        raise

async def load_intelligence_from_file(cve_id: str) -> Dict[str, Any]:
    """Load intelligence data from JSON file"""
    try:
        file_path = os.path.join(INTELLIGENCE_DATA_DIR, f"{cve_id}.json")
        
        if not os.path.exists(file_path):
            logger.info(f"No saved intelligence file found for {cve_id}")
            return {}
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        logger.info(f"Loaded intelligence data from {file_path}")
        return data
    except Exception as e:
        logger.error(f"Error loading intelligence from file: {str(e)}")
        return {}

async def extract_structured_intelligence(aggregated_intel: Dict[str, Any]) -> Models.StructuredIntelligenceResponse:
    """
    Extract structured intelligence from aggregated data
    """
    try:
        cve_id = aggregated_intel.get("cve_id", "")
        sources = aggregated_intel.get("sources", {})
        
        # Extract CVE record
        nvd_data = sources.get("nvd", {})
        description = ""
        cvss_score = 0.0
        severity = "UNKNOWN"
        
        if nvd_data:
            if "descriptions" in nvd_data:
                for desc in nvd_data["descriptions"]:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
            
            if "metrics" in nvd_data:
                metrics = nvd_data["metrics"]
                if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
        
        cve_record = Models.CVERecord(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            severity=severity,
            exploit_maturity=None,
            kev_listed=False
        )
        
        # Extract products from OSV data
        products = []
        cve_product_mappings = []
        osv_data = sources.get("osv", {})
        
        if osv_data and "affected" in osv_data:
            for idx, affected in enumerate(osv_data["affected"]):
                package = affected.get("package", {})
                product_name = package.get("name", "unknown")
                ecosystem = package.get("ecosystem", "unknown")
                
                product_id = f"{ecosystem}:{product_name}"
                
                product = Models.ProductRecord(
                    product_id=product_id,
                    product_name=product_name,
                    vendor=ecosystem,
                    product_family=ecosystem
                )
                products.append(product)
                
                # Extract version range
                version_range = "unknown"
                if "ranges" in affected:
                    for range_info in affected["ranges"]:
                        events = range_info.get("events", [])
                        for event in events:
                            if "introduced" in event:
                                version_range = f">= {event['introduced']}"
                            if "fixed" in event:
                                version_range += f", < {event['fixed']}"
                
                mapping = Models.CVEProductMap(
                    cve_id=cve_id,
                    product_id=product_id,
                    affected_version_range=version_range,
                    vendor_severity=severity
                )
                cve_product_mappings.append(mapping)
        
        # Create response with empty lists for other fields
        response = Models.StructuredIntelligenceResponse(
            cve=cve_record,
            products=products,
            cve_product_mappings=cve_product_mappings,
            vendor_advisories=[],
            patches=[],
            compatibility=[],
            lifecycle=[],
            version_policies=[],
            license_policies=[],
            intelligence_timestamp=datetime.utcnow().isoformat(),
            data_sources=aggregated_intel.get("metadata", {}).get("sources_available", [])
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error extracting structured intelligence: {str(e)}")
        raise

async def save_to_intelligence_database(structured_data: Models.StructuredIntelligenceResponse) -> bool:
    """
    Save structured intelligence to JSON database file
    """
    try:
        db_dir = "app/data/intelligence_db"
        os.makedirs(db_dir, exist_ok=True)
        
        db_file = os.path.join(db_dir, f"{structured_data.cve.cve_id}_structured.json")
        
        with open(db_file, 'w') as f:
            json.dump(structured_data.dict(), f, indent=2)
        
        logger.info(f"Saved structured intelligence to {db_file}")
        return True
    except Exception as e:
        logger.error(f"Error saving to intelligence database: {str(e)}")
        return False

async def list_saved_intelligence_files() -> List[Dict[str, Any]]:
    """List all saved intelligence files"""
    try:
        if not os.path.exists(INTELLIGENCE_DATA_DIR):
            return []
        
        files = []
        for filename in os.listdir(INTELLIGENCE_DATA_DIR):
            if filename.endswith('.json'):
                file_path = os.path.join(INTELLIGENCE_DATA_DIR, filename)
                stat = os.stat(file_path)
                
                files.append({
                    "cve_id": filename.replace('.json', ''),
                    "filename": filename,
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        return files
    except Exception as e:
        logger.error(f"Error listing intelligence files: {str(e)}")
        return []

# Made with Bob
