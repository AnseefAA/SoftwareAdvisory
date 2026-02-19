"""
Product enrichment utilities
Combines CPE parsing with external APIs (endoflife.date, Libraries.io)
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from app.utils.httputil import get, post

logger = logging.getLogger(__name__)

# Product name mapping for endoflife.date API
PRODUCT_NAME_MAPPING = {
    # Container runtimes
    'runc': 'docker',
    'containerd': 'docker',
    'docker': 'docker',
    
    # Programming languages
    'python': 'python',
    'python3': 'python',
    'node': 'nodejs',
    'nodejs': 'nodejs',
    'node.js': 'nodejs',
    'java': 'java',
    'openjdk': 'java',
    'jdk': 'java',
    'jre': 'java',
    'go': 'go',
    'golang': 'go',
    'ruby': 'ruby',
    'php': 'php',
    'rust': 'rust',
    'dotnet': 'dotnet',
    '.net': 'dotnet',
    
    # Databases
    'postgresql': 'postgresql',
    'postgres': 'postgresql',
    'mysql': 'mysql',
    'mariadb': 'mariadb',
    'mongodb': 'mongodb',
    'redis': 'redis',
    'elasticsearch': 'elasticsearch',
    
    # Web servers
    'nginx': 'nginx',
    'apache': 'apache',
    'httpd': 'apache',
    'tomcat': 'tomcat',
    
    # Operating systems
    'ubuntu': 'ubuntu',
    'rhel': 'rhel',
    'centos': 'centos',
    'amazonlinux': 'amazon-linux',
    'debian': 'debian',
    'fedora': 'fedora',
    'alpine': 'alpine',
    
    # Frameworks
    'django': 'django',
    'flask': 'flask',
    'spring': 'spring-framework',
    'rails': 'rails',
    'angular': 'angular',
    'react': 'react',
    'vue': 'vue',
    
    # Other
    'kubernetes': 'kubernetes',
    'k8s': 'kubernetes',
    'openssl': 'openssl',
    'openssh': 'openssh',
}


def normalize_product_name(name: str) -> str:
    """
    Normalize product name for endoflife.date API
    
    Args:
        name: Product name from CPE or other source
    
    Returns:
        Normalized product name for API lookup
    """
    if not name:
        return None
    
    normalized = name.lower().strip()
    return PRODUCT_NAME_MAPPING.get(normalized, normalized)


def parse_cpe_string(cpe: str) -> Optional[Dict[str, str]]:
    """
    Parse CPE string to extract product information
    
    CPE Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    Example: cpe:2.3:a:linuxfoundation:runc:1.1.0:*:*:*:*:*:*:*
    
    Args:
        cpe: CPE string
    
    Returns:
        Dictionary with vendor, product, version, or None if parsing fails
    """
    try:
        parts = cpe.split(':')
        if len(parts) < 6:
            return None
        
        # parts[0] = 'cpe'
        # parts[1] = '2.3'
        # parts[2] = part (a=application, h=hardware, o=os)
        # parts[3] = vendor
        # parts[4] = product
        # parts[5] = version
        
        vendor = parts[3] if parts[3] != '*' else None
        product = parts[4] if parts[4] != '*' else None
        version = parts[5] if parts[5] != '*' else None
        
        if not product:
            return None
        
        return {
            'vendor': vendor,
            'product': product,
            'version': version,
            'cpe_part': parts[2]  # a, h, or o
        }
    except Exception as e:
        logger.warning(f"Failed to parse CPE: {cpe}, error: {e}")
        return None


def extract_products_from_cpe_list(cpe_refs: List[str]) -> List[Dict[str, Any]]:
    """
    Extract unique product information from list of CPE references
    
    Args:
        cpe_refs: List of CPE strings
    
    Returns:
        List of unique product dictionaries
    """
    products = []
    seen = set()
    
    for cpe in cpe_refs:
        parsed = parse_cpe_string(cpe)
        if not parsed:
            continue
        
        # Create unique key (vendor:product:version)
        key = f"{parsed.get('vendor', '')}:{parsed['product']}:{parsed.get('version', '')}"
        
        if key not in seen:
            seen.add(key)
            products.append({
                'vendor': parsed.get('vendor'),
                'name': parsed['product'],
                'version': parsed.get('version'),
                'product_family': None,  # Not available in CPE
                'cpe_part': parsed.get('cpe_part')
            })
    
    logger.info(f"Extracted {len(products)} unique products from {len(cpe_refs)} CPE references")
    return products


async def fetch_product_lifecycle(product_name: str) -> Optional[List[Dict[str, Any]]]:
    """
    Fetch product lifecycle data from endoflife.date API
    
    Args:
        product_name: Product name (normalized)
    
    Returns:
        List of release cycles with EOL dates, or None if not found
    
    Example response:
    [
        {
            "cycle": "3.12",
            "releaseDate": "2023-10-02",
            "eol": "2028-10-02",
            "latest": "3.12.1",
            "lts": false,
            "support": "2028-04-02"
        }
    ]
    """
    try:
        normalized_name = normalize_product_name(product_name)
        if not normalized_name:
            return None
        
        url = f"https://endoflife.date/api/{normalized_name}.json"
        logger.info(f"Fetching lifecycle data for {product_name} (normalized: {normalized_name})")
        
        response = await get(url)
        
        if response and isinstance(response, list):
            logger.info(f"Found {len(response)} release cycles for {product_name}")
            return response
        else:
            logger.warning(f"No lifecycle data found for {product_name}")
            return None
            
    except Exception as e:
        logger.warning(f"Failed to fetch lifecycle data for {product_name}: {e}")
        return None


async def fetch_package_dependencies(package_name: str, ecosystem: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch package dependencies from Libraries.io API
    
    Args:
        package_name: Package name
        ecosystem: Package ecosystem (e.g., 'pypi', 'npm', 'go')
        api_key: Libraries.io API key (optional, but recommended)
    
    Returns:
        Dictionary with dependency information, or None if not found
    
    Example response:
    {
        "name": "django",
        "platform": "Pypi",
        "dependencies": [
            {
                "name": "asgiref",
                "requirements": ">=3.6.0,<4",
                "kind": "runtime"
            }
        ]
    }
    """
    try:
        # Normalize ecosystem name for Libraries.io
        ecosystem_map = {
            'pypi': 'Pypi',
            'npm': 'NPM',
            'go': 'Go',
            'maven': 'Maven',
            'nuget': 'NuGet',
            'rubygems': 'Rubygems',
            'cargo': 'Cargo'
        }
        
        platform = ecosystem_map.get(ecosystem.lower(), ecosystem)
        
        # Build URL
        url = f"https://libraries.io/api/{platform}/{package_name}/dependencies"
        if api_key:
            url += f"?api_key={api_key}"
        
        logger.info(f"Fetching dependencies for {package_name} ({platform})")
        
        response = await get(url)
        
        if response:
            logger.info(f"Found dependencies for {package_name}")
            return response
        else:
            logger.warning(f"No dependencies found for {package_name}")
            return None
            
    except Exception as e:
        logger.warning(f"Failed to fetch dependencies for {package_name}: {e}")
        return None


def parse_version_string(version_str: str) -> Dict[str, Optional[int]]:
    """
    Parse version string into major, minor, patch components
    
    Args:
        version_str: Version string (e.g., "3.12.1", "1.1.0")
    
    Returns:
        Dictionary with major, minor, patch version numbers
    """
    try:
        # Remove any non-numeric prefixes (e.g., 'v3.12.1' -> '3.12.1')
        clean_version = version_str.lstrip('v').strip()
        
        parts = clean_version.split('.')
        
        return {
            'major': int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else None,
            'minor': int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
            'patch': int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
        }
    except Exception as e:
        logger.warning(f"Failed to parse version string: {version_str}, error: {e}")
        return {'major': None, 'minor': None, 'patch': None}


def parse_lifecycle_date(date_str: str) -> Optional[datetime]:
    """
    Parse date string from endoflife.date API
    
    Args:
        date_str: Date string in ISO format or boolean
    
    Returns:
        datetime object or None
    """
    try:
        if not date_str or date_str is True or date_str is False:
            return None
        
        # Handle ISO date format
        if isinstance(date_str, str):
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        
        return None
    except Exception as e:
        logger.warning(f"Failed to parse date: {date_str}, error: {e}")
        return None


async def enrich_product_with_lifecycle(product_name: str) -> Optional[Dict[str, Any]]:
    """
    Enrich product with lifecycle data from endoflife.date
    
    Args:
        product_name: Product name
    
    Returns:
        Dictionary with enriched product data including releases
    """
    lifecycle_data = await fetch_product_lifecycle(product_name)
    
    if not lifecycle_data:
        return None
    
    # Extract overall product info from first release
    first_release = lifecycle_data[0] if lifecycle_data else {}
    
    enriched = {
        'product_name': product_name,
        'has_lifecycle_data': True,
        'total_releases': len(lifecycle_data),
        'releases': []
    }
    
    # Process each release cycle
    for release in lifecycle_data:
        cycle = release.get('cycle', '')
        version_parts = parse_version_string(str(cycle))
        
        release_info = {
            'cycle': cycle,
            'full_version': [str(cycle)],
            'major_version': version_parts['major'],
            'minor_version': version_parts['minor'],
            'patch_version': version_parts['patch'],
            'release_date': parse_lifecycle_date(release.get('releaseDate')),
            'eol_date': parse_lifecycle_date(release.get('eol')),
            'extended_support': release.get('lts', False) or release.get('extendedSupport', False),
            'latest_version': release.get('latest'),
            'support_end_date': parse_lifecycle_date(release.get('support'))
        }
        
        enriched['releases'].append(release_info)
    
    return enriched

# Made with Bob
