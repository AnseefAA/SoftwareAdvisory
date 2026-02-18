import json
import logging
from math import ceil
import os
from typing import Dict, List, Any, Union, Optional
from app.authentication.authentication import fetch_concert_access_token
from app.core.constants import UPLOAD_FILE_PATH
from app.exception import exceptions
import app.models as Models
from fastapi import  File, UploadFile
from app.utils import fileutil
from app.utils.fileutil import dir_creator, file_loader, file_writer, get_absolute_file_path, get_absolute_path, get_filename_without_exstension, read_file
from app.utils.httputil import get, post
from app.utils.severity_calculator import calculate_cvss_score, calculate_severity_from_range, parse_cvss_vector
import re

def generate_openapi_examples(models: dict):
    """
    Dynamically generate one openapi example per model entry.
    """
    examples = {}
    for model_id in models:
        examples[model_id] = {
            "summary": f"{model_id}",
            "description": f"{model_id}",
            "value": {
                "cveId": "CVE-2022-4304",
                "modelId": f"{model_id}"
            }
        }
    return examples

async def fetch_vulnerability(id: str, filepath: str) -> dict:
    """
    Fetches vulnerability details by VulnerabilityID from a JSON file.

    Args:
        file_path (str): Path to the JSON file.
        id (str): ID of the vulnerability to fetch.

    Returns:
        dict: Extracted details including ArtifactName, ArtifactType, OSFamily, OSVersion, Target, and vulnerability info.
    """
    try:
        data = read_file(filepath, json.loads)

        # Extract basic artifact details
        artifact_name = data.get("ArtifactName", "N/A")
        artifact_type = data.get("ArtifactType", "N/A")
        os_family = data.get("Metadata", {}).get("OS", {}).get("Family", "N/A")
        os_version = data.get("Metadata", {}).get("OS", {}).get("Name", "N/A")

        # Search for the specific vulnerability ID
        results = data.get("Results", [])
        for result in results:
            target = result.get("Target", "N/A")
            for vulnerability in result.get("Vulnerabilities", []):
                if vulnerability.get("VulnerabilityID") == id:
                    return {
                        "ArtifactName": artifact_name,
                        "ContainerName": artifact_name,
                        "ArtifactType": artifact_type,
                        "OSFamily": os_family,
                        "OSVersion": os_version,
                        "Target": target,
                        "VulnerabilityInfo": vulnerability
                    }
                
        return await get_cve_info_from_osv_vul_info(id)
    except Exception as e:
        raise e

async def fetch_vendor_advisory(advisory_id: str, filepath: str) -> dict:
    """
    Fetches vendor advisory details from a CSAF format JSON file or Red Hat API.
    First tries to read from the uploaded file, then falls back to Red Hat's API.

    Args:
        advisory_id (str): Advisory ID (e.g., RHSA-2024:11525)
        filepath (str): Path to the advisory JSON file.

    Returns:
        dict: Advisory details including title, severity, CVEs, and mitigation info.
    """
    try:
        # Try to read from file first
        try:
            data = read_file(filepath, json.loads)
            logging.info(f"Advisory {advisory_id} found in file: {filepath}")
        except FileNotFoundError:
            # File not found, try fetching from Red Hat API
            logging.info(f"Advisory {advisory_id} not found in file, fetching from Red Hat API")
            data = await fetch_advisory_from_redhat_api(advisory_id)
        
        # Parse the CSAF format data
        return parse_csaf_advisory(data, advisory_id)
        
    except Exception as e:
        logging.error(f"Error fetching advisory {advisory_id}: {str(e)}")
        raise e


async def fetch_advisory_from_redhat_api(advisory_id: str) -> dict:
    """
    Fetches advisory data from Red Hat's Security Data API.
    
    Args:
        advisory_id (str): Advisory ID (e.g., RHSA-2024:11525)
    
    Returns:
        dict: CSAF format advisory data
    """
    try:
        # Red Hat Security Data API endpoint
        # Format: https://access.redhat.com/hydra/rest/securitydata/csaf/rhsa-2024-11525.json
        advisory_id_formatted = advisory_id.lower().replace(":", "-")
        url = f"https://access.redhat.com/hydra/rest/securitydata/csaf/{advisory_id_formatted}.json"
        
        logging.info(f"Fetching advisory from Red Hat API: {url}")
        data = await get(url, timeout=30)
        
        if not data:
            raise ValueError(f"No data returned from Red Hat API for {advisory_id}")
        
        logging.info(f"Successfully fetched advisory {advisory_id} from Red Hat API")
        return data
        
    except Exception as e:
        logging.error(f"Error fetching advisory from Red Hat API: {str(e)}")
        raise ValueError(f"Advisory {advisory_id} not found in file or Red Hat API")


def parse_csaf_advisory(data: dict, advisory_id: str) -> dict:
    """
    Parses CSAF format advisory data into a structured format.
    
    Args:
        data (dict): CSAF format advisory data
        advisory_id (str): Advisory ID
    
    Returns:
        dict: Parsed advisory information
    """
    # Extract document information
    document = data.get("document", {})
    tracking = document.get("tracking", {})
    
    # Extract advisory metadata
    advisory_info = {
        "advisory_id": tracking.get("id", advisory_id),
        "title": document.get("title", "N/A"),
        "severity": document.get("aggregate_severity", {}).get("text", "N/A"),
        "release_date": tracking.get("current_release_date", "N/A"),
        "status": tracking.get("status", "N/A"),
    }
    
    # Extract CVEs from vulnerabilities section
    vulnerabilities = data.get("vulnerabilities", [])
    cves_info = []
    
    for vuln in vulnerabilities:
        cve_id = vuln.get("cve", "")
        title = vuln.get("title", "")
        
        # Get CVSS score and severity
        scores = vuln.get("scores", [])
        cvss_score = 0.0
        cvss_vector = ""
        severity = "UNKNOWN"
        
        if scores:
            cvss_v3 = scores[0].get("cvss_v3", {})
            cvss_score = cvss_v3.get("baseScore", 0.0)
            cvss_vector = cvss_v3.get("vectorString", "")
            severity = cvss_v3.get("baseSeverity", "UNKNOWN")
        
        # Get description from notes
        description = ""
        notes = vuln.get("notes", [])
        for note in notes:
            if note.get("category") == "description":
                description = note.get("text", "")
                break
        
        # Get remediation info
        remediations = vuln.get("remediations", [])
        remediation_details = []
        for remediation in remediations:
            if remediation.get("category") == "vendor_fix":
                remediation_details.append({
                    "details": remediation.get("details", ""),
                    "url": remediation.get("url", "")
                })
        
        cves_info.append({
            "cve_id": cve_id,
            "title": title,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "description": description,
            "remediations": remediation_details
        })
    
    advisory_info["cves"] = cves_info
    advisory_info["total_cves"] = len(cves_info)
    
    # Extract general notes
    notes = document.get("notes", [])
    for note in notes:
        if note.get("category") == "general":
            advisory_info["details"] = note.get("text", "")
            break
    
    return advisory_info


parent_folder = "data"

async def upload_file_helper(uploaded_file: UploadFile = File(...)):
    sub_folder = get_filename_without_exstension(uploaded_file.filename)
    
    sub_folder_path = get_absolute_file_path(parent_folder,sub_folder)
    
    dir_creator(sub_folder_path)
    
    file_path = get_absolute_file_path(sub_folder_path,uploaded_file.filename)

    await file_writer(file_path,await uploaded_file.read())
    

async def search_vulnerability(search_query: str, filename: str) -> List[Models.VulnerabilityInfo]:
    try:
        file_path = get_complete_path(filename)

        vulerabilities = []
        if fileutil.check_file_exists(file_path):
            logging.error(f"File exist: {filename}")

            data = file_loader(file_path)

            vulnerabilities = search_validation(data, search_query, filename)
            if vulnerabilities:
                logging.error(f"vulnerabilities exist")
                top_vulnerabilities = fetch_top_vulnerabilities(vulnerabilities, 20)
                return top_vulnerabilities

        logging.info("Fetching vulnerabilities from OSV API.")
        vul = await get_cve_info_from_osv_vul_info(search_query)
        vulerabilities.append(vul)
        return vulerabilities
    except Exception as e:
        logging.error(f"Unexpected error during search_vulnerability: {e}")
        raise e

 
def search_validation(data: Dict[str,Any],search_query: str, filename: str) -> List[Models.VulnerabilityInfo]:
    vulnerabilities = []
    try:
        for result in data.get("Results", []):
            try:
                for vulnerability in result.get("Vulnerabilities", []): 
                    if search_query in vulnerability["VulnerabilityID"] or search_query in vulnerability["Severity"]:
                        vulnerability_info = parse_vulnerablity(vulnerability,filename)
                        vulnerabilities.append(vulnerability_info)
            except Exception :
                    logging.error(f"Unexpected error in search_vulnerability: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in search_vulnerability: {e}")
    return vulnerabilities
        
 
def get_vulnerabilities( filename: str,)-> List[Models.VulnerabilityInfo]:
    file_path = get_complete_path(filename)
    
    data = file_loader(file_path) 

    vulnerabilities = fetch_all_vulnerability(data,filename)

    top_vulnerabilities = fetch_top_vulnerabilities(vulnerabilities,20)
    
    return top_vulnerabilities

def get_complete_path(filename : str) -> str: 
    sub_folder = get_filename_without_exstension(filename)
    
    sub_folder_path = get_absolute_file_path(parent_folder,sub_folder)
    
    file_path = get_absolute_file_path(sub_folder_path,filename)
    
    return file_path

def fetch_all_vulnerability(data: Dict[str,Any], filename: str)-> List[Models.VulnerabilityInfo]:
    vulnerabilities = []
    cve_id_list = []
    try:
        for result in data.get("Results", []):
            try:
                for vulnerability in result.get("Vulnerabilities", []):
                        vulnerability_info = parse_vulnerablity(vulnerability,filename)
                        if vulnerability_info.id not in cve_id_list:
                            vulnerabilities.append(vulnerability_info)
                            cve_id_list.append(vulnerability_info.id)
            except Exception :
                    logging.error(f"Unexpected error in fetch_all_vulnerability: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in fetch_all_vulnerability: {e}")
    return vulnerabilities
   


def  parse_vulnerablity(vulnerability: Dict[str,Any], filename: str) -> Models.VulnerabilityInfo:
    try:
        vulnerability_id = vulnerability["VulnerabilityID"]
        new_vulnerability = Models.VulnerabilityInfo(
            id=vulnerability_id,
            title=vulnerability["VulnerabilityID"],
            description=vulnerability["Description"],
            severity=vulnerability["Severity"],
            score=get_vulnerability_score(vulnerability.get("CVSS", {})),
            fileName=filename,
            lastModifiedDate=vulnerability["LastModifiedDate"]
            )
        return new_vulnerability
    except Exception as e:
            logging.error(f"Unexpected error in parse_vulnerability: of id {vulnerability_id}: {e}")

def fetch_top_vulnerabilities(vulnerabilities : List[Models.VulnerabilityInfo],limit: int) -> List[Models.VulnerabilityInfo]:
    new_vulnerabilities_list = []
    new_vulnerabilities_list = sorted(
        vulnerabilities, key=lambda v: v.score, reverse=True
    )[:limit]
    
    return new_vulnerabilities_list
   
def get_vulnerability_score(vulnerability: Dict[str,Any]) -> Union[int, float]:
    return (
        vulnerability.get("nvd", {}).get("V3Score", 0)
        or vulnerability.get("ghsa", {}).get("V3Score", 0)  
    )

def trim_triple_backticks(s):
    # Remove leading \n if present
    if s.startswith("\n"):
        s = s[1:]
    
    # Check if the string starts with ``` and ends with ```
    if s.lstrip().startswith("```") and s.rstrip().endswith("```"):
        # Strip the leading/trailing backticks and any surrounding whitespace
        trimmed = s.lstrip()[3:].rstrip()  # Remove the leading ```
        return trimmed[: -3].strip() if trimmed.endswith("```") else s
    
    return s
    
async def get_cve_info_from_osv_cve_info(cve_id : str) -> Models.CVEInfo:
    try:
        vulnerability =await get_cve_json_data(cve_id)
        validate_vulnerability_id(vulnerability)
        
        inputs = parse_cvss_vector(vulnerability.get("severity", [{}])[0].get("score",""))
        severity_score = 0
        severity = ""
        if inputs:  
            severity_score = calculate_cvss_score(**inputs)
            severity = calculate_severity_from_range(severity_score)
        
        new_cve = parse_cve_info(vulnerability,severity_score,severity)
        
        return new_cve
    except Exception as e:
        logging.error(f"Unexpected error in parse_vulnerability: {e}")
        raise e
            
def parse_cve_info(vulnerability: Dict , severity_score: float, severity: str) -> Models.CVEInfo:  
    new_cve = Models.CVEInfo(
            cve=vulnerability["id"],
            cvss=severity_score,
            severity=severity,
            vector=vulnerability.get("vector",""),
            description=vulnerability.get("details",""),
            related_cves=vulnerability.get("related",[]) ,
            aliases=vulnerability.get("aliases",[])
            )
    
    return new_cve

async def  get_cve_info_from_osv_vul_info(cve_id : str) -> Models.VulnerabilityInfo:
    try:
        cve_json_data =await  get_cve_json_data(cve_id)
        validate_vulnerability_id(cve_json_data)

        inputs = parse_cvss_vector(cve_json_data.get("severity", [{}])[0].get("score",""))
        severity_score = 0
        severity = ""
        if inputs: 
            severity_score = calculate_cvss_score(**inputs)
            severity = calculate_severity_from_range(severity_score)

        new_vulnerability = parse_vul_info(cve_json_data,severity_score,severity)
        return new_vulnerability
    except Exception as e:
            logging.error(f"Unexpected error in parse_vulnerability: of id {cve_id}: {e}")
            raise e
            
def parse_vul_info(vulnerability: Dict , severity_score: float, severity: str) -> Models.VulnerabilityInfo: 
    new_vulnerability = Models.VulnerabilityInfo(
            id=vulnerability["id"],
            title=vulnerability["id"],
            description=vulnerability["details"],
            severity=severity,
            score=severity_score,
            fileName="EXTERNAL_OSV_API",
            lastModifiedDate=vulnerability["modified"]
            )
    
    return new_vulnerability

async def get_cve_json_data(cve_id : str) -> Dict:
    url = get_osv_url(cve_id)

    try:
        json_data =await get(url,timeout = 20)
        return json_data
        
    except Exception as e:
        raise e
    
def get_osv_url(vul_id: str) -> str :
    base_url = os.getenv('OSV_API_BASE_URL')
    url = f"{base_url}/v1/vulns/{vul_id}"
    return url
            
def validate_vulnerability_id(vulnerability: Dict):
    vulnerability_id = vulnerability.get("id", None)
    if vulnerability_id is None:
        raise ValueError("Emmpty vulnerability data")
      
            
def get_osv_url(vul_id: str) -> str :
    base_url = os.getenv('OSV_API_BASE_URL')
    url = f"{base_url}/v1/vulns/{vul_id}"
    return url
        

# async def vm_endpoint(cve_id : str) -> Dict:
#     # TODO Restructure
#     headers = await generate_concert_headers()
    
#     url = f"https://sk1.fyre.ibm.com:12443/core/api/v1/vulnerability/cves/{cve_id}"
#     try:
#         response = await get(url, headers=headers , timeout = 30)
#         return response
#     except Exception as e:
#         logging.error(f"Unexpected error : of id {cve_id}: {e}")
        
async def upload_cve_context(cve_request: Models.CVERequest) -> Dict:
    # TODO Restructure
    
    headers = await generate_concert_headers()
    
    payload = {
        "context": cve_request.context,
    }
    
    url = f"https://sk1.fyre.ibm.com:12443/py-utils/v1/cve/mitigation"
    
    try:
        response = await post(url,payload = payload, headers=headers , timeout = 30)
        # return await parse_cve_response(response)
        return response
    except Exception as e:
        logging.error(f"Unexpected error :{e}")

async def generate_concert_headers() -> Dict:
    token = await fetch_concert_access_token()
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "InstanceId": "0000-0000-0000-0000"
    }
        
async def fetch_projects_metadata() -> List[Models.ProjectMetadata]:
    file_metadata = []
    for filename in os.listdir(UPLOAD_FILE_PATH):
        file_path = os.path.join(UPLOAD_FILE_PATH, filename)
        if os.path.isdir(file_path): 
            file_metadata.append(Models.ProjectMetadata(name=filename, filename=f"{filename}.json"))
    return file_metadata

async def update_feedback(action: Models.FeedbackAction, cached_response: str) -> Models.Feedback:
    try:
        vulnerability_response = Models.Feedback(**json.loads(cached_response))

        if action == Models.FeedbackAction.LIKE:
            vulnerability_response.likeCount += 1
        
        if action == Models.FeedbackAction.DISLIKE:
            vulnerability_response.dislikeCount += 1
        
        return vulnerability_response
    except Exception as e:
        raise e
    
async def fetch_project_impression(subdir: str,project_name: str) -> Models.ProjectFeedbackResponse:
    try:
        abs_path = await get_abs_path_subdir(subdir,project_name)
        
        like_count = 0
        dislike_count = 0
        
        for filename in os.listdir(abs_path):
            if filename.endswith("-response.txt"):
                with open(os.path.join(abs_path, filename), "r") as f:
                    vulnerability_response = Models.Feedback(**json.load(f))
                    like_count += vulnerability_response.likeCount
                    dislike_count += vulnerability_response.dislikeCount
                    
        return Models.ProjectFeedbackResponse(project_name=project_name, likeCount=like_count, dislikeCount=dislike_count)
    except Exception as e: 
        raise e
    
async def get_abs_path_subdir(subdir: str,project_name: str) -> str:
    base_path = os.path.splitext(os.path.basename(project_name))[0]
    return get_absolute_path(f"app/data/{base_path}/{subdir}" if subdir else f"app/data/{base_path}")

def extract_code_as_string(markup_text):
    """
    Extracts all code blocks from a given markup text and returns them as a single concatenated string.
    
    Parameters:
        markup_text (str): The text containing code blocks.
    
    Returns:
        str: A concatenated string of all extracted code blocks.
    """
    # Regular expression to match code blocks with or without a language specifier
    pattern = r"```(?:\w+)?\s*(.*?)```"

    # Extract code blocks using regex with re.DOTALL for multiline matching
    code_blocks = re.findall(pattern, markup_text, re.DOTALL)

    return "\n\n".join(code_blocks).strip()  # Joining with double newlines for readability

async def parse_enhanced_vulnerability(vulnerability: Dict[str, Any], filename: str, 
                                      artifact_name: str = "N/A", 
                                      os_family: str = "N/A") -> Models.EnhancedVulnerabilityInfo:
    """
    Parse vulnerability data into enhanced format with comprehensive context.
    
    Args:
        vulnerability: Vulnerability data from Trivy scan
        filename: Source filename
        artifact_name: Container/artifact name
        os_family: Operating system family
    
    Returns:
        EnhancedVulnerabilityInfo with all context
    """
    try:
        vulnerability_id = vulnerability.get("VulnerabilityID", "")
        
        # Parse CVE information
        cve = Models.EnhancedCVE(
            cve_id=vulnerability_id,
            description=vulnerability.get("Description", ""),
            severity=vulnerability.get("Severity", "UNKNOWN"),
            cvss_score=get_vulnerability_score(vulnerability.get("CVSS", {})),
            kev_listed=False,  # TODO: Check against CISA KEV catalog
            exploit_maturity=None  # TODO: Check exploit databases
        )
        
        # Parse Asset information
        asset = Models.Asset(
            asset_id=artifact_name,
            hostname=artifact_name,
            environment=None,  # Can be enriched from external source
            business_tier=None,  # Can be enriched from external source
            internet_exposed=False  # Can be enriched from external source
        )
        
        # Parse Product information
        product = Models.Product(
            product_name=vulnerability.get("PkgName", ""),
            version=vulnerability.get("InstalledVersion", ""),
            vendor=os_family if os_family != "N/A" else None,
            release_date=vulnerability.get("PublishedDate", None)
        )
        
        # Parse Application Certification (if available)
        app_certification = Models.ApplicationCertification(
            app_id=None,
            product=vulnerability.get("PkgName", ""),
            supported_versions=[vulnerability.get("FixedVersion", "")] if vulnerability.get("FixedVersion") else [],
            certification_status=None
        )
        
        # Parse Dependency information
        dependency = Models.Dependency(
            parent_component=None,  # Can be enriched from dependency tree
            dependency_component=vulnerability.get("PkgName", ""),
            depth=0  # Can be enriched from dependency tree
        )
        
        # Parse Policy information (based on severity)
        policy = Models.Policy(
            policy_id=None,
            rule_type="CVE Severity",
            threshold=vulnerability.get("Severity", "UNKNOWN")
        )
        
        # Create enhanced vulnerability info
        enhanced_vuln = Models.EnhancedVulnerabilityInfo(
            cve=cve,
            asset=asset,
            product=product,
            app_certification=app_certification,
            dependency=dependency,
            policy=policy,
            file_name=filename,
            last_modified_date=vulnerability.get("LastModifiedDate", None),
            published_date=vulnerability.get("PublishedDate", None),
            fixed_version=vulnerability.get("FixedVersion", None),
            references=vulnerability.get("References", [])
        )
        
        return enhanced_vuln
        
    except Exception as e:
        logging.error(f"Error parsing enhanced vulnerability {vulnerability_id}: {str(e)}")
        raise e


async def fetch_enhanced_vulnerabilities(filename: str) -> Models.EnhancedVulnerabilityResponse:
    """
    Fetch and parse all vulnerabilities from a file with enhanced context.
    Supports both Trivy scan format and CSAF (Red Hat Advisory) format.
    
    Args:
        filename: Name of the vulnerability scan file
    
    Returns:
        EnhancedVulnerabilityResponse with comprehensive data
    """
    try:
        file_path = get_complete_path(filename)
        data = file_loader(file_path)
        
        # Detect file format
        is_csaf = "document" in data and "vulnerabilities" in data
        is_trivy = "Results" in data or "ArtifactName" in data
        
        enhanced_vulnerabilities = []
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        kev_count = 0
        
        if is_csaf:
            # Parse CSAF format (Red Hat Advisory)
            logging.info(f"Detected CSAF format for {filename}")
            enhanced_vulnerabilities = await parse_csaf_to_enhanced(data, filename)
        elif is_trivy:
            # Parse Trivy format
            logging.info(f"Detected Trivy format for {filename}")
            artifact_name = data.get("ArtifactName", "N/A")
            os_family = data.get("Metadata", {}).get("OS", {}).get("Family", "N/A")
            
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    enhanced_vuln = await parse_enhanced_vulnerability(
                        vuln, filename, artifact_name, os_family
                    )
                    enhanced_vulnerabilities.append(enhanced_vuln)
        else:
            raise ValueError(f"Unknown file format for {filename}. Expected Trivy or CSAF format.")
        
        # Count by severity
        for enhanced_vuln in enhanced_vulnerabilities:
            severity = enhanced_vuln.cve.severity.upper()
            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            elif severity == "LOW":
                low_count += 1
            
            # Count KEV
            if enhanced_vuln.cve.kev_listed:
                kev_count += 1
        
        return Models.EnhancedVulnerabilityResponse(
            vulnerabilities=enhanced_vulnerabilities,
            total_count=len(enhanced_vulnerabilities),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            kev_count=kev_count
        )
        
    except Exception as e:
        logging.error(f"Error fetching enhanced vulnerabilities: {str(e)}")
        raise e


async def parse_csaf_to_enhanced(data: dict, filename: str) -> List[Models.EnhancedVulnerabilityInfo]:
    """
    Parse CSAF format advisory into enhanced vulnerability format.
    
    Args:
        data: CSAF format data
        filename: Source filename
    
    Returns:
        List of EnhancedVulnerabilityInfo
    """
    enhanced_vulnerabilities = []
    
    try:
        # Extract document metadata
        document = data.get("document", {})
        tracking = document.get("tracking", {})
        advisory_id = tracking.get("id", "N/A")
        advisory_severity = document.get("aggregate_severity", {}).get("text", "UNKNOWN")
        
        # Extract vulnerabilities
        vulnerabilities = data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve", "")
            if not cve_id:
                continue
            
            # Get CVSS score and severity
            scores = vuln.get("scores", [])
            cvss_score = 0.0
            cvss_vector = ""
            severity = advisory_severity
            
            if scores:
                cvss_v3 = scores[0].get("cvss_v3", {})
                cvss_score = cvss_v3.get("baseScore", 0.0)
                cvss_vector = cvss_v3.get("vectorString", "")
                severity = cvss_v3.get("baseSeverity", advisory_severity)
            
            # Get description
            description = ""
            notes = vuln.get("notes", [])
            for note in notes:
                if note.get("category") == "description":
                    description = note.get("text", "")
                    break
            
            # Get product information from product_status
            product_name = "N/A"
            product_version = "N/A"
            fixed_version = None
            
            product_status = vuln.get("product_status", {})
            if "fixed" in product_status and product_status["fixed"]:
                fixed_version = product_status["fixed"][0] if isinstance(product_status["fixed"], list) else str(product_status["fixed"])
            
            # Get remediation info
            remediations = vuln.get("remediations", [])
            references = []
            for remediation in remediations:
                if remediation.get("url"):
                    references.append(remediation["url"])
            
            # Create enhanced CVE
            cve = Models.EnhancedCVE(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                kev_listed=False,  # TODO: Check against CISA KEV
                exploit_maturity=None
            )
            
            # Create asset (advisory-level)
            asset = Models.Asset(
                asset_id=advisory_id,
                hostname=advisory_id,
                environment=None,
                business_tier=None,
                internet_exposed=False
            )
            
            # Create product
            product = Models.Product(
                product_name=product_name,
                version=product_version,
                vendor="Red Hat",
                release_date=tracking.get("current_release_date", None)
            )
            
            # Create app certification
            app_certification = Models.ApplicationCertification(
                app_id=advisory_id,
                product=product_name,
                supported_versions=[fixed_version] if fixed_version else [],
                certification_status="Red Hat Certified"
            )
            
            # Create dependency
            dependency = Models.Dependency(
                parent_component=None,
                dependency_component=product_name,
                depth=0
            )
            
            # Create policy
            policy = Models.Policy(
                policy_id=advisory_id,
                rule_type="Advisory Severity",
                threshold=severity
            )
            
            # Create enhanced vulnerability info
            enhanced_vuln = Models.EnhancedVulnerabilityInfo(
                cve=cve,
                asset=asset,
                product=product,
                app_certification=app_certification,
                dependency=dependency,
                policy=policy,
                file_name=filename,
                last_modified_date=tracking.get("current_release_date", None),
                published_date=tracking.get("initial_release_date", None),
                fixed_version=fixed_version,
                references=references
            )
            
            enhanced_vulnerabilities.append(enhanced_vuln)
        
        return enhanced_vulnerabilities
        
    except Exception as e:
        logging.error(f"Error parsing CSAF to enhanced format: {str(e)}")
        raise e

# ============================================================================
# Multi-Source CVE Intelligence Aggregator
# ============================================================================

async def fetch_nvd_cve_data(cve_id: str) -> Dict[str, Any]:
    """
    Fetch CVE data from NVD (National Vulnerability Database) API v2.0
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2022-4304)
    
    Returns:
        dict: NVD CVE data including CVSS, CWE, references, configurations
    """
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        logging.info(f"Fetching CVE data from NVD: {url}")
        
        data = await get(url, timeout=30)
        
        if data and "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
            vuln_data = data["vulnerabilities"][0]["cve"]
            logging.info(f"Successfully fetched {cve_id} from NVD")
            return vuln_data
        else:
            logging.warning(f"No data found for {cve_id} in NVD")
            return {}
            
    except Exception as e:
        logging.error(f"Error fetching from NVD: {str(e)}")
        return {}


async def fetch_mitre_cve_data(cve_id: str) -> Dict[str, Any]:
    """
    Fetch CVE data from MITRE CVE AWG API
    
    Args:
        cve_id: CVE identifier
    
    Returns:
        dict: MITRE CVE data including CNA information, affected products
    """
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        logging.info(f"Fetching CVE data from MITRE: {url}")
        
        data = await get(url, timeout=30)
        
        if data:
            logging.info(f"Successfully fetched {cve_id} from MITRE")
            return data
        else:
            logging.warning(f"No data found for {cve_id} in MITRE")
            return {}
            
    except Exception as e:
        logging.error(f"Error fetching from MITRE: {str(e)}")
        return {}


async def fetch_github_cve_data(cve_id: str) -> Dict[str, Any]:
    """
    Fetch CVE data from GitHub CVEProject repository
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2022-4304)
    
    Returns:
        dict: GitHub CVE data from cvelistV5
    """
    try:
        # Parse CVE ID to construct GitHub path
        # Format: CVE-YYYY-NNNNN -> cves/YYYY/NNNNxxx/CVE-YYYY-NNNNN.json
        parts = cve_id.split("-")
        if len(parts) != 3:
            logging.error(f"Invalid CVE ID format: {cve_id}")
            return {}
        
        year = parts[1]
        number = parts[2]
        
        # Determine the xxx directory (e.g., 4304 -> 4xxx)
        if len(number) >= 4:
            dir_suffix = number[:-3] + "xxx"
        else:
            dir_suffix = "0xxx"
        
        url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{dir_suffix}/{cve_id}.json"
        logging.info(f"Fetching CVE data from GitHub: {url}")
        
        data = await get(url, timeout=30)
        
        if data:
            logging.info(f"Successfully fetched {cve_id} from GitHub CVE Project")
            return data
        else:
            logging.warning(f"No data found for {cve_id} in GitHub CVE Project")
            return {}
            
    except Exception as e:
        logging.error(f"Error fetching from GitHub CVE Project: {str(e)}")
        return {}


async def aggregate_cve_intelligence(cve_id: str) -> Dict[str, Any]:
    """
    Aggregate CVE intelligence from multiple authoritative sources:
    - NVD (National Vulnerability Database)
    - MITRE CVE AWG
    - GitHub CVE Project
    - OSV.dev (existing)
    
    Args:
        cve_id: CVE identifier
    
    Returns:
        dict: Comprehensive CVE intelligence from all sources
    """
    try:
        logging.info(f"Starting intelligence aggregation for {cve_id}")
        
        # Fetch from all sources concurrently
        import asyncio
        nvd_data, mitre_data, github_data, osv_data = await asyncio.gather(
            fetch_nvd_cve_data(cve_id),
            fetch_mitre_cve_data(cve_id),
            fetch_github_cve_data(cve_id),
            get_cve_json_data(cve_id),
            return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(nvd_data, Exception):
            logging.error(f"NVD fetch failed: {nvd_data}")
            nvd_data = {}
        if isinstance(mitre_data, Exception):
            logging.error(f"MITRE fetch failed: {mitre_data}")
            mitre_data = {}
        if isinstance(github_data, Exception):
            logging.error(f"GitHub fetch failed: {github_data}")
            github_data = {}
        if isinstance(osv_data, Exception):
            logging.error(f"OSV fetch failed: {osv_data}")
            osv_data = {}
        
        # Aggregate intelligence
        aggregated = {
            "cve_id": cve_id,
            "sources": {
                "nvd": nvd_data if nvd_data else None,
                "mitre": mitre_data if mitre_data else None,
                "github": github_data if github_data else None,
                "osv": osv_data if osv_data else None
            },
            "enriched_data": extract_enriched_intelligence(cve_id, nvd_data, mitre_data, github_data, osv_data)
        }
        
        logging.info(f"Intelligence aggregation complete for {cve_id}")
        return aggregated
        
    except Exception as e:
        logging.error(f"Error in intelligence aggregation: {str(e)}")
        return {"cve_id": cve_id, "error": str(e)}


def extract_enriched_intelligence(cve_id: str, nvd_data: Dict, mitre_data: Dict, 
                                  github_data: Dict, osv_data: Dict) -> Dict[str, Any]:
    """
    Extract and consolidate key intelligence from all sources
    
    Returns:
        dict: Enriched intelligence with actionable insights
    """
    enriched = {
        "cve_id": cve_id,
        "descriptions": [],
        "cvss_scores": {},
        "cwe_ids": [],
        "references": [],
        "affected_products": [],
        "exploit_info": {},
        "patch_info": {},
        "timeline": {}
    }
    
    # Extract from NVD
    if nvd_data:
        # Descriptions
        if "descriptions" in nvd_data:
            for desc in nvd_data["descriptions"]:
                if desc.get("lang") == "en":
                    enriched["descriptions"].append({
                        "source": "NVD",
                        "value": desc.get("value", "")
                    })
        
        # CVSS Scores
        if "metrics" in nvd_data:
            metrics = nvd_data["metrics"]
            if "cvssMetricV31" in metrics:
                for metric in metrics["cvssMetricV31"]:
                    cvss_data = metric.get("cvssData", {})
                    enriched["cvss_scores"]["v3.1"] = {
                        "score": cvss_data.get("baseScore"),
                        "severity": cvss_data.get("baseSeverity"),
                        "vector": cvss_data.get("vectorString"),
                        "source": metric.get("source", "NVD")
                    }
            if "cvssMetricV2" in metrics:
                for metric in metrics["cvssMetricV2"]:
                    cvss_data = metric.get("cvssData", {})
                    enriched["cvss_scores"]["v2.0"] = {
                        "score": cvss_data.get("baseScore"),
                        "severity": cvss_data.get("baseSeverity"),
                        "vector": cvss_data.get("vectorString")
                    }
        
        # CWE IDs
        if "weaknesses" in nvd_data:
            for weakness in nvd_data["weaknesses"]:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        enriched["cwe_ids"].append(desc.get("value"))
        
        # References
        if "references" in nvd_data:
            for ref in nvd_data["references"]:
                enriched["references"].append({
                    "url": ref.get("url"),
                    "source": ref.get("source"),
                    "tags": ref.get("tags", [])
                })
        
        # Timeline
        if "published" in nvd_data:
            enriched["timeline"]["published"] = nvd_data["published"]
        if "lastModified" in nvd_data:
            enriched["timeline"]["last_modified"] = nvd_data["lastModified"]
    
    # Extract from MITRE
    if mitre_data and "containers" in mitre_data:
        cna = mitre_data["containers"].get("cna", {})
        
        # Affected products
        if "affected" in cna:
            for affected in cna["affected"]:
                enriched["affected_products"].append({
                    "vendor": affected.get("vendor"),
                    "product": affected.get("product"),
                    "versions": affected.get("versions", [])
                })
        
        # Additional descriptions
        if "descriptions" in cna:
            for desc in cna["descriptions"]:
                if desc.get("lang") == "en":
                    enriched["descriptions"].append({
                        "source": "MITRE",
                        "value": desc.get("value", "")
                    })
    
    # Extract from GitHub
    if github_data and "containers" in github_data:
        cna = github_data["containers"].get("cna", {})
        
        # Problem types (CWE)
        if "problemTypes" in cna:
            for problem in cna["problemTypes"]:
                for desc in problem.get("descriptions", []):
                    if "cweId" in desc:
                        enriched["cwe_ids"].append(desc["cweId"])
    
    # Extract from OSV
    if osv_data:
        # Severity
        if "severity" in osv_data:
            for sev in osv_data["severity"]:
                if sev.get("type") == "CVSS_V3":
                    enriched["cvss_scores"]["osv_v3"] = {
                        "score": sev.get("score"),
                        "vector": sev.get("score")
                    }
        
        # Affected packages with fixed versions
        if "affected" in osv_data:
            for affected in osv_data["affected"]:
                package = affected.get("package", {})
                
                # Extract fixed version from ranges
                fixed_version = None
                patched_versions = []
                
                if "ranges" in affected:
                    for range_info in affected["ranges"]:
                        events = range_info.get("events", [])
                        for event in events:
                            if "fixed" in event:
                                fixed_version = event["fixed"]
                                patched_versions.append(fixed_version)
                
                # Also check database_specific for fixed versions
                if "database_specific" in affected:
                    db_specific = affected["database_specific"]
                    if "fixed_versions" in db_specific:
                        patched_versions.extend(db_specific["fixed_versions"])
                
                enriched["affected_products"].append({
                    "ecosystem": package.get("ecosystem"),
                    "name": package.get("name"),
                    "product": package.get("name"),  # Add product field for consistency
                    "versions": affected.get("versions", []),
                    "ranges": affected.get("ranges", []),  # Keep ranges for detailed parsing
                    "fixed": fixed_version,  # Single fixed version
                    "patched_versions": patched_versions  # All patched versions
                })
    
    # Deduplicate CWE IDs
    enriched["cwe_ids"] = list(set(enriched["cwe_ids"]))
    
    return enriched

async def fetch_endoflife_data(product_name: str) -> Dict[str, Any]:
    """
    Fetch product lifecycle data from endoflife.date API.
    
    Args:
        product_name: Product name (e.g., 'python', 'nodejs', 'ubuntu')
    
    Returns:
        Dict with lifecycle information or empty dict if not found
    """
    try:
        # Normalize product name for endoflife.date API
        normalized_name = product_name.lower().replace(" ", "-")
        
        # Try common mappings
        product_mappings = {
            "runc": "docker-engine",
            "containerd": "docker-engine",
            "python": "python",
            "node": "nodejs",
            "nodejs": "nodejs",
            "java": "java",
            "openjdk": "java",
            "ubuntu": "ubuntu",
            "debian": "debian",
            "rhel": "rhel",
            "centos": "centos"
        }
        
        api_product = product_mappings.get(normalized_name, normalized_name)
        url = f"https://endoflife.date/api/{api_product}.json"
        
        logging.info(f"Fetching lifecycle data from endoflife.date: {url}")
        response = await get(url, timeout=10)
        
        if response and isinstance(response, list) and len(response) > 0:
            logging.info(f"Successfully fetched lifecycle data for {product_name}")
            return {"product": product_name, "cycles": response}
        
        return {}
    except Exception as e:
        logging.warning(f"Could not fetch lifecycle data for {product_name}: {str(e)}")
        return {}


async def fetch_libraries_io_data(product_name: str, platform: str = "pypi") -> Dict[str, Any]:
    """
    Fetch package dependency and compatibility data from libraries.io API.
    
    Args:
        product_name: Package name
        platform: Platform (pypi, npm, maven, go, etc.)
    
    Returns:
        Dict with dependency information or empty dict if not found
    """
    try:
        # Platform mappings
        platform_mappings = {
            "python": "pypi",
            "javascript": "npm",
            "java": "maven",
            "go": "go",
            "ruby": "rubygems",
            "rust": "cargo"
        }
        
        api_platform = platform_mappings.get(platform.lower(), platform)
        url = f"https://libraries.io/api/{api_platform}/{product_name}"
        
        logging.info(f"Fetching dependency data from libraries.io: {url}")
        response = await get(url, timeout=10)
        
        if response and isinstance(response, dict):
            logging.info(f"Successfully fetched dependency data for {product_name}")
            return response
        
        return {}
    except Exception as e:
        logging.warning(f"Could not fetch libraries.io data for {product_name}: {str(e)}")
        return {}


async def fetch_clearlydefined_license(product_name: str, version: str = "latest", 
                                       package_type: str = "pypi") -> Dict[str, Any]:
    """
    Fetch license information from ClearlyDefined API.
    
    Args:
        product_name: Package name
        version: Package version
        package_type: Package type (pypi, npm, maven, etc.)
    
    Returns:
        Dict with license information or empty dict if not found
    """
    try:
        # ClearlyDefined uses format: type/provider/namespace/name/revision
        # Example: pypi/pypi/-/requests/2.28.0
        namespace = "-"  # Most packages use "-" for no namespace
        
        url = f"https://api.clearlydefined.io/definitions/{package_type}/pypi/{namespace}/{product_name}/{version}"
        
        logging.info(f"Fetching license data from ClearlyDefined: {url}")
        response = await get(url, timeout=10)
        
        if response and isinstance(response, dict):
            logging.info(f"Successfully fetched license data for {product_name}")
            return response
        
        return {}
    except Exception as e:
        logging.warning(f"Could not fetch ClearlyDefined data for {product_name}: {str(e)}")
        return {}


async def fetch_github_advisory_details(advisory_id: str) -> Dict[str, Any]:
    """
    Fetch GitHub Security Advisory details.
    
    Args:
        advisory_id: GitHub Security Advisory ID (e.g., GHSA-xr7r-f8xq-vfvv)
    
    Returns:
        Dict with advisory details including patches
    """
    try:
        # GitHub GraphQL API would be better, but REST API works for basic info
        # We can extract from the URL pattern
        url = f"https://api.github.com/advisories/{advisory_id}"
        
        logging.info(f"Fetching GitHub advisory: {url}")
        response = await get(url, timeout=10)
        
        if response and isinstance(response, dict):
            logging.info(f"Successfully fetched GitHub advisory {advisory_id}")
            return response
        
        return {}
    except Exception as e:
        logging.warning(f"Could not fetch GitHub advisory {advisory_id}: {str(e)}")
        return {}


async def extract_lifecycle_records(product_name: str, version: Optional[str] = None) -> List[Models.LifecycleRecord]:
    """
    Extract lifecycle records from endoflife.date data.
    
    Args:
        product_name: Product name
        version: Specific version (optional)
    
    Returns:
        List of LifecycleRecord objects
    """
    lifecycle_records = []
    
    try:
        eol_data = await fetch_endoflife_data(product_name)
        
        if not eol_data or "cycles" not in eol_data:
            return lifecycle_records
        
        for cycle in eol_data["cycles"][:5]:  # Limit to 5 most recent cycles
            try:
                cycle_version = str(cycle.get("cycle", "unknown"))
                
                # Skip if version specified and doesn't match
                if version and not cycle_version.startswith(str(version).split(".")[0]):
                    continue
                
                # Model fields: product, version, release_date, eol_date, extended_support (bool)
                record = Models.LifecycleRecord(
                    product=product_name,
                    version=cycle_version,
                    release_date=cycle.get("releaseDate", ""),
                    eol_date=str(cycle.get("eol", "")),
                    extended_support=bool(cycle.get("extendedSupport", False))
                )
                lifecycle_records.append(record)
            except Exception as e:
                logging.warning(f"Error parsing lifecycle cycle: {str(e)}")
                continue
        
        logging.info(f"Extracted {len(lifecycle_records)} lifecycle records for {product_name}")
    except Exception as e:
        logging.error(f"Error extracting lifecycle records: {str(e)}")
    
    return lifecycle_records


async def extract_compatibility_records(product_name: str) -> List[Models.CompatibilityRecord]:
    """
    Extract compatibility records from libraries.io dependency data.
    
    Args:
        product_name: Product name
    
    Returns:
        List of CompatibilityRecord objects
    """
    compatibility_records = []
    
    try:
        lib_data = await fetch_libraries_io_data(product_name)
        
        if not lib_data:
            return compatibility_records
        
        # Extract dependencies
        dependencies = lib_data.get("dependencies", [])
        
        for dep in dependencies[:10]:  # Limit to 10 dependencies
            try:
                dep_name = dep.get("name", "")
                dep_version = dep.get("requirements", "")
                
                if not dep_name:
                    continue
                
                # Model fields: source_product, dependent_product, supported_versions (List[str]), certification_status (bool)
                supported_versions = [dep_version] if dep_version else []
                
                record = Models.CompatibilityRecord(
                    source_product=product_name,
                    dependent_product=dep_name,
                    supported_versions=supported_versions,
                    certification_status=True  # Assume certified if listed as dependency
                )
                compatibility_records.append(record)
            except Exception as e:
                logging.warning(f"Error parsing dependency: {str(e)}")
                continue
        
        logging.info(f"Extracted {len(compatibility_records)} compatibility records for {product_name}")
    except Exception as e:
        logging.error(f"Error extracting compatibility records: {str(e)}")
    
    return compatibility_records


async def extract_license_policies(product_name: str, version: str = "latest") -> List[Models.LicensePolicy]:
    """
    Extract license policy information from ClearlyDefined.
    
    Args:
        product_name: Product name
        version: Product version
    
    Returns:
        List of LicensePolicy objects
    """
    license_policies = []
    
    try:
        license_data = await fetch_clearlydefined_license(product_name, version)
        
        if not license_data:
            return license_policies
        
        # Extract license information
        licensed = license_data.get("licensed", {})
        declared_license = licensed.get("declared", "UNKNOWN")
        
        # Define approved open source licenses
        approved_licenses = [
            "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause",
            "GPL-3.0", "GPL-2.0", "LGPL-3.0", "LGPL-2.1",
            "ISC", "MPL-2.0", "EPL-2.0"
        ]
        
        # Check if license violates policy (not in approved list)
        has_violation = not any(lic in declared_license for lic in approved_licenses)
        
        # Model fields: package (str), license (str), violation (bool)
        policy = Models.LicensePolicy(
            package=product_name,
            license=declared_license,
            violation=has_violation
        )
        license_policies.append(policy)
        
        logging.info(f"Extracted license policy for {product_name}: {declared_license} (violation: {has_violation})")
    except Exception as e:
        logging.error(f"Error extracting license policies: {str(e)}")
    
    return license_policies


async def save_intelligence_to_file(cve_id: str, intelligence_data: Dict[str, Any]) -> str:
    """
    Save aggregated intelligence data to a file.
    
    Args:
        cve_id: CVE or Advisory ID
        intelligence_data: Aggregated intelligence data
    
    Returns:
        str: Path to the saved file
    """
    import os
    import json
    from datetime import datetime
    
    # Get storage directory from environment or use default
    storage_dir = os.getenv("INTELLIGENCE_DATA_DIR", "app/data/intelligence")
    
    # Create directory if it doesn't exist
    os.makedirs(storage_dir, exist_ok=True)
    
    # Create filename: CVE-2024-12345.json or RHSA-2024-1234.json
    safe_filename = cve_id.replace("/", "_").replace(":", "_")
    filepath = os.path.join(storage_dir, f"{safe_filename}.json")
    
    # Add metadata
    intelligence_data["metadata"] = {
        "cve_id": cve_id,
        "fetched_at": datetime.utcnow().isoformat(),
        "sources_used": list(intelligence_data.get("sources", {}).keys())
    }
    
    # Save to file
    with open(filepath, 'w') as f:
        json.dump(intelligence_data, f, indent=2)
    
    logging.info(f"Saved intelligence data for {cve_id} to {filepath}")
    return filepath


async def load_intelligence_from_file(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Load intelligence data from a file.
    
    Args:
        cve_id: CVE or Advisory ID
    
    Returns:
        Dict with intelligence data or None if file doesn't exist
    """
    import os
    import json
    
    # Get storage directory
    storage_dir = os.getenv("INTELLIGENCE_DATA_DIR", "app/data/intelligence")
    
    # Create filename
    safe_filename = cve_id.replace("/", "_").replace(":", "_")
    filepath = os.path.join(storage_dir, f"{safe_filename}.json")
    
    # Check if file exists
    if not os.path.exists(filepath):
        logging.info(f"No saved intelligence file found for {cve_id}")
        return None
    
    # Load from file
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        logging.info(f"Loaded intelligence data for {cve_id} from {filepath}")
        return data
    except Exception as e:
        logging.error(f"Error loading intelligence file for {cve_id}: {str(e)}")
        return None


async def list_saved_intelligence_files() -> List[Dict[str, str]]:
    """
    List all saved intelligence files.
    
    Returns:
        List of dicts with file information
    """
    import os
    from datetime import datetime
    
    storage_dir = os.getenv("INTELLIGENCE_DATA_DIR", "app/data/intelligence")
    
    if not os.path.exists(storage_dir):
        return []
    
    files = []
    for filename in os.listdir(storage_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(storage_dir, filename)
            stat = os.stat(filepath)
            
            files.append({
                "cve_id": filename.replace('.json', '').replace('_', '-'),
                "filename": filename,
                "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
    
    return sorted(files, key=lambda x: x['modified_at'], reverse=True)


async def extract_structured_intelligence(aggregated_intel: Dict[str, Any]) -> Models.StructuredIntelligenceResponse:
    """
    Extract structured, quantitative data from aggregated intelligence for database storage.
    
    Args:
        aggregated_intel: Aggregated intelligence from multiple sources
    
    Returns:
        StructuredIntelligenceResponse with database-ready structured data
    """
    from datetime import datetime
    
    cve_id = aggregated_intel.get("cve_id", "")
    enriched = aggregated_intel.get("enriched_data", {})
    sources = aggregated_intel.get("sources", {})
    
    # Extract CVE Record
    cvss_score = 0.0
    severity = "UNKNOWN"
    
    if enriched.get("cvss_scores"):
        # Prefer CVSS v3.1
        if "v3.1" in enriched["cvss_scores"]:
            cvss_score = enriched["cvss_scores"]["v3.1"].get("score", 0.0)
            severity = enriched["cvss_scores"]["v3.1"].get("severity", "UNKNOWN")
        elif "osv_v3" in enriched["cvss_scores"]:
            cvss_score = enriched["cvss_scores"]["osv_v3"].get("score", 0.0)
    
    description = ""
    if enriched.get("descriptions"):
        description = enriched["descriptions"][0].get("value", "") if enriched["descriptions"] else ""
    
    cve_record = Models.CVERecord(
        cve_id=cve_id,
        description=description[:500],  # Limit for database
        cvss_score=cvss_score,
        severity=severity,
        exploit_maturity=None,  # TODO: Integrate with exploit databases
        kev_listed=False  # TODO: Check against CISA KEV catalog
    )
    
    # Extract Product Records
    products = []
    cve_product_mappings = []
    
    for idx, product_info in enumerate(enriched.get("affected_products", [])):
        product_name = product_info.get("product") or product_info.get("name") or "Unknown Product"
        vendor = product_info.get("vendor") or product_info.get("ecosystem") or "Unknown Vendor"
        
        # Skip if both are still None or empty
        if not product_name or not vendor:
            continue
            
        product_id = f"{vendor}_{product_name}".replace(" ", "_").replace(".", "_")
        
        product = Models.ProductRecord(
            product_id=product_id,
            product_name=product_name,
            vendor=vendor,
            product_family="Software"  # Can be enhanced with classification logic
        )
        products.append(product)
        
        # Create CVE-Product mapping
        versions = product_info.get("versions", [])
        version_range = ", ".join([str(v) for v in versions[:3]]) if versions else "All versions"
        
        mapping = Models.CVEProductMap(
            cve_id=cve_id,
            product_id=product_id,
            affected_version_range=version_range,
            vendor_severity=severity
        )
        cve_product_mappings.append(mapping)
    
    # Extract Vendor Advisories with enhanced pattern detection
    vendor_advisories = []
    patches = []
    patches_created = set()  # Track created patches to avoid duplicates
    
    # Enhanced advisory URL patterns
    advisory_patterns = {
        "github.com/advisories/GHSA-": "GitHub",
        "github.com/security/advisories/GHSA-": "GitHub",
        "access.redhat.com/errata/": "Red Hat",
        "security.debian.org/": "Debian",
        "lists.debian.org/debian-security-announce": "Debian",
        "lists.debian.org/debian-lts-announce": "Debian",
        "ubuntu.com/security/": "Ubuntu",
        "usn.ubuntu.com/": "Ubuntu",
        "lists.fedoraproject.org/archives/list/package-announce": "Fedora",
        "security.gentoo.org/": "Gentoo",
        "security.archlinux.org/": "Arch Linux"
    }
    
    # Check all references for vendor advisories
    for ref in enriched.get("references", []):
        url = ref.get("url", "")
        
        # Check against all patterns
        for pattern, vendor in advisory_patterns.items():
            if pattern in url:
                # Extract advisory ID from URL
                advisory_id = url.split("/")[-1] if "/" in url else url
                
                # Skip if already added
                if any(adv.advisory_id == advisory_id for adv in vendor_advisories):
                    continue
                
                advisory = Models.VendorAdvisory(
                    advisory_id=advisory_id,
                    vendor=vendor,
                    cve_id=cve_id,
                    severity=severity,
                    advisory_url=url,
                    published_date=enriched.get("timeline", {}).get("published", "")
                )
                vendor_advisories.append(advisory)
                break  # Only match first pattern
    
    # Extract patches from affected products with fixed versions
    import re
    
    for product_info in enriched.get("affected_products", []):
        product_name = product_info.get("product") or product_info.get("name") or "Unknown Product"
        
        # Skip if product name is unknown
        if product_name == "Unknown Product":
            continue
        
        # Look for fixed version information
        fixed_version = None
        
        # Check for patched_versions field (OSV format)
        if product_info.get("patched_versions"):
            patched = product_info["patched_versions"]
            if isinstance(patched, list) and patched:
                fixed_version = patched[0]
            elif isinstance(patched, str):
                fixed_version = patched
        
        # Check for fixed field (GitHub/OSV format)
        elif product_info.get("fixed"):
            fixed_version = product_info["fixed"]
        
        # Check for ranges with introduced/fixed (OSV format)
        elif product_info.get("ranges"):
            for range_info in product_info["ranges"]:
                events = range_info.get("events", [])
                for event in events:
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                        break
                if fixed_version:
                    break
        
        # Parse version information from versions field (MITRE format)
        elif product_info.get("versions"):
            versions = product_info["versions"]
            for version_info in versions:
                if isinstance(version_info, dict):
                    # Check for version with status
                    if version_info.get("status") == "unaffected":
                        fixed_version = version_info.get("version", "").replace(">=", "").replace("v", "").strip()
                        break
                    # Parse version range like ">=v1.0.0-rc93, < 1.1.12"
                    version_str = version_info.get("version", "")
                    if "<" in version_str:
                        # Extract the upper bound as the fixed version
                        match = re.search(r'<\s*([0-9.]+)', version_str)
                        if match:
                            fixed_version = match.group(1)
                            break
        
        # Log for debugging
        logging.info(f"Product: {product_name}, Fixed version: {fixed_version}, Product info keys: {product_info.keys()}")
        
        # Only create patch if we have a fixed version
        if fixed_version and fixed_version != "0":
            patch_key = f"{product_name}_{fixed_version}"
            
            # Skip if already created
            if patch_key in patches_created:
                continue
            
            patches_created.add(patch_key)
            
            # Find matching advisory
            advisory_id = vendor_advisories[0].advisory_id if vendor_advisories else "PATCH"
            
            patch = Models.PatchRecord(
                patch_id=f"PATCH-{product_name}-{fixed_version}".replace(" ", "-"),
                advisory_id=advisory_id,
                product=product_name,
                fixed_version=fixed_version,
                reboot_required=False,  # Would need to parse advisory details
                patch_release_date=enriched.get("timeline", {}).get("published", "")
            )
            patches.append(patch)
            logging.info(f"Created patch record: {patch.patch_id}")
    
    # Fetch additional intelligence from public APIs
    compatibility = []
    lifecycle = []
    version_policies = []
    license_policies = []
    
    # Extract lifecycle and compatibility data for the first product
    if products:
        primary_product = products[0]
        product_name = primary_product.product_name
        
        # Fetch lifecycle data from endoflife.date
        try:
            lifecycle = await extract_lifecycle_records(product_name)
            if lifecycle:
                logging.info(f"Added {len(lifecycle)} lifecycle records")
        except Exception as e:
            logging.warning(f"Could not fetch lifecycle data: {str(e)}")
        
        # Fetch compatibility data from libraries.io
        try:
            compatibility = await extract_compatibility_records(product_name)
            if compatibility:
                logging.info(f"Added {len(compatibility)} compatibility records")
        except Exception as e:
            logging.warning(f"Could not fetch compatibility data: {str(e)}")
        
        # Fetch license policy data from ClearlyDefined
        try:
            license_policies = await extract_license_policies(product_name)
            if license_policies:
                logging.info(f"Added {len(license_policies)} license policies")
        except Exception as e:
            logging.warning(f"Could not fetch license data: {str(e)}")
    
    # Version policies would require organizational policy database
    # This is a placeholder for future integration
    version_policies = []
    
    # Determine data sources used
    data_sources = []
    if sources.get("nvd"):
        data_sources.append("NVD")
    if sources.get("mitre"):
        data_sources.append("MITRE")
    if sources.get("github"):
        data_sources.append("GitHub CVE Project")
    if sources.get("osv"):
        data_sources.append("OSV.dev")
    if lifecycle:
        data_sources.append("endoflife.date")
    if compatibility:
        data_sources.append("libraries.io")
    if license_policies:
        data_sources.append("ClearlyDefined")
    
    return Models.StructuredIntelligenceResponse(
        cve=cve_record,
        products=products,
        cve_product_mappings=cve_product_mappings,
        vendor_advisories=vendor_advisories,
        patches=patches,
        compatibility=compatibility,
        lifecycle=lifecycle,
        version_policies=version_policies,
        license_policies=license_policies,
        intelligence_timestamp=datetime.utcnow().isoformat(),
        data_sources=data_sources
    )


# ============================================================================
# JSON Database Functions for Structured Intelligence
# ============================================================================

async def save_to_intelligence_database(structured_data: Models.StructuredIntelligenceResponse) -> bool:
    """
    Save or update structured intelligence data in JSON database.
    
    The database is a JSON file that stores all CVE intelligence records.
    Each CVE is stored as a separate record with all its related data.
    If a CVE already exists, it will be updated with new data.
    
    Args:
        structured_data: StructuredIntelligenceResponse object
    
    Returns:
        bool: True if successful, False otherwise
    """
    import os
    import json
    from datetime import datetime
    
    try:
        # Get database file path from environment or use default
        db_dir = os.getenv("INTELLIGENCE_DB_DIR", "app/data/intelligence_db")
        os.makedirs(db_dir, exist_ok=True)
        db_file = os.path.join(db_dir, "intelligence_records.json")
        
        # Load existing database
        if os.path.exists(db_file):
            with open(db_file, 'r') as f:
                database = json.load(f)
        else:
            database = {
                "metadata": {
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat(),
                    "total_records": 0
                },
                "records": {}
            }
        
        # Convert Pydantic model to dict
        cve_id = structured_data.cve.cve_id
        record_data = {
            "cve": structured_data.cve.dict(),
            "products": [p.dict() for p in structured_data.products],
            "cve_product_mappings": [m.dict() for m in structured_data.cve_product_mappings],
            "vendor_advisories": [a.dict() for a in structured_data.vendor_advisories],
            "patches": [p.dict() for p in structured_data.patches],
            "compatibility": [c.dict() for c in structured_data.compatibility],
            "lifecycle": [l.dict() for l in structured_data.lifecycle],
            "version_policies": [v.dict() for v in structured_data.version_policies],
            "license_policies": [l.dict() for l in structured_data.license_policies],
            "intelligence_timestamp": structured_data.intelligence_timestamp,
            "data_sources": structured_data.data_sources,
            "last_updated": datetime.utcnow().isoformat()
        }
        
        # Check if record exists
        if cve_id in database["records"]:
            logging.info(f"Updating existing record for {cve_id}")
        else:
            logging.info(f"Creating new record for {cve_id}")
            database["metadata"]["total_records"] += 1
        
        # Save or update record
        database["records"][cve_id] = record_data
        database["metadata"]["last_updated"] = datetime.utcnow().isoformat()
        
        # Write back to file
        with open(db_file, 'w') as f:
            json.dump(database, f, indent=2)
        
        logging.info(f"Successfully saved {cve_id} to intelligence database")
        return True
        
    except Exception as e:
        logging.error(f"Error saving to intelligence database: {str(e)}")
        return False


async def load_from_intelligence_database(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Load a CVE record from the intelligence database.
    
    Args:
        cve_id: CVE identifier
    
    Returns:
        Dict with CVE record data or None if not found
    """
    import os
    import json
    
    try:
        db_dir = os.getenv("INTELLIGENCE_DB_DIR", "app/data/intelligence_db")
        db_file = os.path.join(db_dir, "intelligence_records.json")
        
        if not os.path.exists(db_file):
            logging.info(f"Intelligence database not found")
            return None
        
        with open(db_file, 'r') as f:
            database = json.load(f)
        
        record = database.get("records", {}).get(cve_id)
        
        if record:
            logging.info(f"Found record for {cve_id} in intelligence database")
        else:
            logging.info(f"No record found for {cve_id} in intelligence database")
        
        return record
        
    except Exception as e:
        logging.error(f"Error loading from intelligence database: {str(e)}")
        return None


async def get_all_cve_ids_from_database() -> List[str]:
    """
    Get list of all CVE IDs in the database.
    
    Returns:
        List of CVE IDs
    """
    import os
    import json
    
    try:
        db_dir = os.getenv("INTELLIGENCE_DB_DIR", "app/data/intelligence_db")
        db_file = os.path.join(db_dir, "intelligence_records.json")
        
        if not os.path.exists(db_file):
            return []
        
        with open(db_file, 'r') as f:
            database = json.load(f)
        
        return list(database.get("records", {}).keys())
        
    except Exception as e:
        logging.error(f"Error getting CVE IDs from database: {str(e)}")
        return []


async def query_database_by_field(field_path: str, value: Any) -> List[Dict[str, Any]]:
    """
    Query the database for records matching a field value.
    
    Args:
        field_path: Dot-notation path to field (e.g., "cve.severity", "products.vendor")
        value: Value to match
    
    Returns:
        List of matching records
    """
    import os
    import json
    
    try:
        db_dir = os.getenv("INTELLIGENCE_DB_DIR", "app/data/intelligence_db")
        db_file = os.path.join(db_dir, "intelligence_records.json")
        
        if not os.path.exists(db_file):
            return []
        
        with open(db_file, 'r') as f:
            database = json.load(f)
        
        matching_records = []
        
        for cve_id, record in database.get("records", {}).items():
            # Navigate to the field using dot notation
            parts = field_path.split('.')
            current = record
            
            try:
                for part in parts:
                    if isinstance(current, list):
                        # For list fields, check if any item matches
                        found = False
                        for item in current:
                            if isinstance(item, dict) and part in item:
                                if item[part] == value:
                                    found = True
                                    break
                        if found:
                            matching_records.append(record)
                        break
                    else:
                        current = current[part]
                
                # Check if final value matches
                if not isinstance(current, list) and current == value:
                    matching_records.append(record)
                    
            except (KeyError, TypeError):
                continue
        
        return matching_records
        
    except Exception as e:
        logging.error(f"Error querying database: {str(e)}")
        return []