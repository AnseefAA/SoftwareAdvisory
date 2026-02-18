from fastapi import APIRouter, Body, File, UploadFile, HTTPException
from app.core.config import LLM_MODELS
from app.services.ai import prompts
from app.utils.helpers import fetch_project_impression, fetch_projects_metadata, generate_openapi_examples, fetch_vulnerability, get_cve_info_from_osv_cve_info, get_vulnerabilities, search_vulnerability, get_vulnerabilities, search_vulnerability, update_feedback, upload_cve_context, upload_file_helper, trim_triple_backticks
from langchain_core.prompts import PromptTemplate
from app.services.ai.llm_service import query_llm
from typing import Dict, List , Optional
import app.models as Models
from app.exception import exceptions
import os
import logging
import app.core.constants as Constants
from app.services.ai.cache import FileSystemCache
import json
import re

logger = logging.getLogger('cve_routes')

router = APIRouter(
    prefix="/api/v1",
    tags=["Vulnerability"]
)

@router.post("/test/llm/prompt")
async def llm(
    payload: Models.MitigationRequest = Body(
        openapi_examples=generate_openapi_examples(LLM_MODELS)
    )
):
    """
    Test LLM Response for a given vulnerability using Watsonx AI.

    Args:
        payload (Models.MitigationRequest): Request payload containing model ID and CVE ID.

    Returns:
        dict: Vulnerability details.
    """
    return query_llm(Models.LLMRequest(
        modelId=payload.modelId,
        promptTemplate=PromptTemplate(input_variables=["prompt_context"], template=prompts.CVE_DETAIL),
        promptInputs= {
            "prompt_context": await fetch_vulnerability(payload.cveId, "vulnerabilities_iter_1.json")
        }
    ))

@router.post("/vulnerabilities/enhanced")
async def get_enhanced_vulnerabilities(filename: str) -> Models.EnhancedVulnerabilityResponse:
    """
    Get comprehensive vulnerability analysis with enhanced context including:
    - CVE details (ID, description, severity, CVSS score, KEV status, exploit maturity)
    - Asset information (ID, hostname, environment, business tier, internet exposure)
    - Product details (name, version, vendor, release date)
    - Application certification status
    - Dependency chain information
    - Policy compliance data
    
    Args:
        filename (str): Name of the vulnerability scan file (Trivy format)
    
    Returns:
        EnhancedVulnerabilityResponse: Comprehensive vulnerability data with counts
    
    Example:
        POST /api/v1/vulnerabilities/enhanced?filename=sample-vulnerabilities.json
    """
    try:
        from app.utils.helpers import fetch_enhanced_vulnerabilities
        response = await fetch_enhanced_vulnerabilities(filename)
        return response
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File {filename} not found")
    except Exception as e:
        logger.error(f"Error fetching enhanced vulnerabilities: {str(e)}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@router.post("/mitigation/enhanced")
async def enhanced_mitigation_intelligence(payload: Models.MitigationRequest) -> str:
    """
    Generate comprehensive, actionable mitigation recommendations using multi-source CVE intelligence.
    
    This endpoint aggregates intelligence from:
    - NVD (National Vulnerability Database)
    - MITRE CVE AWG
    - GitHub CVE Project
    - OSV.dev
    - Local vulnerability scan files
    
    And provides answers to critical questions:
    🔎 What does this mean for my environment?
    ⚠️ What's the real risk?
    🛠 What exactly should I do?
    🔁 Is reboot required?
    📦 What breaks if I patch?
    📊 Is this actively exploited?
    ⏱ How urgent is it?
    🔐 Mitigation steps if patching not possible
    
    Args:
        payload (Models.MitigationRequest): Request containing CVE ID and filename
    
    Returns:
        str: Comprehensive JSON response with actionable intelligence
    """
    try:
        # Determine cache subdirectory
        cache_subdir = "enhanced_mitigation"
        
        # Only use cache if filename is provided
        cache = None
        if payload.filename:
            cache = FileSystemCache(
                cve_id=payload.cveId,
                filename=payload.filename,
                subdir=cache_subdir,
                parser=None
            )
            logger.info(f"Enhanced intelligence process initialized for {payload.cveId} with file {payload.filename}")
            
            # Check cache
            if payload.useCache:
                cached_response = cache.lookup()
                if cached_response:
                    logger.info(f"Enhanced mitigation cache found for {payload.cveId}")
                    return cached_response
        else:
            logger.info(f"Enhanced intelligence process initialized for {payload.cveId} (no file specified)")
        
        # Step 1: Aggregate intelligence from multiple sources
        logger.info(f"Aggregating intelligence from multiple sources for {payload.cveId}")
        from app.utils.helpers import aggregate_cve_intelligence
        aggregated_intel = await aggregate_cve_intelligence(payload.cveId)
        
        # Step 2: Also get local file context if filename is provided
        if payload.filename:
            try:
                abs_path = os.path.abspath(os.path.join(Constants.UPLOAD_FILE_PATH, os.path.splitext(os.path.basename(payload.filename))[0]))
                local_context = await fetch_vulnerability(payload.cveId, f"{abs_path}/{payload.filename}")
                aggregated_intel["local_scan_context"] = local_context
                logger.info(f"Added local scan context for {payload.cveId}")
            except Exception as e:
                logger.warning(f"Could not fetch local context: {str(e)}")
                aggregated_intel["local_scan_context"] = "No local scan data available"
        else:
            aggregated_intel["local_scan_context"] = "No local scan data available (filename not provided)"
        
        # Step 3: Format aggregated intelligence for the prompt
        import json
        intelligence_context = json.dumps(aggregated_intel, indent=2)
        
        # Step 4: Generate enhanced prompt
        prompt_template = PromptTemplate(
            input_variables=["aggregated_intelligence"],
            template=prompts.ENHANCED_CVE_INTELLIGENCE
        )
        formatted_prompt = prompt_template.format_prompt(aggregated_intelligence=intelligence_context)
        logger.info(f"Generated enhanced intelligence prompt for {payload.cveId}")
        
        # Step 5: Query LLM with enhanced intelligence
        llm_request = Models.LLMRequest(
            modelId="ibm/granite-3-8b-instruct",
            promptTemplate=prompt_template,
            promptInputs={"aggregated_intelligence": intelligence_context}
        )
        llm_response = query_llm(llm_request, False)
        
        # Step 6: Sanitize response - remove markdown code fences and extra whitespace
        sanitized_response = trim_triple_backticks(llm_response)
        
        # Additional sanitization for JSON responses
        sanitized_response = sanitized_response.strip()
        if sanitized_response.startswith('```json'):
            sanitized_response = sanitized_response[7:]  # Remove ```json
        if sanitized_response.startswith('```'):
            sanitized_response = sanitized_response[3:]  # Remove ```
        if sanitized_response.endswith('```'):
            sanitized_response = sanitized_response[:-3]  # Remove trailing ```
        sanitized_response = sanitized_response.strip()
        
        # Validate it's valid JSON
        try:
            import json
            json.loads(sanitized_response)  # Validate JSON
            logger.info(f"Response validated as valid JSON for {payload.cveId}")
        except json.JSONDecodeError as je:
            logger.error(f"Invalid JSON response: {str(je)}")
            logger.error(f"Response preview: {sanitized_response[:500]}")
            # Return as-is but log the error
        
        # Save to cache if cache is available
        if cache:
            cache.update(formatted_prompt.text, sanitized_response)
        
        logger.info(f"Enhanced mitigation intelligence generated for {payload.cveId}")
        return sanitized_response
        
    except Exception as e:
        logger.error(f"Error in enhanced mitigation intelligence: {str(e)}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")


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
        from app.utils.helpers import aggregate_cve_intelligence, extract_structured_intelligence
        aggregated_intel = await aggregate_cve_intelligence(payload.cveId)
        
        # Step 2: Extract structured data
        structured_data = await extract_structured_intelligence(aggregated_intel)
        
        logger.info(f"Structured intelligence extracted for {payload.cveId}")
        logger.info(f"Found {len(structured_data.products)} products, {len(structured_data.vendor_advisories)} advisories, {len(structured_data.patches)} patches")
        
        return structured_data
        
    except Exception as e:
        logger.error(f"Error fetching structured intelligence: {str(e)}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")


@router.post("/mitigation")
async def recommended_mitigation(payload: Models.MitigationRequest) -> str:
    """
    Generate recommended mitigations for a specified vulnerability or vendor advisory using Watsonx AI.

    Args:
        payload (Models.MitigationRequest): The request payload containing:
            - cveId (str): CVE identifier or Advisory ID
            - filename (str): Name of the file with vulnerability/advisory data
            - type (str): Type of request - "cve" or "advisory" (default: "cve")
            - useCache (bool): Whether to use cached results (default: True)

    Returns:
        str: Recommended mitigations for the specified vulnerability or advisory.
    """
    try:
        # Determine cache subdirectory based on type
        cache_subdir = "advisory_mitigation" if payload.type == Models.VulnerabilityType.ADVISORY else "mitigation"
        
        # Only use cache if filename is provided
        cache = None
        if payload.filename:
            cache = FileSystemCache(
                cve_id = payload.cveId,
                filename = payload.filename,
                subdir = cache_subdir,
                parser = None
            )
            logger.info(f"Process initialized for type: {payload.type} with file {payload.filename}")
            
            # Checking whether LLM cache exists or not
            if payload.useCache:
                cached_response = cache.lookup()
                logger.info(f"{'Advisory' if payload.type == Models.VulnerabilityType.ADVISORY else 'Mitigation'} cache is { '' if cached_response else 'not' } exist for {payload.cveId}")
                if cached_response:
                    return cached_response
        else:
            logger.info(f"Process initialized for type: {payload.type} (no file specified)")

        # Generate mitigation prompt based on type
        logger.info(f"Generating {'advisory' if payload.type == Models.VulnerabilityType.ADVISORY else 'mitigation'} prompt")
        
        # Fetch context and set up prompt template
        if payload.type == Models.VulnerabilityType.ADVISORY:
            # Advisory type
            if payload.filename:
                # Fetch from file
                abs_path = os.path.abspath(os.path.join(Constants.UPLOAD_FILE_PATH, os.path.splitext(os.path.basename(payload.filename))[0]))
                from app.utils.helpers import fetch_vendor_advisory
                prompt_context = await fetch_vendor_advisory(payload.cveId, f"{abs_path}/{payload.filename}")
            else:
                # Fetch from internet (Red Hat API fallback)
                from app.utils.helpers import fetch_vendor_advisory
                prompt_context = await fetch_vendor_advisory(payload.cveId, "")  # Empty string triggers API fallback
            
            prompt_template = PromptTemplate(
                input_variables=["prompt_context"],
                template=prompts.VENDOR_ADVISORY_MITIGATION
            )
            logger.info(f"Processing vendor advisory: {payload.cveId}")
        else:
            # CVE type
            if payload.filename:
                # Fetch from file
                abs_path = os.path.abspath(os.path.join(Constants.UPLOAD_FILE_PATH, os.path.splitext(os.path.basename(payload.filename))[0]))
                prompt_context = await fetch_vulnerability(payload.cveId, f"{abs_path}/{payload.filename}")
            else:
                # For CVE without file, use aggregated intelligence
                from app.utils.helpers import aggregate_cve_intelligence
                aggregated_intel = await aggregate_cve_intelligence(payload.cveId)
                import json
                prompt_context = json.dumps(aggregated_intel, indent=2)
            
            prompt_template = PromptTemplate(
                input_variables=["prompt_context"],
                template=prompts.VULNERABILITY_MITIGATION
            )
            logger.info(f"Processing CVE: {payload.cveId}")
        
        formatted_prompt = prompt_template.format_prompt(prompt_context=prompt_context)
        logger.info(f"Generated prompt for {payload.cveId}")
        logger.info(f"Generated prompt: {formatted_prompt}")
        
        # Query the LLM
        llm_request = Models.LLMRequest(
            modelId="ibm/granite-3-8b-instruct",
            promptTemplate=prompt_template,
            promptInputs={"prompt_context": prompt_context}
        )
        llm_response = query_llm(llm_request, False)

        # Sanitize and save the response
        sanitized_response = trim_triple_backticks(llm_response)
        
        # Saving LLM prompt and response into file system (only if cache exists)
        if cache:
            cache.update(formatted_prompt.text, sanitized_response)

        return sanitized_response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    
    
@router.put("/cves/feedback")
async def update_cve_user_feedback(payload: Models.FeedbackRequest) -> Models.FeedbackResponse:
    """
    Update the user feedback for a specified vulnerability cve.

    Args:
        payload (Models.FeedbackRequest): The request payload containing:
            - filename (str): Name of the file with vulnerability data.
            - cveId (str): CVE identifier of the vulnerability.
            - action (FeedbackAction): Action to be taken on the vulnerability.

    Returns:
        Models.FeedbackResponse: Json body containing action , liked count and disliked count.
    """
    try:
        cache = FileSystemCache(
            cve_id = payload.cveId,
            filename = payload.filename,
            subdir = "feedback",
            parser = None
        )

        cached_response = cache.lookup()

        # Set empty dict if it's not present
        if not cached_response:
            cached_response = "{}"
        
        # Update the feedback
        vulnerability_response = await update_feedback(payload.action , cached_response)

        # Save feedback into the file
        cache.update_response_file(vulnerability_response.json())

        return Models.FeedbackResponse(action = payload.action, likeCount = vulnerability_response.likeCount, dislikeCount = vulnerability_response.dislikeCount)
    except Exception as e:
        raise exceptions.general_error()
    
@router.get("/project/impression/{project_name}")
async def get_project_impression_by_id(project_name: str) -> Models.ProjectFeedbackResponse:
    """
    Get project impresssion by project name such as total number of like and dislike of cves in the mentioned project.

    Args:
        - project_name (str):project name.

    Returns:
        Models.ProjectFeedbackResponse: Json body containing project_name , liked count and disliked count.
    """
    try:
        subdir = "feedback"
        return await fetch_project_impression(subdir,project_name)
    except FileNotFoundError as e:
        raise exceptions.not_found_error()
    except Exception as e:
        raise exceptions.general_error()
    
    
@router.get("/cve/feedback/{filename}/{cve_id}")
async def fetch_feedback(filename: str, cve_id: str,) -> Models.GetFeedbackResponse:
    """
    Fetch the user feedback for a specified vulnerability CVE.

    Args:
        - filename (str): Name of the file with vulnerability data.
        - cve_id (str): CVE identifier of the vulnerability.

    Returns:
        Models.GetFeedbackResponse: JSON body containing the liked count and disliked count.
                                   Returns an empty response if no feedback is found.
    """
    try:
        # Initialize cache
        cache = FileSystemCache(
            cve_id=cve_id,
            filename=filename,
            subdir="feedback",
            parser=None
        )

        # Attempt to fetch the cached response
        cached_response = cache.lookup()

        if not cached_response:
            # Return an empty response if no cached data is found
            return Models.GetFeedbackResponse()

        # Return the parsed cached response
        return Models.GetFeedbackResponse(**json.loads(cached_response))
    except Exception as e:
        logger.error(f"Error fetching feedback for CVE ID {cve_id}: {str(e)}")
        raise exceptions.general_error()

@router.get("/vulnerability/{filename}/{cve_id}")
async def get_vulnerability(filename: str, cve_id: str, useCache: Optional[bool] = True) -> Models.LLMVulnerabilityResponse:
    """
    Retrieve vulnerability details for a specific CVE ID from the specified file.

    Args:
        filename (str): The name of the uploaded vulnerability file.
        cve_id (str): The CVE ID to search for.

    Returns:
        List[Models.VulnerabilityInfo]: A list of details for the specified CVE ID.
    """
    try:
        cache = FileSystemCache(
            cve_id = cve_id,
            filename = filename,
            subdir = "details",
        )
        
        # Checking whether LLM cache is exist or not
        if useCache:
            cached_response = cache.lookup()
            logger.info(f"CVE information cache is { '' if cached_response else 'not' } exist for {cve_id}")
            if cached_response:
                return cached_response

        abs_path = os.path.abspath(os.path.join(Constants.UPLOAD_FILE_PATH, os.path.splitext(os.path.basename(filename))[0]))
        prompt_context = await fetch_vulnerability(cve_id, f"{abs_path}/{filename}")
        prompt_template = PromptTemplate(input_variables=["prompt_context"], template=prompts.CVE_DETAIL)
        formatted_prompt = prompt_template.format_prompt(prompt_context=prompt_context)
        
        response = query_llm(Models.LLMRequest(
            modelId="ibm/granite-3-8b-instruct",
            promptTemplate=prompt_template,
            promptInputs= {"prompt_context": prompt_context}
        ))

        # Saving LLM prompt and response into file system
        cache.update(formatted_prompt.text, json.dumps(response))

        if not isinstance(response, dict):
            response = {}
        else:
            for key in ["isFixAvailable", "fixComplexity", "cvssSeverity"]:
                value = response.get(key)
                if isinstance(value, str):
                    response[key] = value.capitalize()

        return Models.LLMVulnerabilityResponse(**response)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@router.post("/upload")
async def upload_file(uploaded_file: UploadFile = File(...)):
    """
    Endpoint to handle file uploads.

    Args:
        uploaded_file (UploadFile): The file to be uploaded.

    Returns:
        dict: A response indicating the success or failure of the upload.
    """
    try:
        await upload_file_helper(uploaded_file)
            
        return {"message": f"Successfully uploaded file: {uploaded_file.filename}"}
    # except FileNotFoundError as e:
    #     raise exceptions.file_not_found_error(str(e))
    except PermissionError:
        raise exceptions.permission_denied_error()
    # except ValueError:
    #     raise exceptions.invalid_filename_error()
    except Exception as e:
        raise exceptions.general_file_error(f"Failed to upload the file: {str(e)}")

@router.get("/search")
async def search_items(query: str, filename: str) -> List[Models.VulnerabilityInfo]:
    """
    Search for items based on a query string.

    Args:
        query (str): The search query.
        filename (str): The uploaded vulnerability file name.

    Returns:
        List[Models.VulnerabilityInfo]: A list of search results matching the query.
    """
    try:
        return await search_vulnerability(query,filename)
    
    except Exception as e:
        raise exceptions.not_found_error()

@router.get("/vulnerabilities/{filename}")
async def list_vulnerabilities(filename: str) -> List[Models.VulnerabilityInfo]:
    """
    Retrieve a list of vulnerabilities from the specified file.

    Args:
        filename (str): The name of the uploaded vulnerability file.

    Returns:
        List[Models.VulnerabilityInfo]: A list of vulnerability details from the file.
    """
    try:
        return  get_vulnerabilities(filename)
    except Exception as e:
        raise exceptions.general_error()
    
@router.get("/concert/vulnerability/{filename}/{cve_id}")
async def fetch_vulnerability_by_cve_id(filename: str, cve_id: str) -> Models.CVEInfo:
    """
    Retrieve the vulnerability from the specified cve id.

    Args:
        cve_id (str): The name of the vulnerability CVE ID.

    Returns:
        str: Json Formatted Response.
    """
    try:
        cache = FileSystemCache(cve_id=cve_id, filename=filename, subdir="concert_cve_data")

        # Attempt to retrieve cached response
        cached_response = cache.lookup()
        if cached_response:
            return cached_response
        
        cve_info = Models.CVEInfo()
        try:
            # Fetch CVE information from OSV
            cve_info = await get_cve_info_from_osv_cve_info(cve_id)
        except Exception as e:
            abs_path = os.path.abspath(os.path.join(Constants.UPLOAD_FILE_PATH, os.path.splitext(os.path.basename(filename))[0]))
            vulnerability = await fetch_vulnerability(cve_id, f"{abs_path}/{filename}")
            vuln_info = vulnerability.get("VulnerabilityInfo", {})
            cvss_info = vuln_info.get("CVSS", {})

            cve_info = Models.CVEInfo(
                cve=vuln_info.get("VulnerabilityID"),
                cvss=cvss_info.get("ghsa", {}).get("V3Score") or cvss_info.get("nvd", {}).get("V3Score"),
                severity=vuln_info.get("Severity", "").capitalize(),
                vector=None,
                description=vuln_info.get("Description"),
                related_cves=[],
                aliases=[]
            )

        cache.update_response_file(cve_info.json())

        return cve_info

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    
@router.post("/concert/mitigation/context")
async def upload_cve_mitigation_context(cve_request: Models.CVERequest) -> Dict:
    """
    Endpoint to fetch detailed mitigation information for a CVE.

    Args:
        cve_request (Models.CVERequest): The request body containing context.

    Returns:
        dict: The detailed mitigation response.
    """
    try:
        # Extract CVE ID from the request context
        cve_id_match = re.search(r'CVE-\d{4}-\d{4,7}', cve_request.context)
        cve_id = cve_id_match.group() if cve_id_match else None

        if cve_id:
            cache = FileSystemCache(cve_id=cve_id, filename=cve_request.filename, subdir="concert_genai")

            # Attempt to retrieve cached response
            cached_response = cache.lookup()
            if cached_response:
                return cached_response

        # Fetch data from Concert GenAI
        concert_genai_response = await upload_cve_context(cve_request)

        # Cache the response if it's a dictionary
        if isinstance(concert_genai_response, dict):
            cache.update_response_file(json.dumps(concert_genai_response))

        return concert_genai_response

    except Exception:
        raise exceptions.general_error()
    
@router.get("/projects/metadata")
async def get_projects_metadata() -> List[Models.ProjectMetadata]:
    """
    Fetch a  list of project/file metadata.
    
    Returns:
        List[Models.ProjectMetadata]: A list of project/file metadata.
    """
    try:
        return await fetch_projects_metadata()
    
    except Exception:
        raise exceptions.general_error()


@router.post("/intelligence/fetch")
async def fetch_intelligence(payload: Models.MitigationRequest) -> dict:
    """
    Fetch CVE/Advisory intelligence from multiple sources and save to file.
    
    This endpoint aggregates intelligence from configured sources (NVD, MITRE, GitHub CVE Project, 
    OSV.dev, endoflife.date, libraries.io, ClearlyDefined) and saves the raw data to a JSON file
    for later processing.
    
    Args:
        payload (Models.MitigationRequest): Request containing CVE ID or Advisory ID
    
    Returns:
        dict: Confirmation with file path and metadata
        
    Example:
        POST /api/v1/intelligence/fetch
        {
            "cveId": "CVE-2024-21626"
        }
        
        Response:
        {
            "status": "success",
            "cve_id": "CVE-2024-21626",
            "file_path": "app/data/intelligence/CVE-2024-21626.json",
            "sources_fetched": ["NVD", "MITRE", "GitHub CVE Project", "OSV.dev"],
            "fetched_at": "2024-01-15T10:30:00Z"
        }
    """
    try:
        logger.info(f"Fetching intelligence for {payload.cveId} from multiple sources")
        
        # Import helper functions
        from app.utils.helpers import aggregate_cve_intelligence, save_intelligence_to_file
        
        # Step 1: Aggregate intelligence from all configured sources
        aggregated_intel = await aggregate_cve_intelligence(payload.cveId)
        
        # Step 2: Save to file
        file_path = await save_intelligence_to_file(payload.cveId, aggregated_intel)
        
        # Step 3: Prepare response
        sources_used = list(aggregated_intel.get("sources", {}).keys())
        metadata = aggregated_intel.get("metadata", {})
        
        logger.info(f"Intelligence saved for {payload.cveId} to {file_path}")
        
        return {
            "status": "success",
            "cve_id": payload.cveId,
            "file_path": file_path,
            "sources_fetched": sources_used,
            "fetched_at": metadata.get("fetched_at"),
            "message": f"Intelligence data successfully fetched and saved for {payload.cveId}"
        }
        
    except Exception as e:
        logger.error(f"Error fetching intelligence: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch intelligence: {str(e)}")


@router.post("/intelligence/assess")
async def assess_intelligence(payload: Models.MitigationRequest) -> Models.StructuredIntelligenceResponse:
    """
    Assess CVE/Advisory intelligence from saved file or fetch if not available.
    
    This endpoint first attempts to load intelligence data from a previously saved file.
    If the file doesn't exist, it fetches the data from sources, saves it, and then processes it.
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
        
        # Import helper functions
        from app.utils.helpers import (
            load_intelligence_from_file,
            aggregate_cve_intelligence,
            save_intelligence_to_file,
            extract_structured_intelligence,
            save_to_intelligence_database
        )
        
        # Step 1: Try to load from file
        aggregated_intel = await load_intelligence_from_file(payload.cveId)
        
        # Step 2: If not found, fetch from sources and save
        if not aggregated_intel:
            logger.info(f"No saved file found for {payload.cveId}, fetching from sources")
            aggregated_intel = await aggregate_cve_intelligence(payload.cveId)
            
            # Save for future use
            file_path = await save_intelligence_to_file(payload.cveId, aggregated_intel)
            logger.info(f"Intelligence fetched and saved to {file_path}")
        else:
            logger.info(f"Loaded intelligence from saved file for {payload.cveId}")
        
        # Step 3: Extract structured data for database storage
        structured_data = await extract_structured_intelligence(aggregated_intel)
        
        # Step 4: Save to JSON database (insert or update)
        db_saved = await save_to_intelligence_database(structured_data)
        if db_saved:
            logger.info(f"Saved structured intelligence to database for {payload.cveId}")
        else:
            logger.warning(f"Failed to save to database for {payload.cveId}")
        
        logger.info(f"Intelligence assessed for {payload.cveId}")
        logger.info(f"Found {len(structured_data.products)} products, "
                   f"{len(structured_data.vendor_advisories)} advisories, "
                   f"{len(structured_data.patches)} patches, "
                   f"{len(structured_data.lifecycle)} lifecycle records")
        
        return structured_data
        
    except Exception as e:
        logger.error(f"Error assessing intelligence: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to assess intelligence: {str(e)}")


@router.get("/intelligence/files")
async def list_intelligence_files() -> dict:
    """
    List all saved intelligence files.
    
    Returns a list of all CVE/Advisory intelligence files that have been saved,
    including metadata like file size and last modified date.
    
    Returns:
        dict: List of saved intelligence files with metadata
        
    Example:
        GET /api/v1/intelligence/files
        
        Response:
        {
            "total_files": 5,
            "files": [
                {
                    "cve_id": "CVE-2024-21626",
                    "filename": "CVE-2024-21626.json",
                    "size_bytes": 15234,
                    "modified_at": "2024-01-15T10:30:00"
                },
                ...
            ]
        }
    """
    try:
        from app.utils.helpers import list_saved_intelligence_files
        
        files = await list_saved_intelligence_files()
        
        return {
            "total_files": len(files),
            "files": files
        }
        
    except Exception as e:
        logger.error(f"Error listing intelligence files: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list files: {str(e)}")
        raise exceptions.general_error() 
    