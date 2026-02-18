from fastapi import APIRouter, HTTPException, Body
from app.services.ai import prompts
from langchain_core.prompts import PromptTemplate
from app.services.ai.llm_service import query_llm
import app.models as Models
import logging
from app.utils.helpers import generate_concert_headers, extract_code_as_string
from app.utils.httputil import get, post_form
from typing import Dict, List, Any
import json
import base64
import uuid
from app.core.constants import SNYK_SAST_RULES
from app.utils.fileutil import get_absolute_path, read_file
from app.services.wca_access_token_manager import WCAAccessTokenManager
import copy
from app.utils.fuzzy_matcher import fetch_mitigation_technique, fetch_comment_style

logger = logging.getLogger('exposure_routes')

router = APIRouter(
    prefix="/api/v1/exposure",
    tags=["Exposures"]
)

wca_token_manager = WCAAccessTokenManager()

@router.post("/remediation")
async def exposure_mitigation(payload: Models.ExposureMitigationRequest) -> Dict[str, str]:
    """
    Generate exposure mitigations for a specified vulnerability using Watsonx AI.

    Args:
        payload (ExposureMitigationRequest): The request payload containing:
            - vulnerabilityCategory (str): The vulnerability class.
            - vulnerableCodeLang (str): The programming language name.
            - vulnerableLineOfCode (str): The line where the vulnerability occurs.
            - vulnerableContextSnippet (str): Contextual code for the vulnerability.

    Returns:
        Dict[str, str]: A dictionary containing the mitigation details or an error message.

    Raises:
        HTTPException: If an error occurs during processing.
    """
    try:
        prompt_template = PromptTemplate(
            input_variables=["vuln_class", "vuln_root_cause", "vuln_lang", "vuln_line", "vuln_contextual_code"],
            template=prompts.SECURE_CODE_BLOCK_V1
        )

        # Prepare the LLM request
        llm_request = Models.LLMRequest(
            modelId="ibm/granite-3-8b-instruct",
            promptTemplate=prompt_template,
            promptInputs={
                "vuln_class": payload.vulnerabilityCategory,
                "vuln_root_cause": payload.rootCause,
                "vuln_lang": payload.vulnerableCodeLang,
                "vuln_line": payload.sourceCodeDetails.vulnerableLineOfCode,
                "vuln_contextual_code": payload.sourceCodeDetails.vulnerableContextSnippet
            }
        )

        # Query the LLM and return the result
        return query_llm(llm_request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    

@router.post("/scan/remediation")
async def exposure_mitigation(payload: Models.ScanRemediationRequest = Body(openapi_examples=Models.ScanRemediationRequest.Config.examples)) -> dict: # Models.ScanRemediationResponse:
    """
    Generate exposure mitigations for a specified vulnerability using Watsonx AI.

    Args:
        payload (Models.ScanRemediationRequest): The request payload containing:
            - context (str): The prompt context.

    Returns:
        Models.ScanRemediationResponse: The response containing the mitigation details.

    Raises:
        HTTPException: If an error occurs during processing.
    """
    try:
        # Create the prompt template
        prompt_template = PromptTemplate(
            input_variables=["prompt_context"],
            template=prompts.SCAN_REMEDIATION
        )

        # Prepare the LLM request
        llm_request = Models.LLMRequest(
            modelId="ibm/granite-3-8b-instruct",
            promptTemplate=prompt_template,
            promptInputs={
                "prompt_context": str(payload)
            }
        )

        # Query the LLM and return the result
        response = query_llm(llm_request)
        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred during processing: {str(e)}")

@router.post("/wca/remediation")
async def exposure_mitigation(payload: Models.ExposureMitigationRequest = Body(openapi_examples=Models.ExposureMitigationRequest.Config.examples)) -> Models.ExposureMitigationResponse:
    """
    Endpoint to handle exposure mitigation requests. 
    It integrates with IBM Cloud services to generate remediation code.
    """
    try:
        # Step 1: Retrieve the IAM access token
        access_token = await wca_token_manager.get_access_token()
        if not access_token:
            raise HTTPException(status_code=500, detail="Failed to retrieve access token")

        # Step 2: Prepare the prompt using the provided template and payload data
        prompt_template = PromptTemplate(
            input_variables=["vuln_class", "vuln_root_cause", "vuln_lang", "vuln_contextual_code", "mitigation_technique", "comment_symbol"], # "vuln_line",
            template=prompts.SECURE_CODE_BLOCK,
        )
        
        mitigation_technique = fetch_mitigation_technique(payload.vulnerabilityCategory)
        logger.info(f"Mitigation technique for {payload.vulnerabilityCategory} (requestId: ({payload.requestId})) is {mitigation_technique}")

        prompt = prompt_template.format(
            vuln_class=payload.vulnerabilityCategory,
            vuln_root_cause=payload.rootCause,
            vuln_lang=payload.vulnerableCodeLang,
            # vuln_line=payload.sourceCodeDetails.vulnerableLineOfCode,
            vuln_contextual_code=payload.sourceCodeDetails.vulnerableContextSnippet,
            mitigation_technique=mitigation_technique,
            comment_symbol=fetch_comment_style(payload.vulnerableCodeLang)
        )

        # logger.info(f"Prompt for requestId ({payload.requestId}) -- {prompt}")

        # Step 3: Create the input payload for the API request
        input_data = {
            "message_payload": {
                "messages": [{"content": prompt, "role": "USER"}]
            }
        }

        # Convert input data to base64-encoded JSON
        input_base64 = base64.b64encode(json.dumps(input_data).encode("utf-8")).decode("utf-8")
        request_id = str(uuid.uuid4())  # Generate a unique request ID

        # Define API endpoint and headers
        api_url = "https://api.dataplatform.cloud.ibm.com/v2/wca/core/chat/text/generation"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Request-ID": request_id,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # Step 4: Send the API request
        response = await post_form(
            url=api_url,
            form_data={"message": input_base64},
            headers=headers,
            timeout=45,  # Timeout adjusted for the API requirements
        )

        # Validate the response request ID to ensure consistency
        if response.get("request_id") != request_id:
            raise HTTPException(status_code=500, detail="Request ID mismatch")
        
        wca_response = response.get("response", {}).get("message", {}).get("content", "")
        wca_code_block = extract_code_as_string(wca_response)

        # Step 5: Return the fixed code from the API response
        return Models.ExposureMitigationResponse(
            requestId=payload.requestId,
            vulnerabilityCategory=payload.vulnerabilityCategory,
            rootCause=payload.rootCause,
            vulnerableCodeLang=payload.vulnerableCodeLang,
            sourceCodeDetails={
                "vulnerableContextSnippet": payload.sourceCodeDetails.vulnerableContextSnippet,
                "vulnerableLineOfCode": payload.sourceCodeDetails.vulnerableLineOfCode
            },
            remediationDetails={
                "revisedCodeSnippet": wca_code_block or wca_response,
                "isFixable": bool(wca_code_block)
            }
        )
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    
@router.post("/wca/v2/remediation")
async def exposure_mitigation(payload: Models.RemediateCodeExposuresRequest = Body(openapi_examples=Models.RemediateCodeExposuresRequest.Config.examples)) -> Models.RemediateCodeExposuresResponse:
    """
    Endpoint to handle exposure mitigation requests. 
    It integrates with IBM Cloud services to generate remediation code.
    """
    try:
        # Step 1: Retrieve the IAM access token
        access_token = await wca_token_manager.get_access_token()
        if not access_token:
            raise HTTPException(status_code=500, detail="Failed to retrieve access token")

        # Step 2: Prepare the prompt using the provided template and payload data
        prompt_template = PromptTemplate(
            input_variables=["vuln_lang", "comment_symbol", "vulnerabilities_info", "file_content"],
            template=prompts.REMEDIATE_CODE_EXPOSURES,
        )
        
        # mitigation_technique = fetch_mitigation_technique(payload.vulnerabilityCategory)
        # logger.info(f"Mitigation technique for {payload.vulnerabilityCategory} (requestId: ({payload.requestId})) is {mitigation_technique}")

        prompt = prompt_template.format(
            vuln_lang=payload.vulnerableCodeLang,
            comment_symbol=fetch_comment_style(payload.vulnerableCodeLang),
            vulnerabilities_info=payload.vulnerabilitiesInfo,
            file_content=payload.fileContent
        )

        logger.info(f"Prompt for requestId ({payload.requestId}) -- {prompt}")

        # Generate a unique request ID
        request_id = str(uuid.uuid4()) 

        # Step 3: Create the input payload for the API request
        input_data = {
            "message_payload": {
                "chat_session_id": request_id,
                "messages": [{"content": prompt, "role": "USER"}]
            }
        }

        # Convert input data to base64-encoded JSON
        input_base64 = base64.b64encode(json.dumps(input_data).encode("utf-8")).decode("utf-8")

        # Define API endpoint and headers
        api_url = "https://api.dataplatform.cloud.ibm.com/v2/wca/core/chat/text/generation"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Request-ID": request_id,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # Step 4: Send the API request
        response = await post_form(
            url=api_url,
            form_data={"message": input_base64},
            headers=headers,
            timeout=90,  # Timeout adjusted for the API requirements
        )

        # Validate the response request ID to ensure consistency
        if response.get("request_id") != request_id:
            raise HTTPException(status_code=500, detail="Request ID mismatch")
        
        wca_response = response.get("response", {}).get("message", {}).get("content", "")
        wca_file_content = extract_code_as_string(wca_response)

        # Step 5: Return the fixed code from the API response
        return Models.RemediateCodeExposuresResponse(
            requestId=payload.requestId,
            vulnerableCodeLang=payload.vulnerableCodeLang,
            fileContent=wca_file_content,
            filepath=payload.filepath
        )
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@router.post("/list")
async def exposure_list(payload: Models.ExposureListRequest = Body(openapi_examples=Models.ExposureListRequest.Config.examples)) -> Models.ExposureListResponse:
    """
    Provides a list of exposures available in Concert, filtered by repository name.

    Args:
        payload (ExposureListRequest): The request payload containing:
            - repositoryId (str): The repository ID to filter exposures.

    Returns:
        ExposureListResponse: A response model containing the list of exposures.

    Raises:
        HTTPException: If an error occurs during processing.
    """
    try:
        # Generate necessary headers for the Concert API
        concert_headers = await generate_concert_headers()

        # Make the GET request to the Concert API
        response = await get(
            url="https://sk1.fyre.ibm.com:12443/core/api/v1/vulnerability/exposures",
            query_params={
                # "page_number": 1,
                # "page_size": 50,
                "sort_by": "priority",
                "sort_direction": "desc",
                "filter": f"repository_id:{payload.repositoryId}",
            },
            headers=concert_headers,
            timeout=30,
        )

        # Initialize a list to hold filtered exposures
        filtered_exposures = []

        # Iterate through exposures from the response
        for exposure in response.get("exposures", []):
            try:
                # Safely parse the additional_data JSON string
                additional_data = json.loads(exposure.get("additional_data", "{}"))
            except json.JSONDecodeError:
                continue  # Skip this exposure if additional_data cannot be parsed

            # Remove project name prefix from the exposure path if present
            exposure_path = exposure.get("exposure_path", "")
            if ":" in exposure_path:
                exposure_path = exposure_path.split(":", 1)[-1]
            exposure["exposure_path"] = exposure_path

            # Extract the line number(s) from additional_data.
            # Example value: "68, 48, 85, 27"
            line_numbers_str = additional_data.get("linenumber", "")
            if not line_numbers_str:
                continue  # Skip if no line number is provided

            # Split the string by comma, and strip whitespace.
            line_numbers = [num.strip() for num in line_numbers_str.split(",") if num.strip().isdigit()]
            if not line_numbers:
                continue  # Skip if no valid numeric line numbers are found

            # For each valid line number, create a separate exposure dictionary.
            for num in line_numbers:
                # Use a deep copy to avoid modifying the original exposure
                new_exposure = copy.deepcopy(exposure)
                new_exposure["linenumber"] = int(num)

                # Look up additional details from SNYK_SAST_RULES
                for rule in SNYK_SAST_RULES:
                    if rule["id"] == new_exposure.get("rule_id"):
                        new_exposure["shortDescription"] = rule.get("shortDescription")
                        new_exposure["category"] = rule.get("name")
                        new_exposure["short_description"] = rule.get("shortDescription")
                        new_exposure["issue_type"] = rule.get("name")
                        new_exposure["thread_class"] = rule.get("threadClass")
                        break

                filtered_exposures.append(new_exposure)

        # Update the response with the filtered exposures
        response["exposures"] = filtered_exposures

        return response
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=f"An error occurred while making a GET request: {str(e)}")
    except RuntimeError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"HTTP error: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
    
@router.post("/appscan/list")
async def exposure_list(payload: Models.ExposureListRequest = Body(openapi_examples=Models.ExposureListRequest.Config.examples)) -> Models.HCLExposureListResponse:
    """
    Handles the POST request to list exposures based on SAST report analysis.

    Args:
        payload (Models.ExposureListRequest): The request body containing data for the exposure list.

    Returns:
        Models.HCLExposureListResponse: A structured response containing the exposures derived from the SAST report.
    """
    try:
        sast_report = read_file(get_absolute_path("app/scan_reports/appscan_sast_report.json"), json.loads)
        
        # Extract and transform exposure data from the SAST report
        exposures_list: List[Dict[str, Any]] = sast_report['runs'][0]['results']

        # Convert the raw SAST data into the required API response format
        converted_data = [
            {
                "id": str(uuid.uuid4()),  # Generate a unique identifier for each entry
                "category": entry["ruleId"],
                "description": entry["description"],
                "exposure_path": entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "issue_type": entry["ruleId"],
                "linenumber": entry["locations"][0]["physicalLocation"]["region"]["startLine"],
                "severity": entry["level"],
                "short_description": entry["message"]["text"],
                "shortDescription": entry["message"]["text"],
                "thread_class": entry.get("threadClass", "N/A"),
            }
            for entry in exposures_list
        ]

        return { "exposures": converted_data }
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=f"An error occurred while making a GET request: {str(e)}")
    except RuntimeError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"HTTP error: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")