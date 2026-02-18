"""
Advisory remediation API routes
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import logging
import json
from datetime import datetime
from langchain_core.prompts import PromptTemplate

from app import models as Models
from app.db.operations import get_advisory_by_id, update_advisory_remediation
from app.services.ai.llm_service import query_llm
from app.services.ai import prompts

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/advisory/remediation/generate", response_model=Models.AdvisoryRemediationResponse)
async def generate_advisory_remediation(request: Models.AdvisoryRemediationRequest):
    """
    Generate remediation steps for an advisory using WatsonX AI
    
    Args:
        request: Advisory remediation request with advisory_id
    
    Returns:
        AdvisoryRemediationResponse with generated remediation steps
    """
    try:
        advisory_id = request.advisory_id
        logger.info(f"Generating remediation steps for advisory: {advisory_id}")
        
        # Step 1: Fetch advisory data from database
        advisory_data = await get_advisory_by_id(advisory_id)
        
        if not advisory_data:
            raise HTTPException(
                status_code=404,
                detail=f"Advisory {advisory_id} not found in database"
            )
        
        # Step 2: Check if remediation plan already exists
        if advisory_data.get("remediation_plan"):
            logger.info(f"Remediation plan already exists for {advisory_id}, returning cached version")
            return Models.AdvisoryRemediationResponse(
                advisory_id=advisory_data["advisory_id"],
                vendor=advisory_data["vendor"] or "Unknown",
                title=advisory_data["title"] or "No title",
                severity=advisory_data["severity"] or "UNKNOWN",
                remediation_steps=[Models.RemediationStep(**step) for step in advisory_data["remediation_plan"]],
                generated_at=datetime.utcnow().isoformat(),
                saved_to_database=True
            )
        
        # Step 3: Prepare context for AI prompt
        cves_info = "\n".join([
            f"- {cve['cve_id']}: {cve['description'][:200]}... (Severity: {cve['severity']}, CVSS: {cve['cvss_score']})"
            for cve in advisory_data.get("cves", [])
        ])
        
        products_info = "Information available in advisory metadata"
        if advisory_data.get("metadata"):
            metadata_str = json.dumps(advisory_data["metadata"], indent=2)
        else:
            metadata_str = "No additional metadata available"
        
        # Step 4: Build prompt
        prompt_context = prompts.ADVISORY_REMEDIATION_STEPS.format(
            advisory_id=advisory_data["advisory_id"],
            vendor=advisory_data["vendor"] or "Unknown",
            title=advisory_data["title"] or "Security Advisory",
            severity=advisory_data["severity"] or "UNKNOWN",
            advisory_url=advisory_data["advisory_url"] or "N/A",
            cves_info=cves_info if cves_info else "No CVE information available",
            products_info=products_info,
            metadata=metadata_str
        )
        
        logger.info(f"Calling WatsonX AI to generate remediation steps")
        
        # Step 5: Call WatsonX AI directly without PromptTemplate
        # (since the prompt is already formatted and has no variables)
        from ibm_watsonx_ai.metanames import GenTextParamsMetaNames
        from langchain_ibm import WatsonxLLM
        import os
        
        parameters = {
            GenTextParamsMetaNames.DECODING_METHOD: "sample",
            GenTextParamsMetaNames.MAX_NEW_TOKENS: 2000,
            GenTextParamsMetaNames.MIN_NEW_TOKENS: 1,
            GenTextParamsMetaNames.TEMPERATURE: 0.3,
            GenTextParamsMetaNames.TOP_K: 50,
            GenTextParamsMetaNames.TOP_P: 1,
        }
        
        watsonx_llm = WatsonxLLM(
            model_id="ibm/granite-3-8b-instruct",
            url=os.getenv("WATSONX_URL"),
            apikey=os.getenv("WATSONX_API_KEY"),
            project_id=os.getenv("WATSONX_API_PROJECT_ID"),
            params=parameters,
            verbose=True
        )
        
        ai_response = watsonx_llm.invoke(prompt_context)
        
        # Step 6: Parse AI response
        try:
            # Clean the response - remove markdown code blocks if present
            cleaned_response = ai_response.strip()
            if cleaned_response.startswith("```json"):
                cleaned_response = cleaned_response[7:]
            if cleaned_response.startswith("```"):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith("```"):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()
            
            remediation_steps_data = json.loads(cleaned_response)
            
            # Validate it's a list
            if not isinstance(remediation_steps_data, list):
                raise ValueError("AI response is not a JSON array")
            
            # Convert to Pydantic models
            remediation_steps = [Models.RemediationStep(**step) for step in remediation_steps_data]
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {str(e)}")
            logger.error(f"AI Response: {ai_response[:500]}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to parse AI response: {str(e)}"
            )
        except Exception as e:
            logger.error(f"Error processing AI response: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Error processing remediation steps: {str(e)}"
            )
        
        # Step 7: Save to database
        saved = await update_advisory_remediation(
            advisory_id=advisory_id,
            remediation_plan=remediation_steps_data
        )
        
        if not saved:
            logger.warning(f"Failed to save remediation plan to database for {advisory_id}")
        
        # Step 8: Return response
        return Models.AdvisoryRemediationResponse(
            advisory_id=advisory_data["advisory_id"],
            vendor=advisory_data["vendor"] or "Unknown",
            title=advisory_data["title"] or "No title",
            severity=advisory_data["severity"] or "UNKNOWN",
            remediation_steps=remediation_steps,
            generated_at=datetime.utcnow().isoformat(),
            saved_to_database=saved
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating remediation for advisory {request.advisory_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@router.get("/advisory/{advisory_id}")
async def get_advisory(advisory_id: str):
    """
    Get advisory details including remediation plan if available
    
    Args:
        advisory_id: Advisory ID
    
    Returns:
        Advisory details with remediation plan
    """
    try:
        advisory_data = await get_advisory_by_id(advisory_id)
        
        if not advisory_data:
            raise HTTPException(
                status_code=404,
                detail=f"Advisory {advisory_id} not found"
            )
        
        return advisory_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching advisory {advisory_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )