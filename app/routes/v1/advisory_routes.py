"""
Advisory remediation API routes
API: /api/v1/advisory/remediation/generate
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
        try:
            logger.info(f"Calling get_advisory_by_id for {advisory_id}")
            advisory_data = await get_advisory_by_id(advisory_id)
            logger.info(f"get_advisory_by_id returned: {type(advisory_data)}")
            
            if advisory_data:
                logger.info(f"Advisory data keys: {advisory_data.keys()}")
                logger.info(f"Advisory ID: {advisory_data.get('advisory_id')}")
                logger.info(f"Vendor: {advisory_data.get('vendor')}")
                logger.info(f"Title: {advisory_data.get('title')}")
                logger.info(f"Severity: {advisory_data.get('severity')}")
            else:
                logger.warning(f"advisory_data is None or empty")
                
        except Exception as db_error:
            logger.error(f"Database connection error for advisory {advisory_id}: {type(db_error).__name__}: {str(db_error)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=503,
                detail=f"Database connection error: {str(db_error)}. Please try again later."
            )
        
        if not advisory_data:
            logger.error(f"Advisory {advisory_id} not found in database")
            raise HTTPException(
                status_code=404,
                detail=f"Advisory {advisory_id} not found in database. Please run the assess API first to populate the database."
            )
        
        logger.info(f"Advisory data retrieved successfully, checking for existing remediation plan")
        logger.info(f"Number of CVEs: {len(advisory_data.get('cves', []))}")
        
        # Step 2: Check if remediation plan already exists
        if advisory_data.get("remediation_plan"):
            logger.info(f"Remediation plan already exists for {advisory_id}, returning cached version")
            
            # Handle remediation_plan - it should be a list of dicts
            remediation_plan = advisory_data["remediation_plan"]
            
            # Validate and convert to RemediationStep objects
            try:
                if isinstance(remediation_plan, list) and len(remediation_plan) > 0:
                    # Check if first item is a dict (expected format)
                    if isinstance(remediation_plan[0], dict):
                        remediation_steps = [Models.RemediationStep(**step) for step in remediation_plan]
                    else:
                        # If it's not a dict, log and regenerate
                        logger.warning(f"Remediation plan format invalid for {advisory_id}, regenerating...")
                        remediation_steps = None
                else:
                    logger.warning(f"Remediation plan empty for {advisory_id}, regenerating...")
                    remediation_steps = None
                    
                if remediation_steps:
                    return Models.AdvisoryRemediationResponse(
                        advisory_id=advisory_data["advisory_id"],
                        vendor=advisory_data["vendor"] or "Unknown",
                        title=advisory_data["title"] or "No title",
                        severity=advisory_data["severity"] or "UNKNOWN",
                        remediation_steps=remediation_steps,
                        generated_at=datetime.utcnow().isoformat(),
                        saved_to_database=True
                    )
            except Exception as e:
                logger.error(f"Error parsing cached remediation plan: {str(e)}")
                logger.info(f"Will regenerate remediation plan for {advisory_id}")
                # Continue to regenerate
        
        # Step 3: Prepare context for AI prompt
        logger.info(f"Preparing CVE information for prompt")
        cves_info_list = []
        for cve in advisory_data.get("cves", []):
            try:
                cve_id = cve.get('cve_id', 'Unknown')
                description = cve.get('description') or 'No description available'
                severity = cve.get('severity') or 'UNKNOWN'
                cvss_score = cve.get('cvss_score') or 'N/A'
                
                # Truncate description safely
                desc_preview = description[:200] if len(description) > 200 else description
                cve_line = f"- {cve_id}: {desc_preview}... (Severity: {severity}, CVSS: {cvss_score})"
                cves_info_list.append(cve_line)
                logger.debug(f"Added CVE info: {cve_id}")
            except Exception as cve_error:
                logger.error(f"Error processing CVE {cve.get('cve_id', 'unknown')}: {str(cve_error)}")
                continue
        
        cves_info = "\n".join(cves_info_list) if cves_info_list else "No CVE information available"
        logger.info(f"CVE information prepared: {len(cves_info_list)} CVEs")
        
        products_info = "Information available in advisory metadata"
        if advisory_data.get("metadata"):
            metadata_str = json.dumps(advisory_data["metadata"], indent=2)
        else:
            metadata_str = "No additional metadata available"
        
        # Step 4: Build prompt
        prompt_template = PromptTemplate(
            input_variables=["advisory_id", "vendor", "title", "severity", "advisory_url", "cves_info", "products_info", "metadata"],
            template=prompts.ADVISORY_REMEDIATION_STEPS
        )
        
        prompt_inputs = {
            "advisory_id": advisory_data["advisory_id"],
            "vendor": advisory_data["vendor"] or "Unknown",
            "title": advisory_data["title"] or "Security Advisory",
            "severity": advisory_data["severity"] or "UNKNOWN",
            "advisory_url": advisory_data["advisory_url"] or "N/A",
            "cves_info": cves_info if cves_info else "No CVE information available",
            "products_info": products_info,
            "metadata": metadata_str
        }
        
        logger.info(f"Calling WatsonX AI to generate remediation steps")
        
        # Step 5: Call WatsonX AI with increased token limit
        ai_response = query_llm(
            model_id="ibm/granite-3-8b-instruct",
            prompt_template=prompt_template,
            prompt_inputs=prompt_inputs,
            max_tokens=4000,  # Increased from 2000 to handle longer responses
            temperature=0.3
        )
        
        logger.info(f"AI response received, length: {len(ai_response)} characters")
        
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
            
            # Try to fix truncated JSON by closing incomplete structures
            if not cleaned_response.endswith(']'):
                logger.warning("Response appears truncated, attempting to fix JSON")
                # Count opening and closing brackets
                open_brackets = cleaned_response.count('[')
                close_brackets = cleaned_response.count(']')
                open_braces = cleaned_response.count('{')
                close_braces = cleaned_response.count('}')
                
                # Add missing closing brackets/braces
                if open_braces > close_braces:
                    cleaned_response += '}' * (open_braces - close_braces)
                if open_brackets > close_brackets:
                    cleaned_response += ']' * (open_brackets - close_brackets)
                
                logger.info(f"Fixed JSON structure, added {open_braces - close_braces} braces and {open_brackets - close_brackets} brackets")
            
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

# Made with Bob
