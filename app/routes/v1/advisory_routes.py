"""
Advisory remediation API routes - Targeted Remediation Only
API: /api/v1/advisory/remediation/generate-targeted
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


@router.post("/advisory/remediation/generate-targeted", response_model=Models.TargetedRemediationResponse, response_model_exclude_none=True)
async def generate_targeted_remediation(request: Models.TargetedRemediationRequest):
    """
    Generate targeted remediation steps for a specific product/package combination within an advisory
    
    This API fetches CVEs from the database based on advisory_id, product, and package,
    then generates comprehensive remediation steps including file checks, directory navigation,
    and verification steps.
    
    Args:
        request: Targeted remediation request with advisory_id, product, and package
    
    Returns:
        TargetedRemediationResponse with product-specific remediation steps and metadata
    """
    try:
        advisory_id = request.advisory_id
        logger.info(f"Generating targeted remediation for advisory: {advisory_id}, Product: {request.product}, Package: {request.package}")
        
        # Step 1: Fetch advisory data from database
        try:
            logger.info(f"Calling get_advisory_by_id for {advisory_id}")
            advisory_data = await get_advisory_by_id(advisory_id)
            
            if advisory_data:
                logger.info(f"Advisory data retrieved for {advisory_id}")
            else:
                logger.warning(f"advisory_data is None or empty")
                
        except Exception as db_error:
            logger.error(f"Database connection error for advisory {advisory_id}: {type(db_error).__name__}: {str(db_error)}")
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
        
        # Step 2: Get all CVEs related to this advisory, product, and package
        cves_list = advisory_data.get("cves", [])
        
        # Filter CVEs that might be related to the specific product/package
        relevant_cves = []
        cve_ids = []
        highest_severity = advisory_data.get("severity", "MEDIUM").upper()  # Use advisory severity as default
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        
        if cves_list:
            for cve in cves_list:
                cve_id = cve.get('cve_id')
                if cve_id:
                    cve_ids.append(cve_id)
                    relevant_cves.append(cve)
                    
                    # Track highest severity
                    cve_severity = cve.get('severity', 'UNKNOWN').upper()
                    if severity_order.get(cve_severity, 0) > severity_order.get(highest_severity, 0):
                        highest_severity = cve_severity
            
            logger.info(f"Found {len(relevant_cves)} CVEs for {request.product}/{request.package}")
        else:
            logger.warning(f"No CVEs found in advisory {advisory_id}, will use advisory information only")
            cve_ids = []
        
        # Step 3: Prepare targeted context for AI prompt
        if relevant_cves:
            # Use CVE information if available
            cves_info_parts = []
            for cve in relevant_cves[:5]:  # Limit to first 5 CVEs to avoid token limits
                cve_id = cve.get('cve_id')
                cve_description = cve.get('description') or 'No description available'
                cve_severity = cve.get('severity') or 'UNKNOWN'
                cve_cvss = cve.get('cvss_score') or 'N/A'
                
                # Truncate description
                desc_preview = cve_description[:300] if len(cve_description) > 300 else cve_description
                
                cves_info_parts.append(
                    f"CVE: {cve_id}\n"
                    f"Severity: {cve_severity} (CVSS: {cve_cvss})\n"
                    f"Description: {desc_preview}"
                )
            
            cves_info = "\n\n".join(cves_info_parts)
        else:
            # Use advisory information directly
            advisory_title = advisory_data.get("title", "Security Advisory")
            advisory_severity = advisory_data.get("severity", "UNKNOWN")
            
            cves_info = (
                f"Advisory: {advisory_id}\n"
                f"Severity: {advisory_severity}\n"
                f"Title: {advisory_title}\n"
                f"Description: Security update for {request.package} in {request.product}\n"
                f"Note: Specific CVE details not available in database. "
                f"Remediation steps will be based on advisory information and package update best practices."
            )
        
        # Step 4: Build targeted prompt with specific product/package
        # Create products_info from product and package
        products_info = f"Product: {request.product}\nPackage: {request.package}"
        
        prompt_template = PromptTemplate(
            input_variables=["advisory_id", "vendor", "title", "severity", "advisory_url", "cves_info", "products_info", "metadata"],
            template=prompts.ADVISORY_REMEDIATION_STEPS
        )
        
        metadata_str = json.dumps(advisory_data.get("metadata", {}), indent=2) if advisory_data.get("metadata") else "No additional metadata available"
        
        prompt_inputs = {
            "advisory_id": advisory_data["advisory_id"],
            "vendor": advisory_data["vendor"] or "Unknown",
            "title": advisory_data["title"] or "Security Advisory",
            "severity": advisory_data["severity"] or "UNKNOWN",
            "advisory_url": advisory_data["advisory_url"] or "N/A",
            "cves_info": cves_info,
            "products_info": products_info,
            "metadata": metadata_str
        }
        
        logger.info(f"Calling WatsonX AI to generate targeted remediation steps for {request.product}/{request.package}")
        
        # Call WatsonX AI with increased token limit for comprehensive steps
        ai_response = query_llm(
            model_id="ibm/granite-3-8b-instruct",
            prompt_template=prompt_template,
            prompt_inputs=prompt_inputs,
            max_tokens=8000,  # Increased for 14 comprehensive steps
            temperature=0.3
        )
        
        logger.info(f"AI response received, length: {len(ai_response)} characters")
        
        # Parse AI response with robust error handling
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
            
            # Try to fix truncated or malformed JSON
            if not cleaned_response.endswith(']'):
                logger.warning("Response appears truncated or malformed, attempting to fix JSON")
                
                # Find the last complete JSON object by looking for the last complete }
                last_complete_brace = cleaned_response.rfind('}')
                if last_complete_brace > 0:
                    # Truncate to last complete object
                    cleaned_response = cleaned_response[:last_complete_brace + 1]
                    logger.info(f"Truncated to last complete object at position {last_complete_brace}")
                else:
                    # If no complete object found, try to find last complete field
                    logger.warning("No complete object found, attempting to recover partial data")
                    # Find the last comma or opening brace
                    last_comma = cleaned_response.rfind(',')
                    last_open_brace = cleaned_response.rfind('{')
                    if last_comma > last_open_brace:
                        cleaned_response = cleaned_response[:last_comma]
                    elif last_open_brace > 0:
                        cleaned_response = cleaned_response[:last_open_brace]
                
                # Count opening and closing brackets
                open_brackets = cleaned_response.count('[')
                close_brackets = cleaned_response.count(']')
                open_braces = cleaned_response.count('{')
                close_braces = cleaned_response.count('}')
                
                # Add missing closing brackets/braces
                if open_braces > close_braces:
                    cleaned_response += '}' * (open_braces - close_braces)
                    logger.info(f"Added {open_braces - close_braces} closing braces")
                if open_brackets > close_brackets:
                    cleaned_response += ']' * (open_brackets - close_brackets)
                    logger.info(f"Added {open_brackets - close_brackets} closing brackets")
            
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
        
        # Step 7: Save to database (optional - can save targeted remediation separately)
        saved = await update_advisory_remediation(
            advisory_id=advisory_id,
            remediation_plan=remediation_steps_data
        )
        
        if not saved:
            logger.warning(f"Failed to save targeted remediation plan to database for {advisory_id}")
        
        # Step 8: Determine additional metadata
        # Check if reboot is required (kernel, systemd, glibc, etc.)
        is_reboot_required = any(
            keyword in request.package.lower()
            for keyword in ['kernel', 'systemd', 'glibc', 'dbus', 'init']
        )
        
        # Determine if maintenance window is required
        requires_maintenance_window = is_reboot_required or highest_severity in ["CRITICAL", "HIGH"]
        
        # Determine package scope
        package_scope = "kernel" if "kernel" in request.package.lower() else \
                       "system" if any(s in request.package.lower() for s in ['systemd', 'glibc', 'dbus', 'init', 'pam']) else \
                       "library" if any(s in request.package.lower() for s in ['lib', 'ssl', 'crypto']) else \
                       "application"
        
        # Estimate downtime
        estimated_downtime = None
        if is_reboot_required:
            estimated_downtime = 10  # 10 minutes for reboot
        elif package_scope == "system":
            estimated_downtime = 5  # 5 minutes for system services
        elif requires_maintenance_window:
            estimated_downtime = 2  # 2 minutes for critical updates
        
        # Step 9: Return targeted response with comprehensive metadata
        return Models.TargetedRemediationResponse(
            advisory_id=advisory_data["advisory_id"],
            vendor=advisory_data["vendor"] or "Unknown",
            title=advisory_data["title"] or "No title",
            severity=advisory_data["severity"] or "UNKNOWN",
            product=request.product,
            package=request.package,
            cve_ids=cve_ids,
            remediation_steps=remediation_steps,
            is_reboot_required=is_reboot_required,
            requires_maintenance_window=requires_maintenance_window,
            risk_level=highest_severity,
            package_scope=package_scope,
            estimated_downtime_minutes=estimated_downtime,
            generated_at=datetime.utcnow().isoformat(),
            saved_to_database=saved
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating targeted remediation for advisory {request.advisory_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


# Made with Bob
