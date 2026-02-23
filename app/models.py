"""
Pydantic models for API requests and responses
Only includes models needed for targeted remediation API
"""
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class RemediationStep(BaseModel):
    """Enhanced remediation step with comprehensive details"""
    step_id: int
    title: str
    description: str
    action_type: str = "command"  # command, verification, backup, configuration, etc.
    commands: List[str] = []
    files_to_check: Optional[List[str]] = None
    directories_to_navigate: Optional[List[str]] = None
    expected_output: str = "Command executed successfully"
    verification_steps: Optional[List[str]] = None
    automation_possible: bool = True
    requires_sudo: bool = False
    estimated_time_minutes: Optional[int] = None
    
    class Config:
        # Pydantic v1 style config for excluding None values
        exclude_none = True

class TargetedRemediationRequest(BaseModel):
    """Request model for remediation plan generation"""
    advisory_id: str = Field(..., description="Advisory identifier (e.g., RHSA-2026:2783, ALAS-2024-1234) - REQUIRED")
    product: Optional[str] = Field(None, description="Product name (e.g., Red Hat Enterprise Linux 9). Optional - will be fetched from database if not provided.")
    package: Optional[str] = Field(None, description="Package name (e.g., nodejs, runc). Optional - will use first affected package from advisory if not provided.")

class TargetedRemediationResponse(BaseModel):
    """Response model for targeted remediation with comprehensive metadata"""
    advisory_id: str
    vendor: str
    title: str
    severity: str
    product: str
    package: str
    cve_ids: List[str] = []  # Array of related CVE IDs
    remediation_steps: List[RemediationStep]
    is_reboot_required: bool = False
    requires_maintenance_window: bool = False
    risk_level: str = "medium"  # critical, high, medium, low
    package_scope: str = "application"  # system or application
    estimated_downtime_minutes: Optional[int] = None
    generated_at: str
    saved_to_database: bool = False

# Made with Bob
