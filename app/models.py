from pydantic import BaseModel
from typing import Optional, List, Any
from enum import Enum

# Enums
class VulnerabilityType(str, Enum):
    CVE = "cve"
    ADVISORY = "advisory"

# Request Models
class MitigationRequest(BaseModel):
    cveId: str
    filename: Optional[str] = None
    type: Optional[VulnerabilityType] = VulnerabilityType.CVE
    useCache: Optional[bool] = True

class AdvisoryRemediationRequest(BaseModel):
    advisory_id: str

# Response Models
class RemediationStep(BaseModel):
    step_id: int
    title: str
    description: str
    commands: List[str]
    expected_output: str
    automation_possible: bool

class AdvisoryRemediationResponse(BaseModel):
    advisory_id: str
    vendor: str
    title: str
    severity: str
    remediation_steps: List[RemediationStep]
    generated_at: str
    saved_to_database: bool

# Structured Intelligence Models
class CVERecord(BaseModel):
    """CVE record with quantitative data for database storage"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    exploit_maturity: Optional[str] = None
    kev_listed: bool = False

class ProductRecord(BaseModel):
    """Product/Package record"""
    product_id: str
    product_name: str
    vendor: str
    product_family: str

class CVEProductMap(BaseModel):
    """Mapping between CVE and affected products"""
    cve_id: str
    product_id: str
    affected_version_range: str
    vendor_severity: str

class VendorAdvisory(BaseModel):
    """Vendor security advisory"""
    advisory_id: str
    vendor: str
    cve_id: str
    severity: str
    advisory_url: str
    published_date: str

class PatchRecord(BaseModel):
    """Patch/Fix information"""
    patch_id: str
    advisory_id: str
    product: str
    fixed_version: str
    reboot_required: bool
    patch_release_date: str

class CompatibilityRecord(BaseModel):
    """Product compatibility information"""
    source_product: str
    dependent_product: str
    supported_versions: List[str]
    certification_status: bool

class LifecycleRecord(BaseModel):
    """Product lifecycle information"""
    product: str
    version: str
    release_date: str
    eol_date: str
    extended_support: bool

class VersionPolicy(BaseModel):
    """Version policy rules"""
    policy_id: str
    product: str
    max_version_lag: int

class LicensePolicy(BaseModel):
    """License policy violations"""
    package: str
    license: str
    violation: bool

class StructuredIntelligenceResponse(BaseModel):
    """Complete structured intelligence response for database storage"""
    cve: CVERecord
    products: List[ProductRecord]
    cve_product_mappings: List[CVEProductMap]
    vendor_advisories: List[VendorAdvisory]
    patches: List[PatchRecord]
    compatibility: List[CompatibilityRecord]
    lifecycle: List[LifecycleRecord]
    version_policies: List[VersionPolicy]
    license_policies: List[LicensePolicy]
    intelligence_timestamp: str
    data_sources: List[str]

# Made with Bob
