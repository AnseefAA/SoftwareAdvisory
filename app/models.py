from pydantic import BaseModel, Field
from langchain_core.prompts import PromptTemplate
from typing import Optional, List, Any, Union
from enum import Enum
from datetime import datetime
import uuid

class BooleanChoice(str, Enum):
    YES = "Yes"
    NO = "No"

class PriorityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class VulnerabilityType(str, Enum):
    CVE = "cve"
    ADVISORY = "advisory"

class MitigationRequest(BaseModel):
    cveId: str
    filename: Optional[str] = None  # Optional - only needed for file-based lookups
    type: Optional[VulnerabilityType] = VulnerabilityType.CVE
    useCache: Optional[bool] = True

class LLMVulnerabilityResponse(BaseModel):
    description: Optional[str] = None
    protectionMeasures: Optional[str] = None
    isFixAvailable: Optional[BooleanChoice]
    estimatedFixHours: Optional[str] = None
    fixComplexity: Optional[PriorityLevel] = None    
    isZeroDayVulnerability: Optional[bool] = False
    exploitReferences: Optional[List[str]] = []
    zeroDayReferences: Optional[List[str]] = []
    patchReferences: Optional[List[str]] = []
    impactCheckQuestions: Optional[List[str]] = []
    cvssScore: Optional[Any] = None
    cvssSeverity: Optional[PriorityLevel] = None    
    affectedVersions: Optional[List[str]] = []
    
class LLMRequest(BaseModel):
    modelId: str
    promptTemplate: PromptTemplate
    promptInputs: dict
    
class VulnerabilityInfo(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    score: Union[float, int]
    fileName: str
    lastModifiedDate: str
    
class CVEInfo(BaseModel):
    cve: Optional[str] = None
    cvss: Optional[Union[float, int]] = None
    severity: Optional[str] = None
    vector: Optional[str] = None
    description: Optional[str] = None
    related_cves:  Optional[List[str]] = []
    aliases : Optional[List[str]] = []


class CVSS(BaseModel):
    V3Score: float
    V3Vector: str

class VulnerabilityDetail(BaseModel):
    VulnerabilityID: str
    Title: str
    Description: str
    Severity: str
    CVSS: CVSS
    PublishedDate: datetime
    LastModifiedDate: datetime
    PrimaryURL: str

class CVERequest(BaseModel):
    context: str
    filename: str

class CVEResponse(BaseModel):
    agent: str
    question: str
    response: str
    
class ProjectMetadata(BaseModel):
    name: str
    filename: str

class Feedback(BaseModel):
    likeCount: Optional[int] = 0
    dislikeCount: Optional[int] = 0

class FeedbackAction(str, Enum):
    LIKE = "Like"
    DISLIKE = "Dislike"

class FeedbackRequest(BaseModel):
    cveId: str
    filename: str
    action: FeedbackAction

class FeedbackResponse(BaseModel):
    action: FeedbackAction
    likeCount: int
    dislikeCount: int
    
class ProjectFeedbackResponse(BaseModel):
    project_name: str
    likeCount: int
    dislikeCount: int

class GetFeedbackResponse(BaseModel):
    likeCount: int = 0
    dislikeCount: int = 0

class SourceCodeDetails(BaseModel):
    vulnerableContextSnippet: str
    vulnerableLineOfCode: str

class ExposureMitigationRequest(BaseModel):
    requestId: Optional[Union[str, int]] = Field(default_factory=lambda: str(uuid.uuid4()))
    vulnerabilityCategory: str
    rootCause: Optional[str] = ""
    vulnerableCodeLang: str
    sourceCodeDetails: SourceCodeDetails

    class Config:
        examples = {
            "default": {
                "value": {
                    "requestId": "123",
                    "vulnerabilityCategory": "SQL Injection",
                    "rootCause": "No validation was done in order to make sure that user input matches the data type expected",
                    "vulnerableCodeLang": "python",
                    "sourceCodeDetails": {
                        "vulnerableLineOfCode": "const query = `SELECT * FROM users WHERE id = '${userId}'`",
                        "vulnerableContextSnippet": "app.get('/user', (req, res) => {\n    const userId = req.query.id; // User input not sanitized\n    const query = `SELECT * FROM users WHERE id = '${userId}'`;\n\n    db.query(query, (error, results) => {\n        if (error) {\n            res.status(500).send('Database error');\n            return;\n        }\n        res.send(results);\n    });\n});"
                    }
                }
            }
        }

class RemediatedCode(BaseModel):
    revisedCodeSnippet: str
    isFixable: Optional[bool] = True

class ExposureMitigationResponse(ExposureMitigationRequest):
    remediationDetails: RemediatedCode

class RemediateCodeExposuresRequest(BaseModel):
    requestId: Optional[Union[str, int]] = Field(default_factory=lambda: str(uuid.uuid4()))
    vulnerableCodeLang: str
    vulnerabilitiesInfo: Optional[Union[dict, list, str]] = ""
    fileContent: str
    filepath: str

    class Config:
        examples = {
            "default": {
                "value": {
                    "requestId": "123",
                    "vulnerableCodeLang": "python",
                    "vulnerabilitiesInfo": {},
                    "fileContent": "",
                    "filepath": ""
                }
            }
        }

class RemediateCodeExposuresResponse(BaseModel):
    requestId: Optional[Union[str, int]] = Field(default_factory=lambda: str(uuid.uuid4()))
    vulnerableCodeLang: str
    fileContent: str
    filepath: str 

class ExposureListRequest(BaseModel):
    repositoryId: str

    class Config:
        examples = {
            "default": {
                "summary": "Default Repository Id",
                "description": "",
                "value": {
                    "repositoryId": "f1461cb9-c0fa-429b-80a0-22b771f40d48", 
                }
            }
        }

class ExposureDict(BaseModel):
    additional_data: str
    associations: dict
    created_on: int
    description: str

# Advisory Remediation Models
class RemediationStep(BaseModel):
    step_id: int
    title: str
    description: str
    commands: List[str]
    expected_output: str
    automation_possible: bool

class AdvisoryRemediationRequest(BaseModel):
    advisory_id: str
    
class AdvisoryRemediationResponse(BaseModel):
    advisory_id: str
    vendor: str
    title: str
    severity: str
    remediation_steps: List[RemediationStep]
    generated_at: str
    saved_to_database: bool

class ExposureListResponse(BaseModel):
    exposures: List[ExposureDict]

class HCLExposureDict(BaseModel):
    id: str
    category: Optional[str] = ""
    description: str
    exposure_path: str
    issue_type: Optional[str] = ""
    linenumber: Optional[int] = None
    severity: str
    short_description: Optional[str] = ""
    shortDescription: Optional[str] = ""
    thread_class: Optional[str] = ""

class HCLExposureListResponse(BaseModel):
    exposures: List[HCLExposureDict]

class ScanRemediationRequest(BaseModel):
    cve: str
    description: str
    family: str
    pluginName: str
    pluginId: int
    stepsToRemediate: Optional[str] = ""
    platform: Optional[str] = ""

    class Config:
        examples={
            "default": {
                "value": {
                    "pluginName": "Apache Tomcat 9.0.0.M1 < 9.0.98 multiple vulnerabilities",
                    "family": "Web Servers",
                    "description": "The version of Tomcat installed on the remote host is prior to 9.0.98. It is, therefore, affected by multiple vulnerabilities as referenced in the fixed_in_apache_tomcat_9.0.98_security-9 advisory.\n\n  - Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability during JSP compilation in Apache Tomcat     permits an RCE on case insensitive file systems when the default servlet is enabled for write (non-default     configuration). This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.1, from 10.1.0-M1 through     10.1.33, from 9.0.0.M1 through 9.0.97. Users are recommended to upgrade to version 11.0.2, 10.1.34 or     9.0.98, which fixes the issue. (CVE-2024-50379)\n\n  - Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Apache Tomcat. This issue affects     Apache Tomcat: from 11.0.0-M1 through 11.0.1, from 10.1.0-M1 through 10.1.33, from 9.0.0.M1 through     9.0.97. The mitigation for CVE-2024-50379 was incomplete. Users running Tomcat on a case insensitive file     system with the default servlet write enabled (readonly initialisation parameter set to the non-default     value of false) may need additional configuration to fully mitigate CVE-2024-50379 depending on which     version of Java they are using with Tomcat: - running on Java 8 or Java 11: the system property     sun.io.useCanonCaches must be explicitly set to false (it defaults to true) - running on Java 17: the     system property sun.io.useCanonCaches, if set, must be set to false (it defaults to false) - running on     Java 21 onwards: no further configuration is required (the system property and the problematic cache have     been removed) Tomcat 11.0.3, 10.1.35 and 9.0.99 onwards will include checks that sun.io.useCanonCaches is     set appropriately before allowing the default servlet to be write enabled on a case insensitive file     system. Tomcat will also set sun.io.useCanonCaches to false by default where it can. (CVE-2024-56337)\n\n  - Uncontrolled Resource Consumption vulnerability in the examples web application provided with Apache     Tomcat leads to denial of service. This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.1, from     10.1.0-M1 through 10.1.33, from 9.0.0.M1 through 9.9.97. Users are recommended to upgrade to version     11.0.2, 10.1.34 or 9.0.98, which fixes the issue. (CVE-2024-54677)\n\nNote that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.",
                    "stepsToRemediate": "Upgrade to Apache Tomcat version 9.0.98 or later.",
                    "cve": "CVE-2024-50379,CVE-2024-54677,CVE-2024-56337",
                    "pluginId": "213078",
                    "platform": "Linux"
                }
            }
        }

class ScanRemediationResponse(BaseModel):
    type: str
    name: str
    affectedVersions: List[str]
    fixVersion: str

# Enhanced Data Models for Comprehensive Vulnerability Analysis

class EnhancedCVE(BaseModel):
    """Enhanced CVE model with additional security context"""
    cve_id: str
    description: str
    severity: str
    cvss_score: Union[float, int]
    kev_listed: Optional[bool] = False  # Known Exploited Vulnerabilities
    exploit_maturity: Optional[str] = None  # e.g., "Proof of Concept", "Functional", "High", "Not Defined"

class Asset(BaseModel):
    """Asset information where vulnerability is found"""
    asset_id: Optional[str] = None
    hostname: Optional[str] = None
    environment: Optional[str] = None  # e.g., "Production", "Staging", "Development"
    business_tier: Optional[str] = None  # e.g., "Critical", "High", "Medium", "Low"
    internet_exposed: Optional[bool] = False

class Product(BaseModel):
    """Product/Package information"""
    product_name: str
    version: str
    vendor: Optional[str] = None
    release_date: Optional[str] = None

class ApplicationCertification(BaseModel):
    """Application certification and support status"""
    app_id: Optional[str] = None
    product: str
    supported_versions: Optional[List[str]] = []
    certification_status: Optional[str] = None  # e.g., "Certified", "Deprecated", "Unsupported"

class Dependency(BaseModel):
    """Dependency chain information"""
    parent_component: Optional[str] = None
    dependency_component: str
    depth: Optional[int] = 0  # Depth in dependency tree

class Policy(BaseModel):
    """Security policy information"""
    policy_id: Optional[str] = None
    rule_type: Optional[str] = None  # e.g., "CVE Severity", "Age", "Exploit Available"
    threshold: Optional[str] = None  # e.g., "CRITICAL", "7.0+", "30 days"

class EnhancedVulnerabilityInfo(BaseModel):
    """Comprehensive vulnerability information with all context"""
    # Core CVE Information
    cve: EnhancedCVE
    
    # Asset Context
    asset: Optional[Asset] = None
    
    # Product Information
    product: Product
    
    # Application Certification
    app_certification: Optional[ApplicationCertification] = None
    
    # Dependency Information
    dependency: Optional[Dependency] = None
    
    # Policy Compliance
    policy: Optional[Policy] = None
    
    # Additional metadata
    file_name: Optional[str] = None
    last_modified_date: Optional[str] = None
    published_date: Optional[str] = None
    
    # Remediation info
    fixed_version: Optional[str] = None
    references: Optional[List[str]] = []

class EnhancedVulnerabilityRequest(BaseModel):
    """Request model for enhanced vulnerability analysis"""
    cveId: str
    filename: str
    type: Optional[VulnerabilityType] = VulnerabilityType.CVE
    useCache: Optional[bool] = True
    includeAssetContext: Optional[bool] = False
    includePolicyCheck: Optional[bool] = False

class EnhancedVulnerabilityResponse(BaseModel):
    """Response model with comprehensive vulnerability data"""
    vulnerabilities: List[EnhancedVulnerabilityInfo]
    total_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    kev_count: int  # Known Exploited Vulnerabilities count
# ============================================================================
# Database-Ready Structured Intelligence Models
# ============================================================================

class CVERecord(BaseModel):
    """CVE record with quantitative data for database storage"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    exploit_maturity: Optional[str] = None  # Weaponized, Functional, PoC, Unproven
    kev_listed: bool = False  # CISA Known Exploited Vulnerabilities

class ProductRecord(BaseModel):
    """Product/Package record"""
    product_id: str
    product_name: str
    vendor: str
    product_family: str  # e.g., "Linux OS", "Database", "Web Server"

class CVEProductMap(BaseModel):
    """Mapping between CVE and affected products"""
    cve_id: str
    product_id: str
    affected_version_range: str  # e.g., "kernel < 4.18.0-372.9.1"
    vendor_severity: str  # Vendor-specific severity rating

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
    max_version_lag: int  # Maximum versions behind current

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
    
    # Metadata
    intelligence_timestamp: str
    data_sources: List[str]  # e.g., ["NVD", "MITRE", "Red Hat", "OSV"]
