"""
GraphQL Schema for CVE Intelligence Database

This module defines the GraphQL schema for querying vulnerability intelligence data.
"""

import strawberry
from typing import List, Optional
from datetime import datetime
import os
import json
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# GraphQL Types
# ============================================================================

@strawberry.type
class Exploitability:
    cve_id: str
    kev_listed: bool
    exploit_maturity: Optional[str] = None
    epss_score: Optional[float] = None


@strawberry.type
class CveDetails:
    cve_id: str
    description: str
    cvss_score: float
    severity: str


@strawberry.type
class CvssVector:
    cve_id: str
    vector_string: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None


@strawberry.type
class SeverityComparison:
    cve_id: str
    nvd_severity: Optional[str] = None
    vendor_severity: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v3_score: Optional[float] = None


@strawberry.type
class ProductImpact:
    product_id: str
    product_name: str
    vendor: str
    affected_version_range: str
    vendor_severity: Optional[str] = None


@strawberry.type
class VendorAdvisory:
    advisory_id: str
    vendor: str
    cve_id: str
    severity: str
    advisory_url: str
    published_date: str


@strawberry.type
class AdvisoryTimeline:
    cve_id: str
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    advisories: List[VendorAdvisory]


@strawberry.type
class CVE:
    cve_id: str
    description: str
    cvss_score: float
    severity: str


@strawberry.type
class Patch:
    patch_id: str
    advisory_id: str
    product: str
    fixed_version: str
    reboot_required: bool
    patch_release_date: str


@strawberry.type
class FixedVersion:
    product: str
    fixed_version: str
    release_date: str


@strawberry.type
class BackportInfo:
    product: str
    version: str
    backported: bool
    backport_version: Optional[str] = None


@strawberry.type
class RestartImpact:
    cve_id: str
    requires_restart: bool
    restart_type: Optional[str] = None  # system, service, application


@strawberry.type
class DependencyImpact:
    component: str
    dependent_products: List[str]
    blast_radius_score: float


@strawberry.type
class Lifecycle:
    product: str
    version: str
    eol_date: str
    extended_support: bool
    support_status: Optional[str] = None


@strawberry.type
class Release:
    product: str
    version: str
    release_date: str
    support_end_date: Optional[str] = None


@strawberry.type
class CompatibilityIssue:
    dependent_product: str
    certification_status: bool
    risk_level: str


@strawberry.type
class VersionPolicy:
    product: str
    current_version: str
    latest_version: str
    violation: bool


@strawberry.type
class LicensePolicy:
    package: str
    license: str
    violation: bool


@strawberry.type
class LifecyclePolicyViolation:
    product: str
    version: str
    eol_date: str
    days_past_eol: int


@strawberry.type
class PatchSlaViolation:
    cve_id: str
    severity: str
    published_date: str
    days_unpatched: int
    sla_days: int


# ============================================================================
# Helper Functions
# ============================================================================

def load_database() -> dict:
    """Load the intelligence database from JSON file."""
    try:
        db_dir = os.getenv("INTELLIGENCE_DB_DIR", "app/data/intelligence_db")
        db_file = os.path.join(db_dir, "intelligence_records.json")
        
        if not os.path.exists(db_file):
            logger.warning("Intelligence database not found")
            return {"records": {}}
        
        with open(db_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading database: {str(e)}")
        return {"records": {}}


def get_record(cve_id: str) -> Optional[dict]:
    """Get a single CVE record from database."""
    db = load_database()
    return db.get("records", {}).get(cve_id)


# ============================================================================
# GraphQL Query Resolvers
# ============================================================================

@strawberry.type
class Query:
    
    # ---------------- Threat Intelligence ----------------
    
    @strawberry.field
    def get_exploitability(self, cve_id: str) -> Optional[Exploitability]:
        """Get exploitability information for a CVE."""
        record = get_record(cve_id)
        if not record:
            return None
        
        cve_data = record.get("cve", {})
        return Exploitability(
            cve_id=cve_id,
            kev_listed=cve_data.get("kev_listed", False),
            exploit_maturity=cve_data.get("exploit_maturity"),
            epss_score=None  # TODO: Integrate EPSS API
        )
    
    @strawberry.field
    def get_cve_details(self, cve_id: str) -> Optional[CveDetails]:
        """Get detailed CVE information."""
        record = get_record(cve_id)
        if not record:
            return None
        
        cve_data = record.get("cve", {})
        return CveDetails(
            cve_id=cve_id,
            description=cve_data.get("description", ""),
            cvss_score=cve_data.get("cvss_score", 0.0),
            severity=cve_data.get("severity", "UNKNOWN")
        )
    
    @strawberry.field
    def get_cvss_vector(self, cve_id: str) -> Optional[CvssVector]:
        """Get CVSS vector details for a CVE."""
        record = get_record(cve_id)
        if not record:
            return None
        
        # TODO: Parse CVSS vector from enriched data
        return CvssVector(
            cve_id=cve_id,
            vector_string=None,
            attack_vector=None,
            attack_complexity=None,
            privileges_required=None,
            user_interaction=None,
            scope=None,
            confidentiality_impact=None,
            integrity_impact=None,
            availability_impact=None
        )
    
    @strawberry.field
    def get_severity_comparison(self, cve_id: str) -> Optional[SeverityComparison]:
        """Compare severity ratings from different sources."""
        record = get_record(cve_id)
        if not record:
            return None
        
        cve_data = record.get("cve", {})
        return SeverityComparison(
            cve_id=cve_id,
            nvd_severity=cve_data.get("severity"),
            vendor_severity=None,  # TODO: Extract from vendor advisories
            cvss_v2_score=None,
            cvss_v3_score=cve_data.get("cvss_score")
        )
    
    # ---------------- Product Impact ----------------
    
    @strawberry.field
    def get_affected_products(self, cve_id: str) -> List[ProductImpact]:
        """Get list of products affected by a CVE."""
        record = get_record(cve_id)
        if not record:
            return []
        
        mappings = record.get("cve_product_mappings", [])
        products_dict = {p["product_id"]: p for p in record.get("products", [])}
        
        result = []
        for mapping in mappings:
            product_id = mapping.get("product_id")
            product = products_dict.get(product_id, {})
            
            result.append(ProductImpact(
                product_id=product_id,
                product_name=product.get("product_name", "Unknown"),
                vendor=product.get("vendor", "Unknown"),
                affected_version_range=mapping.get("affected_version_range", ""),
                vendor_severity=mapping.get("vendor_severity")
            ))
        
        return result
    
    @strawberry.field
    def get_affected_versions(self, cve_id: str) -> List[str]:
        """Get list of affected versions for a CVE."""
        record = get_record(cve_id)
        if not record:
            return []
        
        versions = set()
        for mapping in record.get("cve_product_mappings", []):
            version_range = mapping.get("affected_version_range", "")
            if version_range:
                versions.add(version_range)
        
        return list(versions)
    
    @strawberry.field
    def get_unaffected_versions(self, cve_id: str) -> List[str]:
        """Get list of unaffected versions for a CVE."""
        # TODO: Implement logic to determine unaffected versions
        return []
    
    # ---------------- Vendor Advisories ----------------
    
    @strawberry.field
    def get_vendor_advisories(self, cve_id: str) -> List[VendorAdvisory]:
        """Get vendor advisories for a CVE."""
        record = get_record(cve_id)
        if not record:
            return []
        
        advisories = record.get("vendor_advisories", [])
        return [
            VendorAdvisory(
                advisory_id=adv.get("advisory_id", ""),
                vendor=adv.get("vendor", ""),
                cve_id=adv.get("cve_id", ""),
                severity=adv.get("severity", ""),
                advisory_url=adv.get("advisory_url", ""),
                published_date=adv.get("published_date", "")
            )
            for adv in advisories
        ]
    
    @strawberry.field
    def get_advisory_timeline(self, cve_id: str) -> Optional[AdvisoryTimeline]:
        """Get timeline of advisories for a CVE."""
        record = get_record(cve_id)
        if not record:
            return None
        
        advisories = self.get_vendor_advisories(cve_id)
        
        return AdvisoryTimeline(
            cve_id=cve_id,
            published_date=record.get("intelligence_timestamp"),
            last_modified_date=record.get("last_updated"),
            advisories=advisories
        )
    
    @strawberry.field
    def get_cves_by_advisory(self, advisory_id: str) -> List[CVE]:
        """Get all CVEs associated with an advisory."""
        db = load_database()
        result = []
        
        for cve_id, record in db.get("records", {}).items():
            advisories = record.get("vendor_advisories", [])
            for adv in advisories:
                if adv.get("advisory_id") == advisory_id:
                    cve_data = record.get("cve", {})
                    result.append(CVE(
                        cve_id=cve_id,
                        description=cve_data.get("description", ""),
                        cvss_score=cve_data.get("cvss_score", 0.0),
                        severity=cve_data.get("severity", "UNKNOWN")
                    ))
                    break
        
        return result
    
    # ---------------- Patch Intelligence ----------------
    
    @strawberry.field
    def get_patch_availability(self, cve_id: str) -> List[Patch]:
        """Get available patches for a CVE."""
        record = get_record(cve_id)
        if not record:
            return []
        
        patches = record.get("patches", [])
        return [
            Patch(
                patch_id=p.get("patch_id", ""),
                advisory_id=p.get("advisory_id", ""),
                product=p.get("product", ""),
                fixed_version=p.get("fixed_version", ""),
                reboot_required=p.get("reboot_required", False),
                patch_release_date=p.get("patch_release_date", "")
            )
            for p in patches
        ]
    
    @strawberry.field
    def get_fixed_versions(self, cve_id: str) -> List[FixedVersion]:
        """Get versions that fix a CVE."""
        patches = self.get_patch_availability(cve_id)
        return [
            FixedVersion(
                product=p.product,
                fixed_version=p.fixed_version,
                release_date=p.patch_release_date
            )
            for p in patches
        ]
    
    @strawberry.field
    def get_backported_fixes(self, cve_id: str) -> List[BackportInfo]:
        """Get information about backported fixes."""
        # TODO: Implement backport detection logic
        return []
    
    @strawberry.field
    def get_superseded_patches(self, advisory_id: str) -> List[Patch]:
        """Get patches that have been superseded."""
        # TODO: Implement superseded patch logic
        return []
    
    @strawberry.field
    def get_restart_requirements(self, cve_id: str) -> Optional[RestartImpact]:
        """Get restart requirements for patching a CVE."""
        patches = self.get_patch_availability(cve_id)
        
        if not patches:
            return None
        
        requires_restart = any(p.reboot_required for p in patches)
        
        return RestartImpact(
            cve_id=cve_id,
            requires_restart=requires_restart,
            restart_type="system" if requires_restart else None
        )
    
    # ---------------- Dependency Intelligence ----------------
    
    @strawberry.field
    def get_dependency_impact(self, cve_id: str) -> Optional[DependencyImpact]:
        """Get dependency impact analysis for a CVE."""
        record = get_record(cve_id)
        if not record:
            return None
        
        products = record.get("products", [])
        if not products:
            return None
        
        # Calculate blast radius based on number of affected products
        blast_radius = len(products) / 10.0  # Normalize to 0-10 scale
        
        return DependencyImpact(
            component=products[0].get("product_name", "Unknown"),
            dependent_products=[p.get("product_name", "") for p in products],
            blast_radius_score=min(blast_radius, 10.0)
        )
    
    # ---------------- Lifecycle Intelligence ----------------
    
    @strawberry.field
    def get_lifecycle(self, product: str, version: str) -> Optional[Lifecycle]:
        """Get lifecycle information for a product version."""
        db = load_database()
        
        for record in db.get("records", {}).values():
            for lc in record.get("lifecycle", []):
                if lc.get("product") == product and lc.get("version") == version:
                    return Lifecycle(
                        product=lc.get("product", ""),
                        version=lc.get("version", ""),
                        eol_date=lc.get("eol_date", ""),
                        extended_support=lc.get("extended_support", False),
                        support_status=lc.get("support_status")
                    )
        
        return None
    
    @strawberry.field
    def get_products_nearing_eol(self, months: int) -> List[Lifecycle]:
        """Get products nearing end-of-life within specified months."""
        from datetime import datetime, timedelta
        
        db = load_database()
        result = []
        cutoff_date = datetime.now() + timedelta(days=months * 30)
        
        for record in db.get("records", {}).values():
            for lc in record.get("lifecycle", []):
                try:
                    eol_date = datetime.fromisoformat(lc.get("eol_date", ""))
                    if eol_date <= cutoff_date:
                        result.append(Lifecycle(
                            product=lc.get("product", ""),
                            version=lc.get("version", ""),
                            eol_date=lc.get("eol_date", ""),
                            extended_support=lc.get("extended_support", False),
                            support_status=lc.get("support_status")
                        ))
                except:
                    continue
        
        return result
    
    @strawberry.field
    def get_product_release_history(self, product: str) -> List[Release]:
        """Get release history for a product."""
        db = load_database()
        result = []
        
        for record in db.get("records", {}).values():
            for lc in record.get("lifecycle", []):
                if lc.get("product") == product:
                    result.append(Release(
                        product=lc.get("product", ""),
                        version=lc.get("version", ""),
                        release_date=lc.get("release_date", ""),
                        support_end_date=lc.get("eol_date")
                    ))
        
        return result
    
    # ---------------- Compatibility ----------------
    
    @strawberry.field
    def get_upgrade_blockers(self, product: str, target_version: str) -> List[CompatibilityIssue]:
        """Get compatibility issues that may block an upgrade."""
        db = load_database()
        result = []
        
        for record in db.get("records", {}).values():
            for comp in record.get("compatibility", []):
                if comp.get("product") == product:
                    result.append(CompatibilityIssue(
                        dependent_product=comp.get("dependent_product", ""),
                        certification_status=comp.get("certification_status", False),
                        risk_level=comp.get("risk_level", "UNKNOWN")
                    ))
        
        return result
    
    # ---------------- Policy Governance ----------------
    
    @strawberry.field
    def get_version_policy_violations(self, product: str) -> List[VersionPolicy]:
        """Get version policy violations for a product."""
        db = load_database()
        result = []
        
        for record in db.get("records", {}).values():
            for vp in record.get("version_policies", []):
                if vp.get("product") == product:
                    result.append(VersionPolicy(
                        product=vp.get("product", ""),
                        current_version=vp.get("current_version", ""),
                        latest_version=vp.get("latest_version", ""),
                        violation=vp.get("violation", False)
                    ))
        
        return result
    
    @strawberry.field
    def get_license_policy_violations(self, package: str) -> List[LicensePolicy]:
        """Get license policy violations for a package."""
        db = load_database()
        result = []
        
        for record in db.get("records", {}).values():
            for lp in record.get("license_policies", []):
                if lp.get("package") == package:
                    result.append(LicensePolicy(
                        package=lp.get("package", ""),
                        license=lp.get("license", ""),
                        violation=lp.get("violation", False)
                    ))
        
        return result
    
    @strawberry.field
    def get_eol_policy_violations(self) -> List[LifecyclePolicyViolation]:
        """Get all products that are past end-of-life."""
        from datetime import datetime
        
        db = load_database()
        result = []
        now = datetime.now()
        
        for record in db.get("records", {}).values():
            for lc in record.get("lifecycle", []):
                try:
                    eol_date = datetime.fromisoformat(lc.get("eol_date", ""))
                    if eol_date < now:
                        days_past = (now - eol_date).days
                        result.append(LifecyclePolicyViolation(
                            product=lc.get("product", ""),
                            version=lc.get("version", ""),
                            eol_date=lc.get("eol_date", ""),
                            days_past_eol=days_past
                        ))
                except:
                    continue
        
        return result
    
    @strawberry.field
    def get_patch_sla_breaches(self) -> List[PatchSlaViolation]:
        """Get CVEs that have breached patch SLA."""
        from datetime import datetime
        
        db = load_database()
        result = []
        now = datetime.now()
        
        # SLA: Critical = 7 days, High = 30 days, Medium = 90 days
        sla_days = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}
        
        for cve_id, record in db.get("records", {}).items():
            cve_data = record.get("cve", {})
            severity = cve_data.get("severity", "UNKNOWN")
            
            # Check if patches exist
            patches = record.get("patches", [])
            if patches:
                continue  # Has patches, no breach
            
            try:
                published = datetime.fromisoformat(record.get("intelligence_timestamp", ""))
                days_unpatched = (now - published).days
                sla = sla_days.get(severity, 180)
                
                if days_unpatched > sla:
                    result.append(PatchSlaViolation(
                        cve_id=cve_id,
                        severity=severity,
                        published_date=record.get("intelligence_timestamp", ""),
                        days_unpatched=days_unpatched,
                        sla_days=sla
                    ))
            except:
                continue
        
        return result


# Create the schema
schema = strawberry.Schema(query=Query)