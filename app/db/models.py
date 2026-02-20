"""
Database models for PostgreSQL advisory database
Minimal version - only models needed for targeted remediation API
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, UUID
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import uuid

Base = declarative_base()

class Advisory(Base):
    """Advisory table model - matches public.advisory"""
    __tablename__ = 'advisory'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    advisory_id = Column(Text, unique=True, nullable=False)
    vendor = Column(Text)
    title = Column(Text)
    aggregate_severity = Column(Text)
    advisory_url = Column(Text)
    csaf_version = Column(Text)
    advisory_type = Column(Text)
    advisory_status = Column(Text)
    tlp_label = Column(Text)
    supersedes = Column(Text)
    patch_release_date = Column(DateTime(timezone=True))
    workaround_available = Column(Boolean, default=False)
    patch_stability = Column(Text)
    known_regressions = Column(Boolean, default=False)
    published_date = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=func.now())
    advisory_metadata = Column('metadata', JSONB)  # Renamed to avoid SQLAlchemy reserved word
    remediation_plan = Column(JSONB)

class Vulnerability(Base):
    """Vulnerabilities table model - matches public.vulnerability"""
    __tablename__ = 'vulnerability'
    
    id = Column(Text, primary_key=True)  # CVE ID
    title = Column(Text)
    description = Column(Text)
    latest_vector_string = Column(Text)
    latest_severity = Column(Text)
    latest_cvss_score = Column(Float)
    cvss_metrics = Column(JSONB)
    source_identifier = Column(Text)
    vulnerability_status = Column(Text)
    published_date = Column(DateTime(timezone=True))
    last_modified_date = Column(DateTime(timezone=True))
    is_exploitable = Column(Boolean, default=False)
    is_patch_available = Column(Boolean, default=False)
    kev_listed = Column(Boolean, default=False)
    exploit_poc_available = Column(Boolean, default=False)
    ransomware_association = Column(Boolean, default=False)
    exploit_maturity = Column(Text)
    attack_vector = Column(Text)
    privileges_required = Column(Text)

class VulnerabilityAdvisory(Base):
    """Relationship table between vulnerabilities and advisories"""
    __tablename__ = 'vulnerability_advisories'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(Text, ForeignKey('vulnerability.id'), nullable=False)
    advisory_id = Column(UUID(as_uuid=True), ForeignKey('advisory.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())


# Made with Bob
