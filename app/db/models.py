"""
Database models for PostgreSQL advisory database
"""
from sqlalchemy import Column, String, Text, DateTime, Float, Boolean, JSON, ARRAY, ForeignKey, UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import uuid

Base = declarative_base()

class Advisory(Base):
    """Advisory table model"""
    __tablename__ = 'advisories'
    __table_args__ = {'schema': 'concert_advisory'}
    
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
    published_date = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=func.now())
    advisory_metadata = Column('metadata', JSON)  # Renamed to avoid SQLAlchemy reserved word
    remediation_plan = Column(JSON)

class Vulnerability(Base):
    """Vulnerabilities table model"""
    __tablename__ = 'vulnerabilities'
    __table_args__ = {'schema': 'concert_advisory'}
    
    cve_id = Column(Text, primary_key=True)
    title = Column(Text)
    description = Column(Text)
    latest_vector_string = Column(Text)
    latest_severity = Column(Text)
    latest_cvss_score = Column(Float)
    cvss_metrics = Column(JSON)
    source_identifier = Column(Text)
    vulnerability_status = Column(Text)
    exploitability_score = Column(Float)
    impact_score = Column(Float)
    epss_score = Column(Float)
    is_zero_day = Column(Boolean, default=False)
    is_exploitable = Column(Boolean, default=False)
    is_patch_available = Column(Boolean, default=False)
    cwe_references = Column(JSON)
    cpe_references = Column(JSON)
    reference_links = Column(JSON)
    raw = Column(JSON)
    tags = Column(ARRAY(Text))
    published_date = Column(DateTime(timezone=True))
    modified_date = Column(DateTime(timezone=True))
    last_modified_date = Column(DateTime(timezone=True))

class Product(Base):
    """Product table model"""
    __tablename__ = 'product'
    __table_args__ = {'schema': 'concert_advisory'}
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(Text, nullable=False)
    vendor = Column(Text)
    product_family = Column(Text)
    version = Column(Text)
    release_date = Column(DateTime)
    eol_date = Column(DateTime)
    extended_support = Column(Boolean, default=False)

class Package(Base):
    """Packages table model"""
    __tablename__ = 'packages'
    __table_args__ = {'schema': 'concert_advisory'}
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(Text, nullable=False)
    version = Column(Text)
    ecosystem = Column(Text)
    description = Column(Text)
    published_at = Column(DateTime)

class CVEAdvisory(Base):
    """CVE-Advisory relationship table"""
    __tablename__ = 'cves_advisories'
    __table_args__ = {'schema': 'concert_advisory'}
    
    cve_id = Column(Text, ForeignKey('concert_advisory.vulnerabilities.cve_id'), primary_key=True)
    advisory_id = Column(UUID(as_uuid=True), ForeignKey('concert_advisory.advisories.id'), primary_key=True)
    tags = Column(ARRAY(Text))