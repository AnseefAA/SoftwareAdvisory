"""
Database models for PostgreSQL advisory database
Matches SoftwareAdvisory implementation
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ARRAY, ForeignKey, UUID
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import uuid
import json

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
    advisory_metadata = Column('metadata', JSONB)  # Renamed to avoid SQLAlchemy reserved word
    remediation_plan = Column(JSONB)

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
    cvss_metrics = Column(JSONB)
    source_identifier = Column(Text)
    vulnerability_status = Column(Text)
    exploitability_score = Column(Float)
    impact_score = Column(Float)
    epss_score = Column(Float)
    is_zero_day = Column(Boolean, default=False)
    is_exploitable = Column(Boolean, default=False)
    is_patch_available = Column(Boolean, default=False)
    cwe_references = Column(JSONB)
    cpe_references = Column(JSONB)
    reference_links = Column(JSONB)
    raw = Column(JSONB)
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

class ProductRelease(Base):
    """Product release table model"""
    __tablename__ = 'product_release'
    __table_args__ = {'schema': 'concert_advisory'}
    
    release_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    product_id = Column(UUID(as_uuid=True), ForeignKey('concert_advisory.product.id'), nullable=False)
    full_version = Column(ARRAY(Text))
    major_version = Column(Integer)
    minor_version = Column(Integer)
    patch_version = Column(Integer)
    release_date = Column(DateTime(timezone=True))
    eol_date = Column(DateTime(timezone=True))
    extended_support = Column(Boolean, default=False)

class ProductDependency(Base):
    """Product dependency table model"""
    __tablename__ = 'product_dependency'
    __table_args__ = {'schema': 'concert_advisory'}
    
    parent_product_id = Column(UUID(as_uuid=True), ForeignKey('concert_advisory.product.id'), primary_key=True)
    dependency_product_id = Column(UUID(as_uuid=True), ForeignKey('concert_advisory.product.id'), primary_key=True)
    dependent_type = Column(Text)
    supported_version_range = Column(Text)

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

class IntelligenceCache(Base):
    """Intelligence cache table for storing aggregated CVE/Advisory intelligence
    Uses TEXT columns for JSON data to avoid SQL_ASCII encoding issues"""
    __tablename__ = 'intelligence_cache'
    __table_args__ = {'schema': 'concert_advisory'}
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identifier = Column(Text, nullable=False)  # CVE ID or Advisory ID
    identifier_type = Column(Text, nullable=False)  # 'cve' or 'advisory'
    
    # Raw aggregated data from all sources (stored as TEXT to avoid encoding issues)
    raw_data = Column(Text)  # JSON stored as text
    
    # Structured data (extracted and processed) (stored as TEXT to avoid encoding issues)
    structured_data = Column(Text)  # JSON stored as text
    
    # Metadata
    sources_fetched = Column(ARRAY(Text))  # Array of source names
    first_fetched_at = Column(DateTime(timezone=True), default=func.now())
    last_updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    fetch_count = Column(Integer, default=1)
    
    # Status tracking
    is_complete = Column(Boolean, default=False)  # All sources successfully fetched
    fetch_errors = Column(Text)  # JSON stored as text
