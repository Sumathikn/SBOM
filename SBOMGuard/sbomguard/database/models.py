"""
SBOMGuard SQLAlchemy 2.0 Database Models
Production relational schema with PostgreSQL optimization, JSON columns,
and indexes on high-cardinality columns.
"""
from datetime import datetime, timezone
from typing import Optional, List, Any
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    Index,
    JSON,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ProjectModel(Base):
    """Multi-tenant / Multi-project isolation entity."""
    __tablename__ = "projects"

    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    sboms = relationship("SBOMModel", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("ScanModel", back_populates="project", cascade="all, delete-orphan")


class SBOMModel(Base):
    """Software Bill of Materials root record."""
    __tablename__ = "sboms"

    id = Column(String(64), primary_key=True)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="CASCADE"), default="default", index=True, nullable=False)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(64), default="1", nullable=False)
    format = Column(String(32), default="cyclonedx", nullable=False)
    source_file = Column(String(512), nullable=True)
    manifest_type = Column(String(64), nullable=True, index=True)
    component_count = Column(Integer, default=0, nullable=False)
    quality_score = Column(Float, default=0.0, nullable=False)
    sbom_data = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    project = relationship("ProjectModel", back_populates="sboms")
    components = relationship("ComponentModel", back_populates="sbom", cascade="all, delete-orphan")
    scans = relationship("ScanModel", back_populates="sbom", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_sboms_project_created", "project_id", "created_at"),
        Index("ix_sboms_name_version", "name", "version"),
    )


class ComponentModel(Base):
    """Individual software component identified within an SBOM."""
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sbom_id = Column(String(64), ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(64), default="default", index=True, nullable=False)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(128), nullable=False, index=True)
    type = Column(String(64), default="library", nullable=False)
    purl = Column(String(512), nullable=True, index=True)
    ecosystem = Column(String(64), nullable=True, index=True)
    license = Column(String(255), nullable=True)
    is_direct = Column(Boolean, default=True, nullable=False)
    depth = Column(Integer, default=0, nullable=False)

    sbom = relationship("SBOMModel", back_populates="components")

    __table_args__ = (
        Index("ix_components_name_version", "name", "version"),
        Index("ix_components_sbom_purl", "sbom_id", "purl"),
        Index("ix_components_ecosystem_name", "ecosystem", "name"),
    )


class ScanModel(Base):
    """Vulnerability scan execution and assessment record."""
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="CASCADE"), default="default", index=True, nullable=False)
    sbom_id = Column(String(64), ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False, index=True)
    sbom_name = Column(String(255), nullable=True)
    total_components = Column(Integer, default=0, nullable=False)
    components_scanned = Column(Integer, default=0, nullable=False)
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    overall_risk_level = Column(String(32), default="info", index=True, nullable=False)
    overall_risk_score = Column(Float, default=0.0, nullable=False)
    scan_data = Column(JSON, nullable=False)
    scanned_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True, nullable=False)

    project = relationship("ProjectModel", back_populates="scans")
    sbom = relationship("SBOMModel", back_populates="scans")
    vulnerabilities = relationship("VulnerabilityRecordModel", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scans_project_scanned_at", "project_id", "scanned_at"),
        Index("ix_scans_risk_level_score", "overall_risk_level", "overall_risk_score"),
    )


class VulnerabilityRecordModel(Base):
    """Denormalized vulnerability record associated with a scan."""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(64), default="default", index=True, nullable=False)
    vuln_id = Column(String(64), nullable=False, index=True)  # CVE-2024-XXXX or GHSA-XXXX
    source = Column(String(64), nullable=True)
    title = Column(String(512), nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(String(32), default="none", index=True, nullable=False)
    cvss_score = Column(Float, default=0.0, index=True, nullable=False)
    epss_score = Column(Float, default=0.0, index=True, nullable=False)
    affected_component = Column(String(255), nullable=True, index=True)
    fixed_version = Column(String(128), nullable=True)
    exploit_available = Column(Boolean, default=False, nullable=False)
    in_kev = Column(Boolean, default=False, index=True, nullable=False)

    scan = relationship("ScanModel", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vulns_scan_sev", "scan_id", "severity"),
        Index("ix_vulns_cve_severity", "vuln_id", "severity"),
        Index("ix_vulns_component_cve", "affected_component", "vuln_id"),
    )
