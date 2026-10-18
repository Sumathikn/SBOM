"""
SBOMGuard Pydantic Data Models
Defines the core data structures used across all engines.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ─── Enums ───────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class SBOMFormat(str, Enum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class ManifestType(str, Enum):
    REQUIREMENTS_TXT = "requirements.txt"
    PACKAGE_JSON = "package.json"
    POM_XML = "pom.xml"
    GO_MOD = "go.mod"
    GEMFILE_LOCK = "Gemfile.lock"


class ComponentType(str, Enum):
    LIBRARY = "library"
    FRAMEWORK = "framework"
    APPLICATION = "application"
    DEVICE = "device"
    FIRMWARE = "firmware"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ─── Component Model ────────────────────────────────────────────────────────

class Component(BaseModel):
    """Represents a single software component/dependency."""
    name: str
    version: str
    type: ComponentType = ComponentType.LIBRARY
    purl: Optional[str] = None          # Package URL (e.g., pkg:pypi/flask@2.3.0)
    ecosystem: Optional[str] = None     # pypi, npm, maven, etc.
    license: Optional[str] = None
    description: Optional[str] = None
    supplier: Optional[str] = None
    is_direct: bool = True              # True = direct dependency, False = transitive
    depth: int = 0                      # Dependency depth level
    hashes: dict = Field(default_factory=dict)


# ─── Vulnerability Model ────────────────────────────────────────────────────

class Vulnerability(BaseModel):
    """Represents a discovered vulnerability."""
    id: str                             # CVE-2024-XXXX or GHSA-XXXX
    source: str = "osv"                 # nvd, osv, github
    title: str = ""
    description: str = ""
    severity: Severity = Severity.NONE
    cvss_score: float = 0.0
    cvss_vector: str = ""
    epss_score: float = 0.0             # Exploit Prediction Scoring System
    epss_percentile: float = 0.0
    cwe_ids: list[str] = Field(default_factory=list)
    affected_component: str = ""
    package_name: str = ""
    affected_versions: str = ""
    installed_version: str = ""
    fixed_version: Optional[str] = None
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    published_date: Optional[str] = None
    last_modified: Optional[str] = None
    exploit_available: bool = False
    in_kev: bool = False                # In CISA Known Exploited Vulnerabilities catalog


# ─── Risk Assessment Model ───────────────────────────────────────────────────

class RiskAssessment(BaseModel):
    """Risk assessment result for a single component."""
    component_name: str
    component_version: str
    risk_level: RiskLevel = RiskLevel.INFO
    risk_score: float = 0.0             # 0-100 composite score
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    max_cvss: float = 0.0
    max_epss: float = 0.0
    has_exploit: bool = False
    remediation: Optional[str] = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


# ─── SBOM Model ─────────────────────────────────────────────────────────────

class SBOM(BaseModel):
    """Represents a complete Software Bill of Materials."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    version: str = "1"
    format: SBOMFormat = SBOMFormat.CYCLONEDX
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool_name: str = "SBOMGuard"
    tool_version: str = "1.0.0"
    source_file: str = ""               # Original manifest filename
    manifest_type: Optional[ManifestType] = None
    components: list[Component] = Field(default_factory=list)
    component_count: int = 0
    quality_score: float = 0.0          # SBOM completeness/quality 0-100


# ─── Scan Result Model ──────────────────────────────────────────────────────

class ScanResult(BaseModel):
    """Complete vulnerability scan result for an SBOM."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sbom_id: str
    sbom_name: str = ""
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_components: int = 0
    components_scanned: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    overall_risk_level: RiskLevel = RiskLevel.INFO
    overall_risk_score: float = 0.0
    risk_assessments: list[RiskAssessment] = Field(default_factory=list)


# ─── Dashboard Stats Model ──────────────────────────────────────────────────

class DashboardStats(BaseModel):
    """Aggregated statistics for the dashboard."""
    total_sboms: int = 0
    total_components: int = 0
    total_scans: int = 0
    total_vulnerabilities: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    avg_risk_score: float = 0.0
    recent_sboms: list[dict] = Field(default_factory=list)
    recent_scans: list[dict] = Field(default_factory=list)
    top_vulnerable_components: list[dict] = Field(default_factory=list)
    severity_distribution: dict = Field(default_factory=dict)


# ─── SBOM Diff Model ────────────────────────────────────────────────────────

class SBOMDiff(BaseModel):
    """Difference between two SBOMs."""
    sbom_a_id: str
    sbom_b_id: str
    added_components: list[Component] = Field(default_factory=list)
    removed_components: list[Component] = Field(default_factory=list)
    version_changes: list[dict] = Field(default_factory=list)
    summary: str = ""
