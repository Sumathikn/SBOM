"""
SBOMGuard — Enterprise DevSecOps Policy Engine
Enforces customizable supply chain governance policies across SBOM completeness,
CVSS/EPSS risk boundaries, CISA KEV active exploitation, and open-source license compliance.
"""
import json
import logging
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

logger = logging.getLogger("sbomguard.policy")


class PolicyAction(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class PolicyViolation(BaseModel):
    rule_id: str
    severity: str  # critical, high, medium, low
    message: str
    component: Optional[str] = None
    advisory_id: Optional[str] = None
    action: PolicyAction = PolicyAction.FAIL


class SecurityPolicy(BaseModel):
    """Configurable organization-wide DevSecOps Policy definition."""
    policy_name: str = "Default Enterprise DevSecOps Policy"
    version: str = "1.0.0"

    # Vulnerability Thresholds
    max_critical_vulnerabilities: int = 0
    max_high_vulnerabilities: int = 0
    max_cvss_threshold: float = 7.0
    max_epss_threshold: float = 0.40  # 40% exploitation probability
    disallow_cisa_kev: bool = True
    require_remediation_available: bool = False

    # SBOM Quality & Governance
    min_sbom_quality_score: float = 60.0  # NTIA Minimum Elements compliance
    disallow_unspecified_versions: bool = True

    # License Compliance
    license_denylist: List[str] = Field(default_factory=lambda: ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"])
    license_allowlist: Optional[List[str]] = None


class PolicyEvaluationResult(BaseModel):
    policy_name: str
    verdict: PolicyAction
    passed: bool
    total_violations: int
    critical_violations: int
    high_violations: int
    violations: List[PolicyViolation] = Field(default_factory=list)
    summary: str


class PolicyEngine:
    """Evaluates SBOMs and vulnerability scans against organizational security policies."""

    def __init__(self, policy: Optional[SecurityPolicy] = None):
        self.policy = policy or SecurityPolicy()

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        """Load a YAML/JSON policy configuration file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        raw_data = json.loads(p.read_text(encoding="utf-8"))
        policy = SecurityPolicy(**raw_data)
        return cls(policy=policy)

    def evaluate(
        self,
        scan_data: dict,
        sbom_data: Optional[dict] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluate scan results and optional SBOM quality against security policies.
        """
        violations: List[PolicyViolation] = []

        total_critical = scan_data.get("critical_count", 0)
        total_high = scan_data.get("high_count", 0)

        # 1. Critical Vulnerabilities Threshold
        if total_critical > self.policy.max_critical_vulnerabilities:
            violations.append(
                PolicyViolation(
                    rule_id="SEC-VULN-001",
                    severity="critical",
                    message=(
                        f"Found {total_critical} CRITICAL vulnerabilities; "
                        f"policy allows maximum {self.policy.max_critical_vulnerabilities}."
                    ),
                    action=PolicyAction.FAIL,
                )
            )

        # 2. High Vulnerabilities Threshold
        if total_high > self.policy.max_high_vulnerabilities:
            violations.append(
                PolicyViolation(
                    rule_id="SEC-VULN-002",
                    severity="high",
                    message=(
                        f"Found {total_high} HIGH vulnerabilities; "
                        f"policy allows maximum {self.policy.max_high_vulnerabilities}."
                    ),
                    action=PolicyAction.FAIL,
                )
            )

        # 3. Individual Findings Assessment (CVSS, EPSS, CISA KEV)
        assessments = scan_data.get("risk_assessments", [])
        for ra in assessments:
            comp_name = ra.get("component_name", "unknown")
            comp_version = ra.get("component_version", "")
            comp_str = f"{comp_name}@{comp_version}" if comp_version else comp_name

            for v in ra.get("vulnerabilities", []):
                vid = v.get("id", "Unknown")
                cvss = float(v.get("cvss_score", 0.0))
                epss = float(v.get("epss_score", 0.0))
                in_kev = bool(v.get("in_kev", False))
                has_fix = bool(v.get("fixed_version"))

                # CISA KEV Check
                if self.policy.disallow_cisa_kev and in_kev:
                    violations.append(
                        PolicyViolation(
                            rule_id="SEC-KEV-001",
                            severity="critical",
                            message=f"Vulnerability {vid} on {comp_str} is actively exploited in CISA KEV catalog.",
                            component=comp_str,
                            advisory_id=vid,
                            action=PolicyAction.FAIL,
                        )
                    )

                # Max CVSS Check
                if cvss >= self.policy.max_cvss_threshold:
                    violations.append(
                        PolicyViolation(
                            rule_id="SEC-CVSS-001",
                            severity="high",
                            message=f"CVSS score {cvss:.1f} for {vid} on {comp_str} exceeds threshold {self.policy.max_cvss_threshold:.1f}.",
                            component=comp_str,
                            advisory_id=vid,
                            action=PolicyAction.FAIL,
                        )
                    )

                # Max EPSS Probability Check
                if epss >= self.policy.max_epss_threshold:
                    violations.append(
                        PolicyViolation(
                            rule_id="SEC-EPSS-001",
                            severity="high",
                            message=f"EPSS exploit probability {epss:.1%} for {vid} on {comp_str} exceeds threshold {self.policy.max_epss_threshold:.1%}.",
                            component=comp_str,
                            advisory_id=vid,
                            action=PolicyAction.FAIL,
                        )
                    )

                # Fix Availability Requirement
                if self.policy.require_remediation_available and not has_fix and cvss >= 7.0:
                    violations.append(
                        PolicyViolation(
                            rule_id="SEC-FIX-001",
                            severity="medium",
                            message=f"No safe fixed version known for high/critical advisory {vid} on {comp_str}.",
                            component=comp_str,
                            advisory_id=vid,
                            action=PolicyAction.WARN,
                        )
                    )

        # 4. SBOM Quality Score Check
        if sbom_data:
            quality = float(sbom_data.get("quality_score", 0.0))
            if quality < self.policy.min_sbom_quality_score:
                violations.append(
                    PolicyViolation(
                        rule_id="GOV-QUAL-001",
                        severity="medium",
                        message=(
                            f"SBOM quality score {quality:.1f}% is below required NTIA standard "
                            f"of {self.policy.min_sbom_quality_score:.1f}%."
                        ),
                        action=PolicyAction.FAIL,
                    )
                )

        # Determine overall verdict
        crit_count = sum(1 for v in violations if v.severity == "critical" and v.action == PolicyAction.FAIL)
        high_count = sum(1 for v in violations if v.severity == "high" and v.action == PolicyAction.FAIL)
        has_fails = any(v.action == PolicyAction.FAIL for v in violations)

        if has_fails:
            verdict = PolicyAction.FAIL
            summary = f"Policy FAILED: {len(violations)} violations detected ({crit_count} Critical, {high_count} High)."
        elif violations:
            verdict = PolicyAction.WARN
            summary = f"Policy PASSED with {len(violations)} warnings."
        else:
            verdict = PolicyAction.PASS
            summary = "Policy PASSED: All supply chain security gates satisfied."

        return PolicyEvaluationResult(
            policy_name=self.policy.policy_name,
            verdict=verdict,
            passed=(verdict != PolicyAction.FAIL),
            total_violations=len(violations),
            critical_violations=crit_count,
            high_violations=high_count,
            violations=violations,
            summary=summary,
        )


# Global Default Policy Engine
default_policy_engine = PolicyEngine()
