"""
SBOMGuard — Risk Scoring Engine
Computes composite risk scores for components based on vulnerability data,
CVSS scores, EPSS exploitability, and supply chain factors.
"""

from sbomguard.models import (
    Component,
    RiskAssessment,
    RiskLevel,
    ScanResult,
    Severity,
    Vulnerability,
)
from config.settings import RISK_WEIGHTS


class RiskScorer:
    """
    Calculates composite risk scores and generates remediation recommendations.

    Risk Score Formula (0-100):
        score = w1 * cvss_factor
              + w2 * epss_factor
              + w3 * exploit_factor
              + w4 * criticality_factor
              + w5 * depth_factor

    Weights are configurable in config/settings.py.
    """

    def __init__(self):
        self.weights = RISK_WEIGHTS

    def assess_component(
        self,
        component: dict,
        vulnerabilities: list[dict],
    ) -> RiskAssessment:
        """
        Produce a risk assessment for a single component.

        Args:
            component: Component dict with name, version, ecosystem.
            vulnerabilities: List of vulnerability dicts from the scanner.

        Returns:
            RiskAssessment with composite score, counts, and remediation.
        """
        vulns = [Vulnerability(**v) for v in vulnerabilities]

        # Count by severity
        critical = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
        high = sum(1 for v in vulns if v.severity == Severity.HIGH)
        medium = sum(1 for v in vulns if v.severity == Severity.MEDIUM)
        low = sum(1 for v in vulns if v.severity == Severity.LOW)

        max_cvss = max((v.cvss_score for v in vulns), default=0.0)
        max_epss = max((v.epss_score for v in vulns), default=0.0)
        has_exploit = any(v.exploit_available for v in vulns)

        # Calculate composite risk score
        risk_score = self._compute_score(
            max_cvss=max_cvss,
            max_epss=max_epss,
            has_exploit=has_exploit,
            is_direct=component.get("is_direct", True),
            depth=component.get("depth", 0),
            vuln_count=len(vulns),
        )

        risk_level = self._score_to_level(risk_score)

        # Generate remediation advice
        remediation = self._generate_remediation(
            component_name=component["name"],
            component_version=component["version"],
            vulns=vulns,
            risk_level=risk_level,
        )

        return RiskAssessment(
            component_name=component["name"],
            component_version=component["version"],
            risk_level=risk_level,
            risk_score=round(risk_score, 1),
            vulnerability_count=len(vulns),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            max_cvss=max_cvss,
            max_epss=max_epss,
            has_exploit=has_exploit,
            remediation=remediation,
            vulnerabilities=vulns,
        )

    def assess_sbom(
        self,
        sbom_id: str,
        sbom_name: str,
        scan_results: list[dict],
    ) -> ScanResult:
        """
        Produce a full scan result with risk assessments for all components.

        Args:
            sbom_id: The SBOM identifier.
            sbom_name: The SBOM display name.
            scan_results: List of {component, vulnerabilities[]} dicts.

        Returns:
            ScanResult with aggregated statistics and per-component assessments.
        """
        assessments = []
        total_vulns = 0
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0

        for result in scan_results:
            comp = result["component"]
            vulns = result["vulnerabilities"]

            if not vulns:
                continue

            assessment = self.assess_component(comp, vulns)
            assessments.append(assessment)

            total_vulns += assessment.vulnerability_count
            total_critical += assessment.critical_count
            total_high += assessment.high_count
            total_medium += assessment.medium_count
            total_low += assessment.low_count

        # Overall risk score = weighted max of component scores
        overall_score = 0.0
        if assessments:
            # Use the 90th-percentile score to represent overall risk
            sorted_scores = sorted(
                [a.risk_score for a in assessments], reverse=True
            )
            top_n = max(1, len(sorted_scores) // 10)
            overall_score = sum(sorted_scores[:top_n]) / top_n

        overall_level = self._score_to_level(overall_score)

        return ScanResult(
            sbom_id=sbom_id,
            sbom_name=sbom_name,
            total_components=len(scan_results),
            components_scanned=len(scan_results),
            total_vulnerabilities=total_vulns,
            critical_count=total_critical,
            high_count=total_high,
            medium_count=total_medium,
            low_count=total_low,
            overall_risk_level=overall_level,
            overall_risk_score=round(overall_score, 1),
            risk_assessments=assessments,
        )

    # ─── Internal Scoring ────────────────────────────────────────────────

    def _compute_score(
        self,
        max_cvss: float,
        max_epss: float,
        has_exploit: bool,
        is_direct: bool,
        depth: int,
        vuln_count: int,
    ) -> float:
        """
        Compute the composite risk score (0-100).
        """
        w = self.weights

        # Factor 1: CVSS (0-10 → 0-100)
        cvss_factor = (max_cvss / 10.0) * 100

        # Factor 2: EPSS (0-1 → 0-100)
        epss_factor = max_epss * 100

        # Factor 3: Known exploit available (binary)
        exploit_factor = 100.0 if has_exploit else 0.0

        # Factor 4: Component criticality (direct deps are more critical)
        criticality_factor = 80.0 if is_direct else 40.0

        # Factor 5: Dependency depth (deeper = less controllable)
        depth_factor = min(depth * 15, 100)

        # Volume bonus: more vulns = more risk
        volume_bonus = min(vuln_count * 3, 20)

        score = (
            w["cvss_score"] * cvss_factor
            + w["epss_score"] * epss_factor
            + w["exploit_available"] * exploit_factor
            + w["component_criticality"] * criticality_factor
            + w["dependency_depth"] * depth_factor
            + volume_bonus
        )

        return min(score, 100.0)

    @staticmethod
    def _score_to_level(score: float) -> RiskLevel:
        """Map composite score to a risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 35:
            return RiskLevel.MEDIUM
        if score >= 10:
            return RiskLevel.LOW
        return RiskLevel.INFO

    @staticmethod
    def _generate_remediation(
        component_name: str,
        component_version: str,
        vulns: list[Vulnerability],
        risk_level: RiskLevel,
    ) -> str:
        """Generate human-readable remediation recommendations."""
        lines = []

        # Check for available fixes
        fixed_versions = [
            v.fixed_version for v in vulns
            if v.fixed_version and v.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        if fixed_versions:
            latest_fix = sorted(fixed_versions)[-1]
            lines.append(
                f"⚠️ UPGRADE {component_name} from {component_version} → {latest_fix} "
                f"to fix {len(fixed_versions)} critical/high vulnerability(ies)."
            )

        kev_vulns = [v for v in vulns if getattr(v, "in_kev", False)]
        if kev_vulns:
            lines.append(
                f"🚨 CISA KEV ACTIVE THREAT: {len(kev_vulns)} vulnerability(ies) in CISA Known Exploited Vulnerabilities catalog! Prioritize immediate remediation."
            )

        if risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            lines.append(
                f"🔴 PRIORITY: Immediate action required. "
                f"{component_name}@{component_version} has {len(vulns)} known vulnerability(ies)."
            )

            exploit_vulns = [v for v in vulns if v.exploit_available or getattr(v, "in_kev", False)]
            if exploit_vulns:
                lines.append(
                    f"🚨 EXPLOIT AVAILABLE for {len(exploit_vulns)} vulnerability(ies). "
                    f"This component is actively targeted."
                )

        elif risk_level == RiskLevel.MEDIUM:
            lines.append(
                f"🟡 MONITOR: {component_name}@{component_version} has moderate risk. "
                f"Plan an upgrade in the next release cycle."
            )

        elif risk_level == RiskLevel.LOW:
            lines.append(
                f"🟢 LOW RISK: {component_name}@{component_version} has minor issues. "
                f"Review during regular maintenance."
            )

        if not lines:
            lines.append(f"ℹ️ No immediate action required for {component_name}.")

        return "\n".join(lines)
