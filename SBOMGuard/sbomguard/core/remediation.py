"""
SBOMGuard Remediation & Intelligence Engine
Computes safe upgrade paths, SemVer compatibility, confidence scores,
breaking-change risks, and automated fix PR patch generation.
"""
import difflib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any, Tuple
from packaging.version import parse as parse_version, InvalidVersion

from sbomguard.core.registries import registry_client
from sbomguard.core.threat_intel import threat_intel
from sbomguard.models import Vulnerability, RiskLevel, Severity

logger = logging.getLogger("sbomguard.remediation")


class SemVerChangeType(str, Enum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNKNOWN = "unknown"


class BreakingChangeRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RemediationGuidance:
    """Intelligent patch recommendation and risk guidance for a vulnerable component."""
    component_name: str
    current_version: str
    ecosystem: str
    vulnerabilities_count: int
    cve_ids_fixed: List[str]
    minimum_safe_version: str
    recommended_version: str
    semver_change_type: SemVerChangeType
    breaking_change_risk: BreakingChangeRisk
    confidence_score: float  # 0 to 100
    has_cisa_kev: bool
    max_epss_score: float
    upgrade_command: str
    remediation_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "component_name": self.component_name,
            "current_version": self.current_version,
            "ecosystem": self.ecosystem,
            "vulnerabilities_count": self.vulnerabilities_count,
            "cve_ids_fixed": self.cve_ids_fixed,
            "minimum_safe_version": self.minimum_safe_version,
            "recommended_version": self.recommended_version,
            "semver_change_type": self.semver_change_type.value,
            "breaking_change_risk": self.breaking_change_risk.value,
            "confidence_score": round(self.confidence_score, 1),
            "has_cisa_kev": self.has_cisa_kev,
            "max_epss_score": round(self.max_epss_score, 4),
            "upgrade_command": self.upgrade_command,
            "remediation_notes": self.remediation_notes,
        }


class RemediationEngine:
    """Evaluates vulnerabilities against package registries and produces safe upgrade paths."""

    async def generate_guidance(
        self,
        component_name: str,
        current_version: str,
        ecosystem: str,
        vulnerabilities: List[dict | Vulnerability],
    ) -> Optional[RemediationGuidance]:
        """Generate safe upgrade guidance for a single component."""
        vuln_models: List[Vulnerability] = [
            v if isinstance(v, Vulnerability) else Vulnerability(**v)
            for v in vulnerabilities
        ]
        if not vuln_models:
            return None

        # 1. Gather all required fixed versions from advisories
        fixed_versions_raw = []
        for v in vuln_models:
            if v.fixed_version and v.fixed_version.lower() not in ("none", "null", ""):
                fixed_versions_raw.append(v.fixed_version)
            if hasattr(v, "fixed_versions") and v.fixed_versions:
                for fv in v.fixed_versions:
                    if fv and fv.lower() not in ("none", "null", "") and fv not in fixed_versions_raw:
                        fixed_versions_raw.append(fv)
        cve_ids = [v.id for v in vuln_models]
        has_kev = any(threat_intel.is_in_kev(v.id) or v.in_kev for v in vuln_models)
        max_epss = max((v.epss_score for v in vuln_models), default=0.0)

        # 2. Fetch available versions from official registry
        available_versions = await registry_client.get_package_versions(
            component_name, ecosystem
        )

        min_safe, rec_version = self._resolve_safe_versions(
            current_version=current_version,
            fixed_versions=fixed_versions_raw,
            available_versions=available_versions,
        )

        if not rec_version:
            # Fallback if no specific version could be parsed
            rec_version = sorted(fixed_versions_raw)[-1] if fixed_versions_raw else "latest"
            min_safe = rec_version

        # 3. Assess SemVer drift & breaking change risk
        semver_change, risk_level, confidence = self._calculate_compatibility(
            current_version=current_version,
            target_version=rec_version,
            has_kev=has_kev,
            max_epss=max_epss,
        )

        # 4. Generate CLI command
        upgrade_cmd = self._generate_upgrade_command(
            component_name=component_name,
            version=rec_version,
            ecosystem=ecosystem,
        )

        # 5. Explanatory guidance notes
        notes = []
        if has_kev:
            notes.append("🚨 CISA KEV ALERT: Vulnerability is actively exploited in the wild. Priority patch required.")
        if max_epss >= 0.3:
            notes.append(f"⚠️ High EPSS probability ({max_epss:.1%}): Known exploit activity detected.")
        if semver_change == SemVerChangeType.MAJOR:
            notes.append(f"⚠️ Major version bump ({current_version} → {rec_version}): Review breaking API changes before merging.")
        elif semver_change == SemVerChangeType.PATCH:
            notes.append(f"✅ Patch version upgrade ({current_version} → {rec_version}): High confidence, zero expected breaking changes.")
        else:
            notes.append(f"ℹ️ Minor version upgrade ({current_version} → {rec_version}): Backward-compatible feature release.")

        return RemediationGuidance(
            component_name=component_name,
            current_version=current_version,
            ecosystem=ecosystem or "unknown",
            vulnerabilities_count=len(vuln_models),
            cve_ids_fixed=cve_ids,
            minimum_safe_version=min_safe,
            recommended_version=rec_version,
            semver_change_type=semver_change,
            breaking_change_risk=risk_level,
            confidence_score=confidence,
            has_cisa_kev=has_kev,
            max_epss_score=max_epss,
            upgrade_command=upgrade_cmd,
            remediation_notes=notes,
        )

    def _resolve_safe_versions(
        self,
        current_version: str,
        fixed_versions: List[str],
        available_versions: List[str],
    ) -> Tuple[str, str]:
        """
        Determine Minimum Safe Version and Recommended Safe Version.
        """
        if not fixed_versions:
            if available_versions:
                return available_versions[-1], available_versions[-1]
            return "latest", "latest"

        # Parse current version
        try:
            curr_v = parse_version(current_version)
        except InvalidVersion:
            curr_v = None

        # Parse required fixed targets
        parsed_fixes = []
        for f in fixed_versions:
            try:
                parsed_fixes.append((parse_version(f), f))
            except InvalidVersion:
                continue

        if not parsed_fixes:
            return "latest", "latest"

        parsed_fixes.sort(key=lambda x: x[0])
        highest_fix_target = parsed_fixes[-1][0]
        highest_fix_version = parsed_fixes[-1][1]

        # Check for same major series fix
        same_series_fixes = [
            (pv, fv) for pv, fv in parsed_fixes
            if curr_v and pv.major == curr_v.major and pv >= curr_v
        ]
        if same_series_fixes:
            target_fix = max(same_series_fixes, key=lambda x: x[0])
            effective_target = target_fix[0]
            fallback_min = target_fix[1]
        else:
            effective_target = highest_fix_target
            fallback_min = highest_fix_version

        if available_versions:
            valid_candidates = []
            for av in available_versions:
                try:
                    pv = parse_version(av)
                    if pv >= effective_target:
                        valid_candidates.append((pv, av))
                except InvalidVersion:
                    continue

            if valid_candidates:
                min_safe_tuple = valid_candidates[0]
                rec_safe_tuple = valid_candidates[-1]
                return min_safe_tuple[1], rec_safe_tuple[1]

        # Registry fallback
        return fallback_min, highest_fix_version

    def _calculate_compatibility(
        self,
        current_version: str,
        target_version: str,
        has_kev: bool,
        max_epss: float,
    ) -> Tuple[SemVerChangeType, BreakingChangeRisk, float]:
        """Compute change type, breaking risk, and confidence score."""
        try:
            curr_v = parse_version(current_version)
            tgt_v = parse_version(target_version)

            curr_major = getattr(curr_v, "major", 0)
            tgt_major = getattr(tgt_v, "major", 0)
            curr_minor = getattr(curr_v, "minor", 0)
            tgt_minor = getattr(tgt_v, "minor", 0)

            if tgt_major > curr_major:
                change = SemVerChangeType.MAJOR
                risk = BreakingChangeRisk.HIGH
                confidence = 55.0
            elif tgt_minor > curr_minor:
                change = SemVerChangeType.MINOR
                risk = BreakingChangeRisk.MEDIUM
                confidence = 82.0
            else:
                change = SemVerChangeType.PATCH
                risk = BreakingChangeRisk.LOW
                confidence = 96.0

        except Exception:
            change = SemVerChangeType.UNKNOWN
            risk = BreakingChangeRisk.MEDIUM
            confidence = 70.0

        # Confidence adjustments
        if has_kev:
            confidence = max(confidence, 90.0)  # High urgency to patch
        if max_epss > 0.5:
            confidence = max(confidence, 88.0)

        return change, risk, min(confidence, 99.0)

    @staticmethod
    def _generate_upgrade_command(component_name: str, version: str, ecosystem: str) -> str:
        """Produce the exact command line copy-paste string."""
        eco = (ecosystem or "").lower()
        if eco in ("pypi", "python"):
            return f"pip install --upgrade {component_name}=={version}"
        elif eco in ("npm", "node", "javascript", "typescript"):
            return f"npm install {component_name}@{version}"
        elif eco in ("maven", "java"):
            return f"mvn versions:use-latest-versions -Dincludes={component_name}"
        elif eco in ("go", "golang"):
            return f"go get -u {component_name}@v{version}"
        return f"# Upgrade {component_name} to {version}"

    # ─── Automated Fix PR & Manifest Patch Generator ────────────────────────

    def generate_manifest_patch(
        self,
        manifest_content: str,
        filename: str,
        recommendations: List[RemediationGuidance],
    ) -> dict:
        """
        Generate modified manifest content and unified git diff for automated PRs.
        """
        original_lines = manifest_content.splitlines(keepends=True)
        updated_lines = list(original_lines)
        modifications = []

        filename_lower = filename.lower()

        for rec in recommendations:
            pkg = rec.component_name
            new_v = rec.recommended_version

            if "requirements.txt" in filename_lower:
                for idx, line in enumerate(updated_lines):
                    # Match e.g. "flask==2.3.0" or "flask>=2.3.0"
                    pattern = rf"^({re.escape(pkg)})\s*([><=!~]+)\s*[\d.*]+"
                    if re.match(pattern, line.strip(), re.IGNORECASE):
                        old_line = updated_lines[idx]
                        newline = re.sub(
                            r"([><=!~]+)\s*[\d.*]+",
                            f"=={new_v}",
                            old_line,
                        )
                        updated_lines[idx] = newline
                        modifications.append({
                            "package": pkg,
                            "before": old_line.strip(),
                            "after": newline.strip(),
                        })
                        break

            elif "package.json" in filename_lower:
                for idx, line in enumerate(updated_lines):
                    # Match e.g. '"axios": "^1.6.0"'
                    pattern = rf'"{re.escape(pkg)}"\s*:\s*"[^"]+"'
                    if re.search(pattern, line):
                        old_line = updated_lines[idx]
                        newline = re.sub(
                            rf'("{re.escape(pkg)}"\s*:\s*)"[^"]+"',
                            rf'\g<1>"^{new_v}"',
                            old_line,
                        )
                        updated_lines[idx] = newline
                        modifications.append({
                            "package": pkg,
                            "before": old_line.strip(),
                            "after": newline.strip(),
                        })
                        break

            elif "go.mod" in filename_lower:
                for idx, line in enumerate(updated_lines):
                    pattern = rf"^(\s*{re.escape(pkg)})\s+v[\d.]+\S*"
                    if re.match(pattern, line):
                        old_line = updated_lines[idx]
                        newline = re.sub(
                            rf"(\s*{re.escape(pkg)}\s+)v[\d.]+\S*",
                            rf"\g<1>v{new_v}",
                            old_line,
                        )
                        updated_lines[idx] = newline
                        modifications.append({
                            "package": pkg,
                            "before": old_line.strip(),
                            "after": newline.strip(),
                        })
                        break

        new_content = "".join(updated_lines)

        # Compute unified diff
        diff_lines = list(
            difflib.unified_diff(
                original_lines,
                updated_lines,
                fromfile=f"a/{filename}",
                tofile=f"b/{filename}",
            )
        )
        unified_diff = "".join(diff_lines)

        # Generate PR Metadata
        pr_title = (
            f"security(deps): bump {recommendations[0].component_name} to {recommendations[0].recommended_version}"
            if len(recommendations) == 1
            else f"security(deps): patch {len(modifications)} vulnerable dependencies"
        )

        body_lines = [
            "### 🛡️ SBOMGuard Automated Security Remediation",
            "",
            "This automated pull request updates vulnerable dependencies to their minimum safe and verified versions.",
            "",
            "| Package | Current | Recommended | Change | Breaking Risk | CVEs Fixed |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in recommendations:
            cves_str = ", ".join(r.cve_ids_fixed[:3])
            body_lines.append(
                f"| `{r.component_name}` | `{r.current_version}` | `{r.recommended_version}` | "
                f"`{r.semver_change_type.value}` | `{r.breaking_change_risk.value}` | {cves_str} |"
            )

        body_lines.extend([
            "",
            "> **Generated by SBOMGuard DevSecOps Intelligence Engine**",
        ])

        return {
            "target_file": filename,
            "modifications_count": len(modifications),
            "modifications": modifications,
            "updated_content": new_content,
            "unified_diff": unified_diff,
            "diff": unified_diff,
            "pr_title": pr_title,
            "pr_body": "\n".join(body_lines),
        }


# Global engine instance
remediation_engine = RemediationEngine()
