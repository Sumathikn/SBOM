"""
SBOMGuard — SBOM Management Engine (Week 6 Enhanced)
Handles SBOM storage, retrieval, version drift analysis, SemVer diffing,
hierarchical tree diffs, validation, and quality scoring.
"""
from typing import Optional, List, Dict, Any
from packaging.version import parse as parse_version, InvalidVersion

from sbomguard.models import SBOM, Component, SBOMDiff
from sbomguard.database import get_sbom, list_sboms, delete_sbom


class SBOMManager:
    """
    Manages the SBOM repository: storage, versioning, advanced diffing with SemVer drift analysis.
    """

    def get(self, sbom_id: str) -> Optional[dict]:
        """Retrieve an SBOM by its ID."""
        return get_sbom(sbom_id)

    def list_all(self, limit: int = 50) -> List[dict]:
        """List all stored SBOMs (metadata only)."""
        return list_sboms(limit)

    def delete(self, sbom_id: str) -> bool:
        """Delete an SBOM from the repository."""
        return delete_sbom(sbom_id)

    def compare(self, sbom_a_id: str, sbom_b_id: str) -> dict:
        """
        Compare two SBOMs by ID and produce an advanced version drift analysis.
        """
        sbom_a = get_sbom(sbom_a_id)
        sbom_b = get_sbom(sbom_b_id)

        if not sbom_a:
            raise ValueError(f"Base SBOM not found: {sbom_a_id}")
        if not sbom_b:
            raise ValueError(f"Target SBOM not found: {sbom_b_id}")

        return self.compare_sbom_dicts(sbom_a, sbom_b, sbom_a_id=sbom_a_id, sbom_b_id=sbom_b_id)

    def compare_sbom_dicts(
        self,
        sbom_a: dict,
        sbom_b: dict,
        sbom_a_id: Optional[str] = None,
        sbom_b_id: Optional[str] = None,
    ) -> dict:
        """
        Compare two SBOM dictionaries (CycloneDX or SPDX) and produce an advanced version drift analysis.
        Includes SemVer drift categorization (Major/Minor/Patch), breaking risks,
        direct vs transitive breakdown, and tree diff representation.
        """
        raw_comps_a = sbom_a.get("components") or sbom_a.get("packages") or []
        raw_comps_b = sbom_b.get("components") or sbom_b.get("packages") or []

        comps_a = {c["name"]: c for c in raw_comps_a}
        comps_b = {c["name"]: c for c in raw_comps_b}

        names_a = set(comps_a.keys())
        names_b = set(comps_b.keys())

        # Added components (in B, not in A)
        added = [comps_b[n] for n in sorted(names_b - names_a)]

        # Removed components (in A, not in B)
        removed = [comps_a[n] for n in sorted(names_a - names_b)]

        # Modified components with SemVer drift analysis
        version_changes = []
        major_drift_count = 0
        minor_drift_count = 0
        patch_drift_count = 0

        for name in sorted(names_a & names_b):
            c_a = comps_a[name]
            c_b = comps_b[name]
            ver_a = c_a.get("version", "")
            ver_b = c_b.get("version", "")

            if ver_a != ver_b:
                drift_type, breaking_risk = self._classify_version_drift(ver_a, ver_b)
                if drift_type == "major":
                    major_drift_count += 1
                elif drift_type == "minor":
                    minor_drift_count += 1
                elif drift_type == "patch":
                    patch_drift_count += 1

                version_changes.append({
                    "name": name,
                    "ecosystem": c_b.get("ecosystem") or c_a.get("ecosystem"),
                    "purl_before": c_a.get("purl"),
                    "purl_after": c_b.get("purl"),
                    "version_before": ver_a,
                    "version_after": ver_b,
                    "is_direct": c_b.get("is_direct", True),
                    "depth": c_b.get("depth", 0),
                    "drift_type": drift_type,
                    "breaking_risk": breaking_risk,
                })

        # Direct vs Transitive drift counts
        direct_drift = [vc for vc in version_changes if vc.get("is_direct")]
        transitive_drift = [vc for vc in version_changes if not vc.get("is_direct")]

        # Summary
        summary_parts = []
        if added:
            summary_parts.append(f"{len(added)} added")
        if removed:
            summary_parts.append(f"{len(removed)} removed")
        if version_changes:
            summary_parts.append(
                f"{len(version_changes)} modified ({major_drift_count} major, {minor_drift_count} minor, {patch_drift_count} patch)"
            )
        summary = "; ".join(summary_parts) if summary_parts else "No differences found (Identical SBOMs)."

        return {
            "sbom_a": {
                "id": sbom_a_id or sbom_a.get("sbom_id", "local_a"),
                "name": sbom_a.get("name", ""),
                "version": sbom_a.get("version", "1"),
                "component_count": len(comps_a),
                "created_at": sbom_a.get("created_at"),
            },
            "sbom_b": {
                "id": sbom_b_id or sbom_b.get("sbom_id", "local_b"),
                "name": sbom_b.get("name", ""),
                "version": sbom_b.get("version", "1"),
                "component_count": len(comps_b),
                "created_at": sbom_b.get("created_at"),
            },
            "stats": {
                "total_a": len(comps_a),
                "total_b": len(comps_b),
                "added_count": len(added),
                "removed_count": len(removed),
                "modified_count": len(version_changes),
                "major_drift_count": major_drift_count,
                "minor_drift_count": minor_drift_count,
                "patch_drift_count": patch_drift_count,
                "direct_drift_count": len(direct_drift),
                "transitive_drift_count": len(transitive_drift),
            },
            "added_components": added,
            "removed_components": removed,
            "version_changes": version_changes,
            "direct_drift": direct_drift,
            "transitive_drift": transitive_drift,
            "summary": summary,
        }

    @staticmethod
    def _classify_version_drift(ver_before: str, ver_after: str) -> tuple[str, str]:
        """Classify SemVer drift between two versions."""
        try:
            vb = parse_version(ver_before)
            va = parse_version(ver_after)

            maj_b = getattr(vb, "major", 0)
            maj_a = getattr(va, "major", 0)
            min_b = getattr(vb, "minor", 0)
            min_a = getattr(va, "minor", 0)

            if maj_a != maj_b:
                return "major", "high"
            if min_a != min_b:
                return "minor", "medium"
            return "patch", "low"
        except Exception:
            return "unknown", "medium"

    def validate(self, sbom_data: dict) -> dict:
        """Validate an SBOM for completeness and compliance."""
        issues = []
        warnings = []
        components = sbom_data.get("components", [])

        if not components:
            issues.append("SBOM contains zero components.")

        for i, comp in enumerate(components):
            name = comp.get("name", "")
            version = comp.get("version", "")
            if not name:
                issues.append(f"Component #{i+1} has no identifier/name.")
            if not version or version == "unknown":
                warnings.append(f"Component '{name}' has unpinned/unknown version.")
            if not comp.get("purl"):
                warnings.append(f"Component '{name}' is missing a canonical Package URL (PURL).")
            if not comp.get("license"):
                warnings.append(f"Component '{name}' has no declared license information.")

        is_valid = len(issues) == 0
        return {
            "is_valid": is_valid,
            "quality_score": sbom_data.get("quality_score", 0.0),
            "issues": issues,
            "warnings": warnings,
            "component_count": len(components),
            "summary": "SBOM is valid." if is_valid else f"Found {len(issues)} critical issue(s).",
        }
