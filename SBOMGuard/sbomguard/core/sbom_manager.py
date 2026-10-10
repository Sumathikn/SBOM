"""
SBOMGuard — SBOM Management Engine
Handles SBOM storage, retrieval, version control, comparison (diff),
validation, and quality scoring.
"""

from typing import Optional

from sbomguard.models import SBOM, Component, SBOMDiff
from sbomguard.database import get_sbom, list_sboms, delete_sbom


class SBOMManager:
    """
    Manages the SBOM repository: storage, versioning, diffing.
    """

    def get(self, sbom_id: str) -> Optional[dict]:
        """Retrieve an SBOM by its ID."""
        return get_sbom(sbom_id)

    def list_all(self, limit: int = 50) -> list[dict]:
        """List all stored SBOMs (metadata only)."""
        return list_sboms(limit)

    def delete(self, sbom_id: str) -> bool:
        """Delete an SBOM from the repository."""
        return delete_sbom(sbom_id)

    def compare(self, sbom_a_id: str, sbom_b_id: str) -> dict:
        """
        Compare two SBOMs and return the differences.

        Returns a SBOMDiff with added, removed, and version-changed components.
        """
        sbom_a = get_sbom(sbom_a_id)
        sbom_b = get_sbom(sbom_b_id)

        if not sbom_a:
            raise ValueError(f"SBOM not found: {sbom_a_id}")
        if not sbom_b:
            raise ValueError(f"SBOM not found: {sbom_b_id}")

        # Build component maps: name → component dict
        comps_a = {c["name"]: c for c in sbom_a.get("components", [])}
        comps_b = {c["name"]: c for c in sbom_b.get("components", [])}

        names_a = set(comps_a.keys())
        names_b = set(comps_b.keys())

        # Added = in B but not in A
        added = [comps_b[n] for n in (names_b - names_a)]

        # Removed = in A but not in B
        removed = [comps_a[n] for n in (names_a - names_b)]

        # Version changes = same name, different version
        version_changes = []
        for name in (names_a & names_b):
            ver_a = comps_a[name].get("version", "")
            ver_b = comps_b[name].get("version", "")
            if ver_a != ver_b:
                version_changes.append({
                    "name": name,
                    "version_before": ver_a,
                    "version_after": ver_b,
                })

        # Build summary
        parts = []
        if added:
            parts.append(f"{len(added)} component(s) added")
        if removed:
            parts.append(f"{len(removed)} component(s) removed")
        if version_changes:
            parts.append(f"{len(version_changes)} version change(s)")
        summary = "; ".join(parts) if parts else "No differences found."

        return {
            "sbom_a_id": sbom_a_id,
            "sbom_b_id": sbom_b_id,
            "added_components": added,
            "removed_components": removed,
            "version_changes": version_changes,
            "summary": summary,
        }

    def validate(self, sbom_data: dict) -> dict:
        """
        Validate an SBOM for completeness and correctness.

        Returns a validation report with issues found.
        """
        issues = []
        warnings = []

        components = sbom_data.get("components", [])

        if not components:
            issues.append("SBOM contains no components.")

        for i, comp in enumerate(components):
            name = comp.get("name", "")
            version = comp.get("version", "")

            if not name:
                issues.append(f"Component #{i+1} has no name.")
            if not version or version == "unknown":
                warnings.append(f"Component '{name}' has unknown version.")
            if not comp.get("purl"):
                warnings.append(f"Component '{name}' is missing a Package URL (PURL).")
            if not comp.get("license"):
                warnings.append(f"Component '{name}' has no license information.")

        is_valid = len(issues) == 0
        quality_score = sbom_data.get("quality_score", 0.0)

        return {
            "is_valid": is_valid,
            "quality_score": quality_score,
            "issues": issues,
            "warnings": warnings,
            "component_count": len(components),
            "summary": (
                "SBOM is valid." if is_valid
                else f"SBOM has {len(issues)} issue(s) that need to be resolved."
            ),
        }
