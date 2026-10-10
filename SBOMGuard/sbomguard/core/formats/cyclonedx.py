"""
SBOMGuard — CycloneDX Format Handler
Generates CycloneDX v1.5 JSON output from SBOM objects.
"""

from datetime import datetime, timezone
from typing import Any

from sbomguard.models import SBOM, Component


def generate_cyclonedx(sbom: SBOM) -> dict[str, Any]:
    """
    Generate a CycloneDX v1.5 JSON document from an SBOM model.
    Spec: https://cyclonedx.org/docs/1.5/json/
    """
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{sbom.id}",
        "version": int(sbom.version) if sbom.version.isdigit() else 1,
        "metadata": {
            "timestamp": sbom.created_at or datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": sbom.tool_name,
                        "version": sbom.tool_version,
                        "description": "Automated SBOM Generation & Vulnerability Analysis",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": sbom.name or "Unknown Project",
                "version": sbom.version,
            },
        },
        "components": [_component_to_cdx(c) for c in sbom.components],
        "dependencies": _build_dependencies(sbom.components),
    }

    return cdx


def _component_to_cdx(comp: Component) -> dict[str, Any]:
    """Convert a Component model to a CycloneDX component dict."""
    cdx_comp: dict[str, Any] = {
        "type": comp.type.value if comp.type else "library",
        "name": comp.name,
        "version": comp.version,
    }

    if comp.purl:
        cdx_comp["purl"] = comp.purl
        cdx_comp["bom-ref"] = comp.purl

    if comp.description:
        cdx_comp["description"] = comp.description

    if comp.supplier:
        cdx_comp["supplier"] = {"name": comp.supplier}

    if comp.license:
        cdx_comp["licenses"] = [
            {"license": {"id": comp.license}}
        ]

    if comp.hashes:
        cdx_comp["hashes"] = [
            {"alg": alg.upper(), "content": val}
            for alg, val in comp.hashes.items()
        ]

    if comp.ecosystem:
        cdx_comp["properties"] = [
            {"name": "ecosystem", "value": comp.ecosystem},
            {"name": "is_direct", "value": str(comp.is_direct)},
            {"name": "depth", "value": str(comp.depth)},
        ]

    return cdx_comp


def _build_dependencies(components: list[Component]) -> list[dict]:
    """Build the dependency tree (flat for now)."""
    deps = []
    for comp in components:
        ref = comp.purl or f"{comp.name}@{comp.version}"
        deps.append({"ref": ref, "dependsOn": []})
    return deps
