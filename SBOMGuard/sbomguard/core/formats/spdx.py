"""
SBOMGuard — SPDX Format Handler
Generates SPDX v2.3 JSON output from SBOM objects.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any

from sbomguard.models import SBOM, Component


def generate_spdx(sbom: SBOM) -> dict[str, Any]:
    """
    Generate an SPDX v2.3 JSON document from an SBOM model.
    Spec: https://spdx.github.io/spdx-spec/v2.3/
    """
    doc_namespace = f"https://sbomguard.io/spdx/{sbom.id}"

    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": sbom.name or "Unknown Project",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": sbom.created_at or datetime.now(timezone.utc).isoformat(),
            "creators": [
                f"Tool: {sbom.tool_name}-{sbom.tool_version}",
                "Organization: SBOMGuard",
            ],
            "licenseListVersion": "3.22",
        },
        "packages": [_component_to_spdx(c, i) for i, c in enumerate(sbom.components)],
        "relationships": _build_relationships(sbom),
    }

    return spdx


def _spdx_id(name: str, index: int) -> str:
    """Generate a valid SPDX identifier."""
    # SPDX IDs must match [a-zA-Z0-9.-]+
    clean = "".join(c if c.isalnum() or c in ".-" else "-" for c in name)
    return f"SPDXRef-Package-{index}-{clean}"


def _component_to_spdx(comp: Component, index: int) -> dict[str, Any]:
    """Convert a Component model to an SPDX package dict."""
    spdx_pkg: dict[str, Any] = {
        "SPDXID": _spdx_id(comp.name, index),
        "name": comp.name,
        "versionInfo": comp.version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": f"Organization: {comp.supplier}" if comp.supplier else "NOASSERTION",
        "primaryPackagePurpose": comp.type.value.upper() if comp.type else "LIBRARY",
    }

    if comp.license:
        spdx_pkg["licenseConcluded"] = comp.license
        spdx_pkg["licenseDeclared"] = comp.license
    else:
        spdx_pkg["licenseConcluded"] = "NOASSERTION"
        spdx_pkg["licenseDeclared"] = "NOASSERTION"

    spdx_pkg["copyrightText"] = "NOASSERTION"

    if comp.purl:
        spdx_pkg["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": comp.purl,
                "referenceType": "purl",
            }
        ]

    if comp.description:
        spdx_pkg["description"] = comp.description

    if comp.hashes:
        checksums = []
        for alg, val in comp.hashes.items():
            spdx_alg = {
                "sha256": "SHA256",
                "sha1": "SHA1",
                "md5": "MD5",
                "sha512": "SHA512",
            }.get(alg.lower(), alg.upper())
            checksums.append({
                "algorithm": spdx_alg,
                "checksumValue": val,
            })
        if checksums:
            spdx_pkg["checksums"] = checksums

    return spdx_pkg


def _build_relationships(sbom: SBOM) -> list[dict]:
    """Build SPDX relationships."""
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
        }
    ]

    for i, comp in enumerate(sbom.components):
        spdx_id = _spdx_id(comp.name, i)
        rel_type = "DEPENDS_ON" if comp.is_direct else "DEV_DEPENDENCY_OF"
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": spdx_id,
            "relationshipType": rel_type,
        })

    return relationships
