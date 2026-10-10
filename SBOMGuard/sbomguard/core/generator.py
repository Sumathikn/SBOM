"""
SBOMGuard — SBOM Generation Engine
Orchestrates manifest parsing, component extraction, quality scoring,
and SBOM output in CycloneDX/SPDX formats.
"""

import json
from pathlib import Path
from typing import Optional

from sbomguard.models import SBOM, Component, ManifestType, SBOMFormat
from sbomguard.core.parser import detect_manifest_type, parse_manifest
from sbomguard.core.formats.cyclonedx import generate_cyclonedx
from sbomguard.core.formats.spdx import generate_spdx
from sbomguard.database import save_sbom
from config.settings import SBOM_STORAGE_DIR


class SBOMGenerator:
    """
    Core engine for generating Software Bills of Materials.

    Workflow:
        1. Accept manifest file content + filename
        2. Detect manifest type
        3. Parse components
        4. Calculate quality score
        5. Generate SBOM in requested format
        6. Save to database & filesystem
    """

    def generate(
        self,
        content: str,
        filename: str,
        output_format: str = "cyclonedx",
        project_name: Optional[str] = None,
    ) -> dict:
        """
        Generate an SBOM from manifest file content.

        Args:
            content: Raw text content of the manifest file.
            filename: Original filename (for type detection).
            output_format: 'cyclonedx' or 'spdx'.
            project_name: Optional project name.

        Returns:
            dict with 'sbom' (internal model), 'document' (formatted output),
            and 'metadata' about the generation.
        """
        # 1. Detect manifest type
        manifest_type = detect_manifest_type(filename)
        if manifest_type is None:
            raise ValueError(
                f"Unsupported manifest file: '{filename}'. "
                f"Supported: requirements.txt, package.json, pom.xml, go.mod, Gemfile.lock"
            )

        # 2. Parse components
        components = parse_manifest(content, manifest_type)
        if not components:
            raise ValueError(f"No components found in '{filename}'. Is the file empty?")

        # 3. Build SBOM model
        fmt = SBOMFormat.SPDX if output_format.lower() == "spdx" else SBOMFormat.CYCLONEDX
        sbom_name = project_name or Path(filename).stem

        sbom = SBOM(
            name=sbom_name,
            format=fmt,
            source_file=filename,
            manifest_type=manifest_type,
            components=components,
            component_count=len(components),
        )

        # 4. Calculate quality score
        sbom.quality_score = self._calculate_quality(sbom)

        # 5. Generate formatted document
        if fmt == SBOMFormat.CYCLONEDX:
            document = generate_cyclonedx(sbom)
        else:
            document = generate_spdx(sbom)

        # 6. Save to database
        sbom_dict = sbom.model_dump()
        sbom_dict["format"] = sbom_dict["format"].value if hasattr(sbom_dict["format"], "value") else sbom_dict["format"]
        if sbom_dict.get("manifest_type") and hasattr(sbom_dict["manifest_type"], "value"):
            sbom_dict["manifest_type"] = sbom_dict["manifest_type"].value
        # Convert component types to string values
        for comp in sbom_dict.get("components", []):
            if hasattr(comp.get("type"), "value"):
                comp["type"] = comp["type"].value

        save_sbom(sbom_dict)

        # 7. Save formatted document to file
        doc_path = SBOM_STORAGE_DIR / f"{sbom.id}.json"
        with open(doc_path, "w") as f:
            json.dump(document, f, indent=2, default=str)

        return {
            "sbom_id": sbom.id,
            "name": sbom.name,
            "format": fmt.value,
            "source_file": filename,
            "manifest_type": manifest_type.value,
            "component_count": len(components),
            "quality_score": sbom.quality_score,
            "created_at": sbom.created_at,
            "document": document,
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "ecosystem": c.ecosystem,
                    "purl": c.purl,
                    "is_direct": c.is_direct,
                }
                for c in components
            ],
        }

    def _calculate_quality(self, sbom: SBOM) -> float:
        """
        Calculate an SBOM quality/completeness score (0-100).

        Scoring criteria:
        - Has components:          20 points
        - Components have PURLs:   20 points (proportional)
        - Components have versions: 20 points (proportional)
        - Components have licenses: 15 points (proportional)
        - Has supplier info:       10 points (proportional)
        - Has description:         15 points (proportional)
        """
        if not sbom.components:
            return 0.0

        total = len(sbom.components)
        score = 20.0  # Base score for having components

        # PURL completeness
        purls = sum(1 for c in sbom.components if c.purl)
        score += (purls / total) * 20

        # Version completeness (not "unknown")
        versions = sum(1 for c in sbom.components if c.version and c.version != "unknown")
        score += (versions / total) * 20

        # License info
        licenses = sum(1 for c in sbom.components if c.license)
        score += (licenses / total) * 15

        # Supplier info
        suppliers = sum(1 for c in sbom.components if c.supplier)
        score += (suppliers / total) * 10

        # Description
        descriptions = sum(1 for c in sbom.components if c.description)
        score += (descriptions / total) * 15

        return round(min(score, 100.0), 1)
