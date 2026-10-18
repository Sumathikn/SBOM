"""
Unit tests for SPDX 2.3 format generation
"""
import pytest
from datetime import datetime, timezone

from sbomguard.models import SBOM, Component, ComponentType
from sbomguard.core.formats.spdx import generate_spdx, _spdx_id


class TestSPDXGenerator:
    def test_generate_spdx_document(self):
        comp1 = Component(
            name="requests",
            version="2.31.0",
            purl="pkg:pypi/requests@2.31.0",
            type=ComponentType.LIBRARY,
            license="Apache-2.0",
            supplier="PSF",
            description="Python HTTP for Humans",
            hashes={"sha256": "abcdef1234567890abcdef1234567890"},
            is_direct=True,
        )
        comp2 = Component(
            name="urllib3",
            version="2.0.7",
            purl="pkg:pypi/urllib3@2.0.7",
            type=ComponentType.LIBRARY,
            license="MIT",
            is_direct=False,
        )

        sbom = SBOM(
            name="test-spdx-project",
            format="spdx",
            components=[comp1, comp2],
        )

        doc = generate_spdx(sbom)

        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"
        assert doc["name"] == "test-spdx-project"
        assert len(doc["packages"]) == 2
        assert len(doc["relationships"]) >= 2

        pkg1 = doc["packages"][0]
        assert pkg1["name"] == "requests"
        assert pkg1["versionInfo"] == "2.31.0"
        assert pkg1["licenseConcluded"] == "Apache-2.0"
        assert pkg1["checksums"][0]["algorithm"] == "SHA256"
        assert pkg1["externalRefs"][0]["referenceLocator"] == "pkg:pypi/requests@2.31.0"

    def test_spdx_id_sanitization(self):
        clean_id = _spdx_id("@angular/core", 0)
        assert "@" not in clean_id
        assert "/" not in clean_id
        assert clean_id.startswith("SPDXRef-Package-0-")
