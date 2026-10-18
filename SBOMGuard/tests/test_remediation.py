"""
Unit Tests for SBOMGuard Advanced Remediation & Intelligence Engine
"""
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomguard.core.remediation import (
    RemediationEngine,
    SemVerChangeType,
    BreakingChangeRisk,
    RemediationGuidance,
)
from sbomguard.models import Vulnerability, Severity


@pytest.fixture
def remediation_engine():
    return RemediationEngine()


class TestRemediationEngine:
    def test_calculate_compatibility_patch(self, remediation_engine):
        change, risk, confidence = remediation_engine._calculate_compatibility(
            current_version="1.2.3",
            target_version="1.2.4",
            has_kev=False,
            max_epss=0.01,
        )
        assert change == SemVerChangeType.PATCH
        assert risk == BreakingChangeRisk.LOW
        assert confidence >= 90.0

    def test_calculate_compatibility_minor(self, remediation_engine):
        change, risk, confidence = remediation_engine._calculate_compatibility(
            current_version="1.2.3",
            target_version="1.3.0",
            has_kev=False,
            max_epss=0.05,
        )
        assert change == SemVerChangeType.MINOR
        assert risk == BreakingChangeRisk.MEDIUM
        assert 75.0 <= confidence <= 90.0

    def test_calculate_compatibility_major(self, remediation_engine):
        change, risk, confidence = remediation_engine._calculate_compatibility(
            current_version="1.2.3",
            target_version="2.0.0",
            has_kev=False,
            max_epss=0.1,
        )
        assert change == SemVerChangeType.MAJOR
        assert risk == BreakingChangeRisk.HIGH
        assert confidence < 75.0

    def test_calculate_compatibility_with_kev_urgency(self, remediation_engine):
        change, risk, confidence = remediation_engine._calculate_compatibility(
            current_version="1.0.0",
            target_version="2.0.0",
            has_kev=True,
            max_epss=0.85,
        )
        # Even with major version, urgency elevates confidence to remediate
        assert confidence >= 90.0

    def test_resolve_safe_versions_with_registry_candidates(self, remediation_engine):
        min_safe, rec_safe = remediation_engine._resolve_safe_versions(
            current_version="2.3.0",
            fixed_versions=["2.3.2", "2.3.1"],
            available_versions=["2.3.0", "2.3.1", "2.3.2", "2.3.3", "3.0.0"],
        )
        assert min_safe == "2.3.2"
        assert rec_safe == "3.0.0"

    def test_generate_upgrade_command(self, remediation_engine):
        pypi_cmd = remediation_engine._generate_upgrade_command("flask", "3.0.3", "pypi")
        assert "pip install --upgrade flask==3.0.3" in pypi_cmd

        npm_cmd = remediation_engine._generate_upgrade_command("axios", "1.7.4", "npm")
        assert "npm install axios@1.7.4" in npm_cmd

        go_cmd = remediation_engine._generate_upgrade_command("golang.org/x/crypto", "0.21.0", "go")
        assert "go get -u golang.org/x/crypto@v0.21.0" in go_cmd

    def test_generate_manifest_patch_requirements(self, remediation_engine):
        original = "flask==2.3.0\nrequests==2.25.1\nwerkzeug==2.2.0\n"
        recs = [
            RemediationGuidance(
                component_name="flask",
                current_version="2.3.0",
                ecosystem="pypi",
                vulnerabilities_count=1,
                cve_ids_fixed=["CVE-2023-30861"],
                minimum_safe_version="2.3.2",
                recommended_version="3.0.3",
                semver_change_type=SemVerChangeType.MAJOR,
                breaking_change_risk=BreakingChangeRisk.HIGH,
                confidence_score=95.0,
                has_cisa_kev=False,
                max_epss_score=0.1,
                upgrade_command="pip install --upgrade flask==3.0.3",
            )
        ]

        patch_res = remediation_engine.generate_manifest_patch(
            manifest_content=original,
            filename="requirements.txt",
            recommendations=recs,
        )

        assert patch_res["modifications_count"] == 1
        assert "flask==3.0.3" in patch_res["updated_content"]
        assert "-flask==2.3.0" in patch_res["unified_diff"]
        assert "+flask==3.0.3" in patch_res["unified_diff"]
        assert "bump flask" in patch_res["pr_title"].lower()

    def test_generate_manifest_patch_package_json(self, remediation_engine):
        original = '{\n  "dependencies": {\n    "axios": "^1.6.0"\n  }\n}\n'
        recs = [
            RemediationGuidance(
                component_name="axios",
                current_version="1.6.0",
                ecosystem="npm",
                vulnerabilities_count=1,
                cve_ids_fixed=["CVE-2024-39338"],
                minimum_safe_version="1.7.4",
                recommended_version="1.7.4",
                semver_change_type=SemVerChangeType.MINOR,
                breaking_change_risk=BreakingChangeRisk.MEDIUM,
                confidence_score=90.0,
                has_cisa_kev=False,
                max_epss_score=0.05,
                upgrade_command="npm install axios@1.7.4",
            )
        ]

        patch_res = remediation_engine.generate_manifest_patch(
            manifest_content=original,
            filename="package.json",
            recommendations=recs,
        )

        assert patch_res["modifications_count"] == 1
        assert '"axios": "^1.7.4"' in patch_res["updated_content"]
        assert "-    \"axios\": \"^1.6.0\"" in patch_res["unified_diff"]
