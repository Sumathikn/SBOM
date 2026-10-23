"""
Unit and Integration Tests for SBOMGuard CLI (typer)
"""
import json
import pytest
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

from sbomguard.cli import app
from sbomguard.models import ScanResult, Severity

runner = CliRunner()


class TestSBOMGuardCLI:
    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "SBOMGuard Enterprise Platform" in result.stdout

    def test_generate_cyclonedx(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("flask==2.3.0\nrequests==2.31.0\n")
        out_file = tmp_path / "sbom.json"

        result = runner.invoke(
            app,
            ["generate", str(manifest), "--format", "cyclonedx", "--output", str(out_file)],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data.get("bomFormat") == "CycloneDX"

    def test_generate_spdx(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("fastapi==0.110.0\n")
        out_file = tmp_path / "spdx.json"

        result = runner.invoke(
            app,
            ["generate", str(manifest), "--format", "spdx", "--output", str(out_file)],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data.get("spdxVersion") == "SPDX-2.3"

    def test_generate_file_not_found(self):
        result = runner.invoke(app, ["generate", "non_existent_file.txt"])
        assert result.exit_code == 2
        assert "File not found" in result.stdout

    def test_scan_file_not_found(self):
        result = runner.invoke(app, ["scan", "non_existent_file.txt"])
        assert result.exit_code == 2
        assert "File not found" in result.stdout

    def test_scan_clean_manifest(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("clean-package==1.0.0\n")
        sarif_out = tmp_path / "out.sarif"
        json_out = tmp_path / "out.json"

        # Mock VulnerabilityScanner and RiskScorer to return 0 vulnerabilities
        with patch("sbomguard.cli.VulnerabilityScanner") as mock_scanner_cls, \
             patch("sbomguard.cli.RiskScorer") as mock_scorer_cls:
            mock_scanner = MagicMock()
            mock_scanner_cls.return_value = mock_scanner
            mock_scanner.scan_components.return_value = []
            mock_scorer = MagicMock()
            mock_scorer_cls.return_value = mock_scorer
            mock_res = ScanResult(
                sbom_id="test-id",
                total_components=1,
                total_vulnerabilities=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                overall_risk_score=0.0,
                risk_assessments=[],
            )
            mock_scorer.assess_sbom.return_value = mock_res

            result = runner.invoke(
                app,
                [
                    "scan",
                    str(manifest),
                    "--sarif",
                    str(sarif_out),
                    "--json",
                    str(json_out),
                ],
            )
            assert result.exit_code == 0
            assert sarif_out.exists()
            assert json_out.exists()
            assert "DevSecOps Gate Passed" in result.stdout

    def test_scan_vulnerable_manifest_fail_gate(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("vulnerable-pkg==1.0.0\n")

        with patch("sbomguard.cli.VulnerabilityScanner") as mock_scanner_cls, \
             patch("sbomguard.cli.RiskScorer") as mock_scorer_cls:
            mock_scanner = MagicMock()
            mock_scanner_cls.return_value = mock_scanner
            mock_scanner.scan_components.return_value = []
            mock_scorer = MagicMock()
            mock_scorer_cls.return_value = mock_scorer
            from sbomguard.models import Vulnerability, RiskAssessment

            vuln = Vulnerability(
                id="CVE-2023-9999",
                affected_component="vulnerable-pkg",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                in_kev=True,
            )
            ra = RiskAssessment(
                component_name="vulnerable-pkg",
                component_version="1.0.0",
                vulnerabilities=[vuln],
            )
            mock_res = ScanResult(
                sbom_id="test-id",
                total_components=1,
                total_vulnerabilities=1,
                critical_count=1,
                high_count=0,
                medium_count=0,
                low_count=0,
                overall_risk_score=95.0,
                risk_assessments=[ra],
            )
            mock_scorer.assess_sbom.return_value = mock_res

            result = runner.invoke(
                app,
                ["scan", str(manifest), "--fail-on", "high", "--fail-on-kev"],
            )
            assert result.exit_code == 1
            assert "DevSecOps Gate Failed" in result.stdout

    def test_diff_command_local_files(self, tmp_path):
        sbom_a = tmp_path / "a.json"
        sbom_b = tmp_path / "b.json"
        sbom_a.write_text(json.dumps({"components": [{"name": "pkgA", "version": "1.0.0"}]}))
        sbom_b.write_text(json.dumps({"components": [{"name": "pkgA", "version": "1.1.0"}]}))

        result = runner.invoke(app, ["diff", str(sbom_a), str(sbom_b)])
        assert result.exit_code == 0
        assert "Comparing local files" in result.stdout

    def test_generate_with_attestation(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("fastapi==0.110.0\n")
        sbom_out = tmp_path / "sbom.json"
        attest_out = tmp_path / "sbom.attest.json"

        result = runner.invoke(
            app,
            ["generate", str(manifest), "-o", str(sbom_out), "--attest", str(attest_out)],
        )
        assert result.exit_code == 0
        assert sbom_out.exists()
        assert attest_out.exists()
        attestation = json.loads(attest_out.read_text())
        assert attestation["payloadType"] == "application/vnd.in-toto+json"
        assert len(attestation["signatures"]) == 1

    def test_remediate_command_clean(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("clean-package==1.0.0\n")

        with patch("sbomguard.cli.VulnerabilityScanner") as mock_scanner_cls:
            mock_scanner = MagicMock()
            mock_scanner_cls.return_value = mock_scanner
            mock_scanner.scan_components.return_value = []

            result = runner.invoke(app, ["remediate", str(manifest)])
            assert result.exit_code == 0
            assert "No vulnerable components require remediation" in result.stdout

