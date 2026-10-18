"""
Unit Tests for SBOMGuard SARIF 2.1.0 Generator
"""
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomguard.core.sarif import generate_sarif_report


class TestSarifExporter:
    def test_sarif_schema_structure(self):
        sample_scan = {
            "id": "scan-123",
            "sbom_name": "backend-service",
            "risk_assessments": [
                {
                    "component_name": "requests",
                    "component_version": "2.25.1",
                    "vulnerabilities": [
                        {
                            "id": "CVE-2023-32681",
                            "severity": "high",
                            "cvss_score": 7.5,
                            "epss_score": 0.45,
                            "in_kev": False,
                            "fixed_version": "2.31.0",
                            "title": "Requests Proxy-Authorization Leak",
                            "description": "Information disclosure vulnerability",
                            "affected_component": "requests@2.25.1",
                        }
                    ],
                }
            ],
        }

        sarif = generate_sarif_report(sample_scan, repo_file_path="requirements.txt")

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "SBOMGuard"

        # Check rules
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "CVE-2023-32681"
        assert rules[0]["defaultConfiguration"]["level"] == "error"
        assert rules[0]["properties"]["security-severity"] == "7.5"

        # Check results
        results = run["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CVE-2023-32681"
        assert results[0]["level"] == "error"
        assert "requests@2.25.1" in results[0]["message"]["text"]
