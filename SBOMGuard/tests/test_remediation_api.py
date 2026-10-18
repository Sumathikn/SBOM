"""
Integration tests for Remediation & Patch Intelligence API routes
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from sbomguard.main import app
from sbomguard.database import save_scan
from sbomguard.models import ScanResult, Severity, Vulnerability

client = TestClient(app)


class TestRemediationAPI:
    def test_get_scan_remediation_plan_not_found(self):
        resp = client.get("/api/v1/remediation/scan/nonexistent-id")
        assert resp.status_code == 404

    def test_get_scan_remediation_plan_success(self):
        # Save a scan with a vulnerable component
        scan_dict = {
            "id": "scan-remed-test-1",
            "sbom_id": "sbom-1",
            "total_components": 1,
            "vulnerable_components": 1,
            "total_vulnerabilities": 1,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "overall_risk_score": 85.0,
            "risk_assessments": [
                {
                    "component_name": "urllib3",
                    "component_version": "1.26.4",
                    "vulnerabilities": [
                        {
                            "id": "GHSA-1234",
                            "package_name": "urllib3",
                            "installed_version": "1.26.4",
                            "fixed_versions": ["1.26.5", "2.0.0"],
                            "severity": "high",
                            "cvss_score": 7.5,
                        }
                    ],
                }
            ],
        }
        save_scan(scan_dict)

        resp = client.get("/api/v1/remediation/scan/scan-remed-test-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["total_vulnerable_components"] == 1
        assert len(data["data"]) == 1
        item = data["data"][0]
        assert item["component_name"] == "urllib3"
        assert item["current_version"] == "1.26.4"
        assert item["minimum_safe_version"] == "1.26.5"

    def test_generate_patch_endpoint(self):
        scan_dict = {
            "id": "scan-patch-test-1",
            "sbom_id": "sbom-2",
            "total_components": 1,
            "vulnerable_components": 1,
            "total_vulnerabilities": 1,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "overall_risk_score": 85.0,
            "risk_assessments": [
                {
                    "component_name": "flask",
                    "component_version": "2.0.1",
                    "vulnerabilities": [
                        {
                            "id": "CVE-2023-30861",
                            "package_name": "flask",
                            "installed_version": "2.0.1",
                            "fixed_versions": ["2.2.5", "2.3.2"],
                            "severity": "high",
                            "cvss_score": 7.5,
                        }
                    ],
                }
            ],
        }
        save_scan(scan_dict)

        req_body = {
            "manifest_content": "flask==2.0.1\nrequests==2.31.0\n",
            "filename": "requirements.txt",
            "scan_id": "scan-patch-test-1",
        }

        resp = client.post("/api/v1/remediation/patch", json=req_body)
        assert resp.status_code == 200
        res = resp.json()
        assert res["status"] == "success"
        assert "diff" in res["data"]
        assert "+flask==2.2.5" in res["data"]["diff"] or "+flask==" in res["data"]["diff"]
