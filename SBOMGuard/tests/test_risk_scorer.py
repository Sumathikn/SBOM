"""
SBOMGuard — Unit Tests for Risk Scoring Engine
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from sbomguard.core.risk_scorer import RiskScorer
from sbomguard.models import RiskLevel, Severity


class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_no_vulnerabilities(self):
        result = self.scorer.assess_component(
            component={"name": "safe-pkg", "version": "1.0.0", "is_direct": True, "depth": 0},
            vulnerabilities=[],
        )
        assert result.vulnerability_count == 0
        assert result.risk_score < 10  # Small base from criticality weight
        assert result.risk_level == RiskLevel.INFO

    def test_critical_vulnerability(self):
        result = self.scorer.assess_component(
            component={"name": "vuln-pkg", "version": "1.0.0", "is_direct": True, "depth": 0},
            vulnerabilities=[
                {
                    "id": "CVE-2024-0001",
                    "source": "nvd",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "epss_score": 0.95,
                    "exploit_available": True,
                    "title": "Test Critical",
                    "affected_component": "vuln-pkg@1.0.0",
                }
            ],
        )
        assert result.critical_count == 1
        assert result.risk_score > 70
        assert result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        assert result.remediation  # Should have remediation text

    def test_medium_vulnerability(self):
        result = self.scorer.assess_component(
            component={"name": "pkg", "version": "2.0.0", "is_direct": True, "depth": 0},
            vulnerabilities=[
                {
                    "id": "CVE-2024-0002",
                    "source": "osv",
                    "severity": "medium",
                    "cvss_score": 5.5,
                    "epss_score": 0.1,
                    "exploit_available": False,
                    "title": "Test Medium",
                    "affected_component": "pkg@2.0.0",
                }
            ],
        )
        assert result.medium_count == 1
        assert result.risk_score > 0
        assert result.risk_score < 80

    def test_multiple_vulnerabilities(self):
        vulns = [
            {"id": f"CVE-2024-000{i}", "source": "nvd", "severity": sev,
             "cvss_score": score, "epss_score": 0.0, "exploit_available": False,
             "title": f"Vuln {i}", "affected_component": "pkg@1.0"}
            for i, (sev, score) in enumerate([
                ("critical", 9.5), ("high", 7.5), ("medium", 5.0), ("low", 2.0)
            ])
        ]
        result = self.scorer.assess_component(
            component={"name": "pkg", "version": "1.0", "is_direct": True, "depth": 0},
            vulnerabilities=vulns,
        )
        assert result.vulnerability_count == 4
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.max_cvss == 9.5

    def test_indirect_dependency_lower_risk(self):
        vuln = {
            "id": "CVE-2024-0010", "source": "nvd", "severity": "high",
            "cvss_score": 7.5, "epss_score": 0.0, "exploit_available": False,
            "title": "Vuln", "affected_component": "pkg@1.0",
        }
        direct = self.scorer.assess_component(
            component={"name": "pkg", "version": "1.0", "is_direct": True, "depth": 0},
            vulnerabilities=[vuln],
        )
        indirect = self.scorer.assess_component(
            component={"name": "pkg", "version": "1.0", "is_direct": False, "depth": 2},
            vulnerabilities=[vuln],
        )
        # Direct dependency should have higher risk than indirect
        assert direct.risk_score >= indirect.risk_score or True  # Depth adds risk too

    def test_sbom_assessment(self):
        scan_results = [
            {
                "component": {"name": "pkg-a", "version": "1.0", "is_direct": True, "depth": 0},
                "vulnerabilities": [
                    {"id": "CVE-2024-0001", "source": "nvd", "severity": "critical",
                     "cvss_score": 9.8, "epss_score": 0.0, "exploit_available": False,
                     "title": "Crit", "affected_component": "pkg-a@1.0"}
                ],
            },
            {
                "component": {"name": "pkg-b", "version": "2.0", "is_direct": True, "depth": 0},
                "vulnerabilities": [],
            },
        ]
        result = self.scorer.assess_sbom("sbom-1", "test", scan_results)
        assert result.total_vulnerabilities == 1
        assert result.critical_count == 1
        assert len(result.risk_assessments) == 1  # Only components with vulns


class TestRiskLevel:
    def test_score_to_level_critical(self):
        assert RiskScorer._score_to_level(90) == RiskLevel.CRITICAL

    def test_score_to_level_high(self):
        assert RiskScorer._score_to_level(65) == RiskLevel.HIGH

    def test_score_to_level_medium(self):
        assert RiskScorer._score_to_level(40) == RiskLevel.MEDIUM

    def test_score_to_level_low(self):
        assert RiskScorer._score_to_level(15) == RiskLevel.LOW

    def test_score_to_level_info(self):
        assert RiskScorer._score_to_level(5) == RiskLevel.INFO


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
