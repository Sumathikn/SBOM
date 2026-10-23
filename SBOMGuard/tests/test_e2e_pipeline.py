"""
SBOMGuard — End-to-End Enterprise Integration Test Suite
Validates the complete DevSecOps supply chain pipeline:
Manifest Ingestion -> SBOM Generation (CycloneDX & SPDX) -> Cryptographic Attestation ->
Vulnerability Batch Correlation -> CISA KEV & EPSS Enrichment -> Risk Assessment ->
Policy Enforcement -> Remediation Guidance -> Git Patch Diff -> Version Drift Diffing -> SARIF Export.
"""
import json
import pytest
from pathlib import Path

from sbomguard.core.generator import SBOMGenerator
from sbomguard.core.vulnerability import VulnerabilityScanner
from sbomguard.core.risk_scorer import RiskScorer
from sbomguard.core.policy import SecurityPolicy, PolicyEngine, PolicyAction
from sbomguard.core.attestation import attestation_engine
from sbomguard.core.remediation import remediation_engine
from sbomguard.core.sbom_manager import SBOMManager
from sbomguard.core.sarif import generate_sarif_report
from sbomguard.models import Component, Severity


class TestEndToEndPipeline:
    """Complete multi-step lifecycle integration tests."""

    @pytest.mark.asyncio
    async def test_full_cyclonedx_e2e_lifecycle(self, tmp_path):
        manifest_content = (
            "flask==2.3.0\n"
            "requests==2.25.1\n"
            "urllib3==1.26.5\n"
        )
        manifest_file = tmp_path / "requirements.txt"
        manifest_file.write_text(manifest_content, encoding="utf-8")

        # ─── Step 1: SBOM Generation (CycloneDX 1.5) ────────────────────────
        generator = SBOMGenerator()
        sbom_res = generator.generate(
            content=manifest_content,
            filename="requirements.txt",
            output_format="cyclonedx",
            project_name="e2e-cloud-microservice",
        )
        assert sbom_res is not None
        assert sbom_res["format"] == "cyclonedx"
        assert sbom_res["component_count"] == 3
        assert sbom_res["quality_score"] >= 50.0

        doc = sbom_res["document"]
        assert doc["bomFormat"] == "CycloneDX"
        assert len(doc["components"]) == 3
        purls = [c.get("purl") for c in doc["components"]]
        assert "pkg:pypi/flask@2.3.0" in purls
        assert "pkg:pypi/requests@2.25.1" in purls
        assert "pkg:pypi/urllib3@1.26.5" in purls

        # ─── Step 2: In-toto Cryptographic Attestation ───────────────────────
        attestation = attestation_engine.create_attestation(
            sbom_data=sbom_res,
            project_name="e2e-cloud-microservice",
        )
        assert attestation["payloadType"] == "application/vnd.in-toto+json"
        assert len(attestation["signatures"]) == 1

        # Verify Attestation
        valid, msg = attestation_engine.verify_attestation(
            attestation=attestation,
            sbom_data=sbom_res,
        )
        assert valid is True
        assert "verified successfully" in msg

        # ─── Step 3: Vulnerability Scanning & OSV Batch Correlation ──────────
        components = [
            Component(
                name=c["name"],
                version=c["version"],
                ecosystem=c.get("ecosystem"),
                purl=c.get("purl"),
                is_direct=c.get("is_direct", True),
            )
            for c in sbom_res.get("components", [])
        ]
        scanner = VulnerabilityScanner()
        try:
            scan_raw = await scanner.scan_components_async(components)
        finally:
            scanner.close()

        assert len(scan_raw) == 3
        urllib_scan = next(s for s in scan_raw if s["component"]["name"] == "urllib3")
        assert len(urllib_scan["vulnerabilities"]) > 0

        # ─── Step 4: Risk Scoring & Threat Intel Enrichment ──────────────────
        scorer = RiskScorer()
        scan_res = scorer.assess_sbom(
            sbom_id=sbom_res["sbom_id"],
            sbom_name="e2e-cloud-microservice",
            scan_results=scan_raw,
        )
        assert scan_res.total_vulnerabilities > 0
        assert scan_res.overall_risk_score > 0.0

        scan_dict = scan_res.model_dump()

        # ─── Step 5: Enterprise Policy Enforcement ───────────────────────────
        strict_policy = SecurityPolicy(
            policy_name="Strict Zero-Critical Policy",
            max_critical_vulnerabilities=0,
            max_high_vulnerabilities=0,
            max_cvss_threshold=7.0,
            disallow_cisa_kev=True,
        )
        strict_engine = PolicyEngine(policy=strict_policy)
        eval_result = strict_engine.evaluate(scan_data=scan_dict, sbom_data=sbom_res)
        # Should fail gate due to urllib3 / requests CVEs
        assert eval_result.passed is False
        assert eval_result.verdict == PolicyAction.FAIL
        assert len(eval_result.violations) > 0

        # ─── Step 6: Remediation & Safe Upgrade Planning ─────────────────────
        guidances = []
        for ra in scan_dict.get("risk_assessments", []):
            vulns = ra.get("vulnerabilities", [])
            if not vulns:
                continue
            g = await remediation_engine.generate_guidance(
                component_name=ra["component_name"],
                current_version=ra["component_version"],
                ecosystem="pypi",
                vulnerabilities=vulns,
            )
            if g:
                guidances.append(g)

        assert len(guidances) > 0
        urllib_guidance = next(g for g in guidances if g.component_name == "urllib3")
        assert urllib_guidance.recommended_version != "1.26.5"
        assert urllib_guidance.confidence_score > 0.0
        assert len(urllib_guidance.cve_ids_fixed) > 0

        # ─── Step 7: Automated Manifest Patch & Git Diff ─────────────────────
        patch = remediation_engine.generate_manifest_patch(
            manifest_content=manifest_content,
            filename="requirements.txt",
            recommendations=guidances,
        )
        assert patch["modifications_count"] >= 1
        assert "diff" in patch
        assert "a/requirements.txt" in patch["unified_diff"]
        assert "b/requirements.txt" in patch["unified_diff"]
        assert patch["updated_content"] != manifest_content

        # ─── Step 8: Apply Patch & Generate Target SBOM ──────────────────────
        patched_manifest = patch["updated_content"]
        sbom_target = generator.generate(
            content=patched_manifest,
            filename="requirements.txt",
            output_format="cyclonedx",
            project_name="e2e-cloud-microservice-v2",
        )

        # ─── Step 9: SBOM Diff & Version Drift Verification ──────────────────
        manager = SBOMManager()
        # Save both to disk for diffing
        f_base = tmp_path / "base_sbom.json"
        f_target = tmp_path / "target_sbom.json"
        f_base.write_text(json.dumps(sbom_res["document"]))
        f_target.write_text(json.dumps(sbom_target["document"]))

        diff_res = manager.compare_sbom_dicts(sbom_res["document"], sbom_target["document"])
        assert diff_res["stats"]["total_a"] == 3
        assert diff_res["stats"]["total_b"] == 3
        assert diff_res["stats"]["modified_count"] >= 1
        drift_pkgs = [c["name"] for c in diff_res["version_changes"]]
        assert "urllib3" in drift_pkgs

        # ─── Step 10: SARIF 2.1.0 Security Report Export ─────────────────────
        sarif_report = generate_sarif_report(scan_dict, repo_file_path=str(manifest_file))
        assert sarif_report["version"] == "2.1.0"
        assert sarif_report["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert len(sarif_report["runs"]) == 1
        assert len(sarif_report["runs"][0]["results"]) == scan_res.total_vulnerabilities

    def test_spdx_maven_java_lifecycle(self):
        pom_xml = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>secure-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.yaml</groupId>
            <artifactId>snakeyaml</artifactId>
            <version>1.30</version>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-text</artifactId>
            <version>1.9</version>
        </dependency>
    </dependencies>
</project>"""
        generator = SBOMGenerator()
        spdx_res = generator.generate(
            content=pom_xml,
            filename="pom.xml",
            output_format="spdx",
            project_name="maven-enterprise-core",
        )
        assert spdx_res["format"] == "spdx"
        assert spdx_res["component_count"] == 2
        spdx_doc = spdx_res["document"]
        assert spdx_doc["spdxVersion"] == "SPDX-2.3"
        pkg_names = [p["name"] for p in spdx_doc["packages"]]
        assert "org.yaml:snakeyaml" in pkg_names
        assert "org.apache.commons:commons-text" in pkg_names

        # Verify Attestation on SPDX
        attest = attestation_engine.create_attestation(spdx_res, "maven-enterprise-core")
        valid, _ = attestation_engine.verify_attestation(attest, spdx_res)
        assert valid is True
