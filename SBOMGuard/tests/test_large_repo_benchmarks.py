"""
SBOMGuard — Multi-Ecosystem Large-Scale Performance Benchmarking Suite
Evaluates parsing, SBOM generation (CycloneDX 1.5 & SPDX 2.3), vulnerability correlation,
NTIA Minimum Elements compliance, and memory footprint across 6 real-world enterprise repositories:
1. Kubernetes (Go / go.mod)
2. Django (Python / requirements.txt)
3. React & Next.js (Node.js / package.json)
4. FastAPI (Python / requirements.txt)
5. Spring Boot (Java / pom.xml)
6. HashiCorp Terraform (Go / go.mod)
"""
import time
import json
import tracemalloc
import pytest
from pathlib import Path
from typing import Dict, Any

from sbomguard.core.generator import SBOMGenerator
from sbomguard.core.policy import PolicyEngine, SecurityPolicy
from sbomguard.core.attestation import attestation_engine
from sbomguard.models import Component


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "real_world"

BENCHMARK_TARGETS = [
    {
        "id": "kubernetes",
        "name": "Kubernetes Orchestration Engine",
        "ecosystem": "go",
        "filename": "kubernetes_go.mod",
        "manifest_type": "go.mod",
        "min_components": 15,
    },
    {
        "id": "django",
        "name": "Django Web Framework Project",
        "ecosystem": "pypi",
        "filename": "django_requirements.txt",
        "manifest_type": "requirements.txt",
        "min_components": 8,
    },
    {
        "id": "react_nextjs",
        "name": "Next.js & React Web Application",
        "ecosystem": "npm",
        "filename": "react_nextjs_package.json",
        "manifest_type": "package.json",
        "min_components": 15,
    },
    {
        "id": "fastapi",
        "name": "FastAPI High-Performance Cloud Service",
        "ecosystem": "pypi",
        "filename": "fastapi_requirements.txt",
        "manifest_type": "requirements.txt",
        "min_components": 8,
    },
    {
        "id": "spring_boot",
        "name": "Spring Boot Enterprise Application",
        "ecosystem": "maven",
        "filename": "spring_boot_pom.xml",
        "manifest_type": "pom.xml",
        "min_components": 8,
    },
    {
        "id": "terraform",
        "name": "HashiCorp Terraform Provider Infrastructure",
        "ecosystem": "go",
        "filename": "terraform_go.mod",
        "manifest_type": "go.mod",
        "min_components": 18,
    },
]


class TestLargeRepoBenchmarks:
    """Rigorous benchmarking and telemetry collection across enterprise manifests."""

    @pytest.mark.parametrize("target", BENCHMARK_TARGETS, ids=[t["id"] for t in BENCHMARK_TARGETS])
    def test_benchmark_cyclonedx_generation(self, target: Dict[str, Any]):
        filepath = FIXTURES_DIR / target["filename"]
        assert filepath.exists(), f"Benchmark fixture {filepath} missing"
        content = filepath.read_text(encoding="utf-8")

        generator = SBOMGenerator()

        # Measure memory and latency
        tracemalloc.start()
        start_time = time.perf_counter()

        sbom_res = generator.generate(
            content=content,
            filename=target["filename"],
            output_format="cyclonedx",
            project_name=target["name"],
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Assertions
        assert sbom_res is not None
        assert sbom_res["format"] == "cyclonedx"
        assert sbom_res["component_count"] >= target["min_components"]
        assert sbom_res["quality_score"] >= 60.0, "Must satisfy NTIA minimum quality threshold"
        assert elapsed_ms < 500.0, f"Generation exceeded SLA: {elapsed_ms:.2f}ms"
        assert peak_mem < 15 * 1024 * 1024, f"Peak memory exceeded SLA: {peak_mem / (1024*1024):.2f}MB"

        # Validate In-toto Attestation performance
        start_attest = time.perf_counter()
        attestation = attestation_engine.create_attestation(sbom_res, project_name=target["name"])
        attest_time_ms = (time.perf_counter() - start_attest) * 1000.0
        assert attest_time_ms < 100.0, "Attestation generation took too long"
        assert attestation["payloadType"] == "application/vnd.in-toto+json"

        # Validate Policy Engine evaluation speed
        engine = PolicyEngine(policy=SecurityPolicy())
        dummy_scan = {
            "critical_count": 0,
            "high_count": 0,
            "risk_assessments": [],
        }
        start_policy = time.perf_counter()
        eval_result = engine.evaluate(dummy_scan, sbom_res)
        policy_time_ms = (time.perf_counter() - start_policy) * 1000.0
        assert policy_time_ms < 50.0, "Policy evaluation took too long"
        assert eval_result.passed is True

    @pytest.mark.parametrize("target", BENCHMARK_TARGETS, ids=[t["id"] for t in BENCHMARK_TARGETS])
    def test_benchmark_spdx_generation(self, target: Dict[str, Any]):
        filepath = FIXTURES_DIR / target["filename"]
        content = filepath.read_text(encoding="utf-8")

        generator = SBOMGenerator()

        start_time = time.perf_counter()
        sbom_res = generator.generate(
            content=content,
            filename=target["filename"],
            output_format="spdx",
            project_name=target["name"],
        )
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        assert sbom_res is not None
        assert sbom_res["format"] == "spdx"
        assert sbom_res["component_count"] >= target["min_components"]
        assert elapsed_ms < 500.0, f"SPDX generation exceeded SLA: {elapsed_ms:.2f}ms"
        doc = sbom_res["document"]
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert len(doc["packages"]) >= target["min_components"]
