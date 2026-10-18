"""
Unit Tests for Database Models and Repository Operations
"""
import sys
import uuid
from pathlib import Path
import pytest
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomguard.database import (
    save_sbom,
    get_sbom,
    list_sboms,
    delete_sbom,
    save_scan,
    get_scan,
    list_scans,
    get_dashboard_stats,
    init_database,
)


@pytest.fixture(autouse=True)
async def setup_db():
    await init_database()


class TestDatabaseRepository:
    def test_sbom_crud_lifecycle(self):
        test_id = str(uuid.uuid4())
        sbom_data = {
            "id": test_id,
            "name": "test-repo",
            "version": "1.0",
            "format": "cyclonedx",
            "source_file": "requirements.txt",
            "manifest_type": "requirements.txt",
            "component_count": 2,
            "quality_score": 85.0,
            "components": [
                {
                    "name": "flask",
                    "version": "2.3.0",
                    "type": "library",
                    "purl": "pkg:pypi/flask@2.3.0",
                    "ecosystem": "pypi",
                    "license": "BSD-3-Clause",
                    "is_direct": True,
                    "depth": 0,
                },
                {
                    "name": "requests",
                    "version": "2.25.1",
                    "type": "library",
                    "purl": "pkg:pypi/requests@2.25.1",
                    "ecosystem": "pypi",
                    "license": "Apache-2.0",
                    "is_direct": True,
                    "depth": 0,
                },
            ],
        }

        # 1. Save
        saved_id = save_sbom(sbom_data)
        assert saved_id == test_id

        # 2. Get
        retrieved = get_sbom(test_id)
        assert retrieved is not None
        assert retrieved["name"] == "test-repo"
        assert len(retrieved["components"]) == 2

        # 3. List
        all_sboms = list_sboms(limit=10)
        assert any(s["id"] == test_id for s in all_sboms)

        # 4. Delete
        deleted = delete_sbom(test_id)
        assert deleted is True
        assert get_sbom(test_id) is None

    def test_multi_tenant_isolation(self):
        id_tenant_a = str(uuid.uuid4())
        id_tenant_b = str(uuid.uuid4())

        data_a = {"id": id_tenant_a, "name": "tenant-a-app", "component_count": 1, "components": []}
        data_b = {"id": id_tenant_b, "name": "tenant-b-app", "component_count": 1, "components": []}

        save_sbom(data_a, tenant_id="tenant-alpha")
        save_sbom(data_b, tenant_id="tenant-beta")

        # Tenant alpha can only see their own SBOM
        assert get_sbom(id_tenant_a, tenant_id="tenant-alpha") is not None
        assert get_sbom(id_tenant_b, tenant_id="tenant-alpha") is None

        # Tenant beta can only see their own SBOM
        assert get_sbom(id_tenant_b, tenant_id="tenant-beta") is not None
        assert get_sbom(id_tenant_a, tenant_id="tenant-beta") is None

    def test_dashboard_stats_telemetry(self):
        stats = get_dashboard_stats()
        assert "total_sboms" in stats
        assert "total_components" in stats
        assert "total_vulnerabilities" in stats
        assert "avg_risk_score" in stats
        assert "ecosystem_distribution" in stats
        assert "dependency_ratio" in stats
