"""
Integration Tests for SBOMGuard FastAPI Endpoints
"""
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomguard.main import app

client = TestClient(app)


class TestApiIntegration:
    def test_health_endpoints(self):
        resp_live = client.get("/health/live")
        assert resp_live.status_code == 200
        assert resp_live.json()["status"] == "ok"

        resp_ready = client.get("/health/ready")
        assert resp_ready.status_code == 200
        assert resp_ready.json()["status"] == "ready"

    def test_prometheus_metrics(self):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "sbomguard_http_requests_total" in resp.text

    def test_generate_and_list_sbom(self):
        manifest_content = "flask==2.3.0\nrequests==2.25.1\n"
        files = {"file": ("requirements.txt", manifest_content, "text/plain")}
        data = {"format": "cyclonedx", "project_name": "api-test-suite"}

        gen_resp = client.post("/api/v1/sbom/generate", files=files, data=data)
        assert gen_resp.status_code == 200
        body = gen_resp.json()
        assert body["status"] == "success"
        sbom_id = body["data"]["sbom_id"]
        assert body["data"]["component_count"] == 2

        # Verify listing
        list_resp = client.get("/api/v1/sbom/list")
        assert list_resp.status_code == 200
        sboms = list_resp.json()["data"]
        assert any(s["id"] == sbom_id for s in sboms)

        # Get SBOM
        get_resp = client.get(f"/api/v1/sbom/{sbom_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["data"]["name"] == "api-test-suite"

    def test_compare_sboms_api(self):
        # Generate two small SBOMs
        f1 = {"file": ("requirements.txt", "flask==2.3.0\n", "text/plain")}
        f2 = {"file": ("requirements.txt", "flask==3.0.3\nrequests==2.31.0\n", "text/plain")}

        id1 = client.post("/api/v1/sbom/generate", files=f1, data={"format": "cyclonedx"}).json()["data"]["sbom_id"]
        id2 = client.post("/api/v1/sbom/generate", files=f2, data={"format": "cyclonedx"}).json()["data"]["sbom_id"]

        comp_resp = client.post(
            "/api/v1/sbom/compare",
            json={"sbom_a_id": id1, "sbom_b_id": id2},
        )
        assert comp_resp.status_code == 200
        diff = comp_resp.json()["data"]
        assert diff["stats"]["modified_count"] == 1
        assert diff["stats"]["added_count"] == 1
        assert diff["version_changes"][0]["name"] == "flask"
        assert diff["version_changes"][0]["drift_type"] == "major"

    def test_dashboard_stats_api(self):
        resp = client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        stats = resp.json()["data"]
        assert "total_sboms" in stats
        assert "total_components" in stats

    def test_sbom_validate_download_delete(self):
        files = {"file": ("requirements.txt", "urllib3==1.26.5\n", "text/plain")}
        gen = client.post("/api/v1/sbom/generate", files=files, data={"format": "cyclonedx"}).json()["data"]
        sbom_id = gen["sbom_id"]

        # Validate
        val_resp = client.post(f"/api/v1/sbom/validate/{sbom_id}")
        assert val_resp.status_code == 200
        assert "quality_score" in val_resp.json()["data"]

        # Download
        dl_resp = client.get(f"/api/v1/sbom/download/{sbom_id}")
        assert dl_resp.status_code == 200

        # Delete
        del_resp = client.delete(f"/api/v1/sbom/{sbom_id}")
        assert del_resp.status_code == 200

        # 404 on missing
        assert client.get(f"/api/v1/sbom/{sbom_id}").status_code == 404
        assert client.delete(f"/api/v1/sbom/{sbom_id}").status_code == 404
        assert client.post(f"/api/v1/sbom/validate/{sbom_id}").status_code == 404

    def test_compare_missing_parameters(self):
        resp = client.post("/api/v1/sbom/compare", json={})
        assert resp.status_code == 400
