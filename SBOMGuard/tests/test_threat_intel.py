"""
Unit tests for Threat Intelligence Service (CISA KEV + EPSS)
"""
import pytest
from unittest.mock import patch, MagicMock
import httpx

from sbomguard.core.threat_intel import ThreatIntelService, threat_intel
from sbomguard.core.cache import CacheService
from sbomguard.models import Vulnerability, Severity


class TestThreatIntelService:
    def setup_method(self):
        CacheService.clear()

    def teardown_method(self):
        CacheService.clear()

    def test_local_kev_fallback(self):
        service = ThreatIntelService()
        assert service.is_in_kev("CVE-2021-44228") is True
        assert service.is_in_kev("CVE-9999-0001") is False

        details = service.get_kev_details("CVE-2021-44228")
        assert details is not None
        assert "Apache Log4j" in details.get("vulnerabilityName", "")

    @pytest.mark.asyncio
    async def test_fetch_cisa_kev_catalog(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2023-1234",
                    "vendorProject": "TestVendor",
                    "product": "TestProduct",
                    "vulnerabilityName": "Remote Code Execution",
                    "dateAdded": "2023-01-01",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        }

        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            service = ThreatIntelService()
            catalog = await service.get_cisa_kev_catalog()
            assert "CVE-2023-1234" in catalog
            assert service.is_in_kev("CVE-2023-1234") is True

    @pytest.mark.asyncio
    async def test_fetch_epss(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.999"}
            ]
        }

        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            service = ThreatIntelService()
            res = await service.fetch_epss("CVE-2021-44228")
            assert res["epss"] == 0.975
            assert res["percentile"] == 0.999

    def test_enrich_vulnerability(self):
        service = ThreatIntelService()
        vuln = Vulnerability(
            id="CVE-2021-44228",
            package_name="log4j-core",
            installed_version="2.14.0",
            fixed_versions=["2.17.1"],
            severity=Severity.CRITICAL,
            cvss_score=10.0,
        )
        enriched = service.enrich_vulnerability(vuln)
        assert enriched.in_kev is True
        assert enriched.exploit_available is True
