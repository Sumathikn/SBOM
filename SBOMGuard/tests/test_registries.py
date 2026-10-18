"""
Unit tests for multi-ecosystem package registry resolution
"""
import pytest
from unittest.mock import patch, MagicMock
import httpx

from sbomguard.core.registries import RegistryClient, registry_client
from sbomguard.core.cache import CacheService


class TestRegistryClient:
    def setup_method(self):
        CacheService.clear()

    def teardown_method(self):
        CacheService.clear()

    @pytest.mark.asyncio
    async def test_pypi_versions_fetch(self):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "releases": {
                "1.0.0": [{"yanked": False}],
                "1.1.0": [{"yanked": False}],
                "1.2.0a1": [{"yanked": False}],  # prerelease should be excluded
                "1.0.1": [{"yanked": True}],     # yanked should be excluded
                "2.0.0": [{"yanked": False}],
            }
        }

        with patch("httpx.AsyncClient.get", return_value=mock_response):
            client = RegistryClient()
            versions = await client.get_package_versions("flask", "pypi")
            assert versions == ["1.0.0", "1.1.0", "2.0.0"]

    @pytest.mark.asyncio
    async def test_npm_versions_fetch(self):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "versions": {
                "4.17.20": {},
                "4.17.21": {},
                "4.18.0-beta.1": {},  # prerelease
                "5.0.0": {},
            }
        }

        with patch("httpx.AsyncClient.get", return_value=mock_response):
            client = RegistryClient()
            versions = await client.get_package_versions("lodash", "npm")
            assert "4.17.20" in versions
            assert "4.17.21" in versions
            assert "5.0.0" in versions
            assert "4.18.0-beta.1" not in versions

    @pytest.mark.asyncio
    async def test_maven_versions_fetch(self):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": {
                "docs": [
                    {"v": "2.14.0"},
                    {"v": "2.15.0"},
                    {"v": "2.17.1"},
                ]
            }
        }

        with patch("httpx.AsyncClient.get", return_value=mock_response):
            client = RegistryClient()
            versions = await client.get_package_versions("org.apache.logging.log4j:log4j-core", "maven")
            assert versions == ["2.14.0", "2.15.0", "2.17.1"]

    @pytest.mark.asyncio
    async def test_go_versions_fetch(self):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.text = "v1.2.0\nv1.3.1\nv1.4.0\n"

        with patch("httpx.AsyncClient.get", return_value=mock_response):
            client = RegistryClient()
            versions = await client.get_package_versions("github.com/gin-gonic/gin", "go")
            assert versions == ["1.2.0", "1.3.1", "1.4.0"]

    def test_sort_versions(self):
        unsorted = ["1.10.0", "1.2.0", "2.0.0", "0.9.5", "invalid-version"]
        sorted_vers = RegistryClient._sort_versions(unsorted)
        assert sorted_vers[0] == "0.9.5"
        assert sorted_vers[1] == "1.2.0"
        assert sorted_vers[2] == "1.10.0"
        assert sorted_vers[3] == "2.0.0"
