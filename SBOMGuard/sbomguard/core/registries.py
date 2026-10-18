"""
SBOMGuard Package Registries Client
Multi-source package version resolution for PyPI, npm, Maven Central, and Go modules.
Retrieves release histories, release dates, and package health signals.
"""
import logging
from typing import List, Optional, Dict, Any
import httpx
from packaging.version import parse as parse_version, InvalidVersion

from config.settings import (
    PYPI_REGISTRY_BASE,
    NPM_REGISTRY_BASE,
    MAVEN_SEARCH_BASE,
    GO_PROXY_BASE,
)
from sbomguard.core.cache import CacheService

logger = logging.getLogger("sbomguard.registries")
REGISTRY_CACHE_TTL = 21600  # 6 hours


class RegistryClient:
    """Multi-ecosystem client for resolving available package versions and metadata."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    async def get_package_versions(self, name: str, ecosystem: str) -> List[str]:
        """
        Resolve all available stable versions for a package from its official registry.
        Sorted in ascending SemVer order.
        """
        eco = (ecosystem or "").lower().strip()
        cache_key = f"registry_versions:{eco}:{name}"
        cached = CacheService.get(cache_key)
        if cached is not None:
            return cached

        versions = []
        if eco in ("pypi", "python"):
            versions = await self._fetch_pypi_versions(name)
        elif eco in ("npm", "node", "javascript", "typescript"):
            versions = await self._fetch_npm_versions(name)
        elif eco in ("maven", "java"):
            versions = await self._fetch_maven_versions(name)
        elif eco in ("go", "golang"):
            versions = await self._fetch_go_versions(name)

        if versions:
            CacheService.set(cache_key, versions, ttl_seconds=REGISTRY_CACHE_TTL)
        return versions

    async def _fetch_pypi_versions(self, package_name: str) -> List[str]:
        """Fetch versions from PyPI JSON API."""
        url = f"{PYPI_REGISTRY_BASE}/{package_name}/json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    releases = data.get("releases", {})
                    # Filter out yanked releases and sort valid semver
                    valid_versions = []
                    for v_str, files in releases.items():
                        if any(f.get("yanked", False) for f in files):
                            continue
                        try:
                            v = parse_version(v_str)
                            if not v.is_prerelease and not v.is_devrelease:
                                valid_versions.append(v_str)
                        except InvalidVersion:
                            continue
                    return self._sort_versions(valid_versions)
        except Exception as e:
            logger.debug(f"PyPI version fetch error for {package_name}: {e}")
        return []

    async def _fetch_npm_versions(self, package_name: str) -> List[str]:
        """Fetch versions from npm Registry API."""
        url = f"{NPM_REGISTRY_BASE}/{package_name}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    versions_dict = data.get("versions", {})
                    valid_versions = []
                    for v_str in versions_dict.keys():
                        try:
                            v = parse_version(v_str)
                            if not v.is_prerelease and not v.is_devrelease:
                                valid_versions.append(v_str)
                        except InvalidVersion:
                            continue
                    return self._sort_versions(valid_versions)
        except Exception as e:
            logger.debug(f"npm version fetch error for {package_name}: {e}")
        return []

    async def _fetch_maven_versions(self, full_name: str) -> List[str]:
        """Fetch versions from Maven Central."""
        parts = full_name.split(":")
        if len(parts) == 2:
            group, artifact = parts
            query = f"g:{group} AND a:{artifact}"
        else:
            query = f"a:{full_name}"

        url = f"{MAVEN_SEARCH_BASE}?q={query}&rows=50&wt=json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    docs = data.get("response", {}).get("docs", [])
                    versions = [d.get("v") for d in docs if d.get("v")]
                    return self._sort_versions(versions)
        except Exception as e:
            logger.debug(f"Maven version fetch error for {full_name}: {e}")
        return []

    async def _fetch_go_versions(self, module_name: str) -> List[str]:
        """Fetch versions from Go Proxy."""
        url = f"{GO_PROXY_BASE}/{module_name}/@v/list"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    lines = resp.text.strip().splitlines()
                    clean_vers = [line.strip().lstrip("v") for line in lines if line.strip()]
                    return self._sort_versions(clean_vers)
        except Exception as e:
            logger.debug(f"Go module version fetch error for {module_name}: {e}")
        return []

    @staticmethod
    def _sort_versions(versions: List[str]) -> List[str]:
        """Sort versions in ascending order using packaging.version."""
        def safe_key(v: str):
            try:
                return (0, parse_version(v))
            except Exception:
                return (1, v)

        return sorted(list(set(versions)), key=safe_key)


# Global registry client
registry_client = RegistryClient()
