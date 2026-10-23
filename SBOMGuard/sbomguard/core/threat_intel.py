"""
SBOMGuard Threat Intelligence Engine
Integrates CISA Known Exploited Vulnerabilities (KEV) and FIRST EPSS
(Exploit Prediction Scoring System) feeds with intelligent caching.
"""
import logging
from typing import Optional, Dict, Any
import httpx

from config.settings import CISA_KEV_FEED_URL, EPSS_API_BASE
from sbomguard.core.cache import CacheService
from sbomguard.core.circuit_breaker import cisa_kev_breaker, epss_breaker
from sbomguard.models import Vulnerability

logger = logging.getLogger("sbomguard.threat_intel")

KEV_CACHE_KEY = "threat_intel:cisa_kev_v1"
KEV_TTL = 43200  # 12 hours
EPSS_TTL = 86400  # 24 hours


class ThreatIntelService:
    """Manages external threat intelligence feeds and CVE enrichment."""

    def __init__(self):
        self._kev_map: Dict[str, dict] = {}
        self._load_local_kev_fallback()

    def _load_local_kev_fallback(self):
        """Pre-populate high-profile known exploited vulnerabilities for offline testing."""
        high_profile = {
            "CVE-2021-44228": {"name": "Apache Log4j RCE", "ransomware": True},
            "CVE-2022-22965": {"name": "Spring Framework RCE (Spring4Shell)", "ransomware": True},
            "CVE-2023-34362": {"name": "MOVEit Transfer SQLi", "ransomware": True},
            "CVE-2024-3094": {"name": "XZ Utils Backdoor", "ransomware": False},
            "CVE-2023-4863": {"name": "libwebp Heap Buffer Overflow", "ransomware": False},
            "CVE-2021-3156": {"name": "Sudo Baron Samedit", "ransomware": False},
            "CVE-2023-44487": {"name": "HTTP/2 Rapid Reset", "ransomware": False},
        }
        for cve, meta in high_profile.items():
            self._kev_map[cve] = {
                "cveID": cve,
                "vulnerabilityName": meta["name"],
                "knownRansomwareCampaignUse": "Known" if meta["ransomware"] else "Unknown",
            }

    async def get_cisa_kev_catalog(self) -> Dict[str, dict]:
        """Fetch and cache CISA KEV catalog."""
        cached = CacheService.get(KEV_CACHE_KEY)
        if cached:
            return cached

        try:
            cisa_kev_breaker.check_state()
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(CISA_KEV_FEED_URL)
                if resp.status_code == 200:
                    cisa_kev_breaker.record_success()
                    data = resp.json()
                    catalog = {}
                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cveID", "").upper()
                        if cve:
                            catalog[cve] = {
                                "cveID": cve,
                                "vendorProject": item.get("vendorProject", ""),
                                "product": item.get("product", ""),
                                "vulnerabilityName": item.get("vulnerabilityName", ""),
                                "dateAdded": item.get("dateAdded", ""),
                                "dueDate": item.get("dueDate", ""),
                                "knownRansomwareCampaignUse": item.get("knownRansomwareCampaignUse", "Unknown"),
                            }
                    if catalog:
                        CacheService.set(KEV_CACHE_KEY, catalog, ttl_seconds=KEV_TTL)
                        self._kev_map.update(catalog)
                        return catalog
                else:
                    cisa_kev_breaker.record_failure(Exception(f"HTTP {resp.status_code}"))
        except Exception as e:
            cisa_kev_breaker.record_failure(e)
            logger.debug(f"Failed to fetch live CISA KEV feed ({e}), using fallback.")

        return self._kev_map

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if CVE is present in CISA KEV catalog (synchronous / fast lookup)."""
        clean_cve = cve_id.strip().upper()
        # Check in memory first
        if clean_cve in self._kev_map:
            return True
        # Check cache
        cached = CacheService.get(KEV_CACHE_KEY)
        if cached and clean_cve in cached:
            return True
        return False

    def get_kev_details(self, cve_id: str) -> Optional[dict]:
        """Retrieve CISA KEV details for a CVE."""
        clean_cve = cve_id.strip().upper()
        if clean_cve in self._kev_map:
            return self._kev_map[clean_cve]
        cached = CacheService.get(KEV_CACHE_KEY)
        if cached and clean_cve in cached:
            return cached[clean_cve]
        return None

    async def fetch_epss(self, cve_id: str) -> dict:
        """Fetch EPSS score and percentile from FIRST API with caching."""
        clean_cve = cve_id.strip().upper()
        if not clean_cve.startswith("CVE-"):
            return {"epss": 0.0, "percentile": 0.0}

        cache_key = f"threat_intel:epss:{clean_cve}"
        cached = CacheService.get(cache_key)
        if cached:
            return cached

        result = {"epss": 0.0, "percentile": 0.0}
        try:
            epss_breaker.check_state()
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
                url = f"{EPSS_API_BASE}?cve={clean_cve}"
                resp = await client.get(url)
                if resp.status_code == 200:
                    epss_breaker.record_success()
                    data = resp.json()
                    epss_data = data.get("data", [])
                    if epss_data:
                        score = float(epss_data[0].get("epss", 0.0))
                        pct = float(epss_data[0].get("percentile", 0.0))
                        result = {"epss": score, "percentile": pct}
                        CacheService.set(cache_key, result, ttl_seconds=EPSS_TTL)
                else:
                    epss_breaker.record_failure(Exception(f"HTTP {resp.status_code}"))
        except Exception as e:
            epss_breaker.record_failure(e)
            logger.debug(f"EPSS lookup failed for {clean_cve}: {e}")

        return result

    def enrich_vulnerability(self, vuln: Vulnerability) -> Vulnerability:
        """Enrich a vulnerability record with KEV and EPSS signals."""
        candidates = [vuln.id.strip().upper()] + [a.strip().upper() for a in getattr(vuln, "aliases", [])]

        for cve in candidates:
            if self.is_in_kev(cve):
                vuln.in_kev = True
                vuln.exploit_available = True
                break

        for cve in candidates:
            cached_epss = CacheService.get(f"threat_intel:epss:{cve}")
            if cached_epss:
                vuln.epss_score = float(cached_epss.get("epss", vuln.epss_score))
                vuln.epss_percentile = float(cached_epss.get("percentile", vuln.epss_percentile))
                if vuln.epss_score >= 0.4:
                    vuln.exploit_available = True
                break

        return vuln


# Global Singleton Instance
threat_intel = ThreatIntelService()
