"""
Unit tests for CacheService and in-memory TTL caching
"""
import time
from sbomguard.core.cache import CacheService, _in_memory_cache


class TestCacheService:
    def setup_method(self):
        CacheService.clear()

    def teardown_method(self):
        CacheService.clear()

    def test_set_and_get(self):
        CacheService.set("test_key", {"foo": "bar"}, ttl_seconds=60)
        cached = CacheService.get("test_key")
        assert cached == {"foo": "bar"}

    def test_get_nonexistent(self):
        assert CacheService.get("missing_key") is None

    def test_delete(self):
        CacheService.set("test_delete", "value", ttl_seconds=60)
        assert CacheService.get("test_delete") == "value"
        CacheService.delete("test_delete")
        assert CacheService.get("test_delete") is None

    def test_ttl_expiry(self):
        CacheService.set("expire_key", "old_value", ttl_seconds=0)
        time.sleep(0.01)
        assert CacheService.get("expire_key") is None

    def test_clear(self):
        CacheService.set("k1", 1)
        CacheService.set("k2", 2)
        CacheService.clear()
        assert CacheService.get("k1") is None
        assert CacheService.get("k2") is None
