"""
SBOMGuard Caching Layer
High-performance Redis cache with seamless in-memory TTL fallback.
Caches vulnerability lookups, registry metadata, and threat intelligence.
"""
import json
import logging
import time
from typing import Any, Optional

from config.settings import REDIS_ENABLED, REDIS_URL, REDIS_CACHE_TTL_SECONDS

logger = logging.getLogger("sbomguard.cache")

_redis_client = None
_in_memory_cache: dict[str, tuple[float, str]] = {}


def get_redis_client():
    """Initialize or return Redis client if enabled and reachable."""
    global _redis_client
    if not REDIS_ENABLED:
        return None

    if _redis_client is None:
        try:
            import redis
            client = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=1.5)
            client.ping()
            _redis_client = client
            logger.info(f"✅ Connected to Redis cache at {REDIS_URL}")
        except Exception as e:
            logger.debug(f"Redis unavailable ({e}), using in-memory TTL cache.")
            _redis_client = None
    return _redis_client


class CacheService:
    """Unified cache service for Redis with in-memory fallback."""

    @staticmethod
    def get(key: str) -> Optional[Any]:
        """Retrieve a cached value by key."""
        r = get_redis_client()
        if r:
            try:
                val = r.get(key)
                if val:
                    return json.loads(val)
            except Exception as e:
                logger.debug(f"Redis get error for {key}: {e}")

        # Check in-memory fallback
        item = _in_memory_cache.get(key)
        if item:
            expiry, data = item
            if time.time() < expiry:
                try:
                    return json.loads(data)
                except Exception:
                    return data
            else:
                _in_memory_cache.pop(key, None)
        return None

    @staticmethod
    def set(key: str, value: Any, ttl_seconds: int = REDIS_CACHE_TTL_SECONDS) -> None:
        """Store a value in cache with TTL."""
        serialized = json.dumps(value, default=str)
        r = get_redis_client()
        if r:
            try:
                r.setex(key, ttl_seconds, serialized)
                return
            except Exception as e:
                logger.debug(f"Redis set error for {key}: {e}")

        # In-memory fallback
        _in_memory_cache[key] = (time.time() + ttl_seconds, serialized)

    @staticmethod
    def delete(key: str) -> None:
        """Remove a key from cache."""
        r = get_redis_client()
        if r:
            try:
                r.delete(key)
            except Exception:
                pass
        _in_memory_cache.pop(key, None)

    @staticmethod
    def clear() -> None:
        """Clear all in-memory cache items."""
        _in_memory_cache.clear()
