"""Simple TTL cache for API responses."""

import time
import logging
from typing import Optional, Any

logger = logging.getLogger("cybersentinel.utils.cache")


class TTLCache:
    """In-memory cache with per-key time-to-live expiration."""

    def __init__(self, default_ttl: int = 300) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self._default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        """Retrieve a cached value if it exists and hasn't expired."""
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            logger.debug("Cache miss (expired): %s", key)
            return None
        logger.debug("Cache hit: %s", key)
        return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store a value with an optional custom TTL."""
        ttl = ttl if ttl is not None else self._default_ttl
        expires_at = time.monotonic() + ttl
        self._store[key] = (value, expires_at)
        logger.debug("Cache set: %s (ttl=%ds)", key, ttl)

    def invalidate(self, key: str) -> None:
        """Remove a key from the cache."""
        self._store.pop(key, None)

    def clear(self) -> None:
        """Remove all entries."""
        self._store.clear()

    def size(self) -> int:
        """Return the number of entries (including possibly expired ones)."""
        return len(self._store)
