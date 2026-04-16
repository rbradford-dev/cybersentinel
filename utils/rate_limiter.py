"""Per-source async rate limiter using asyncio.Semaphore."""

import asyncio
import time
import logging
from typing import Optional

logger = logging.getLogger("cybersentinel.utils.rate_limiter")


class RateLimiter:
    """Sliding-window rate limiter backed by asyncio.Semaphore."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._semaphore = asyncio.Semaphore(max_requests)
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request slot is available within the window."""
        while True:
            async with self._lock:
                now = time.monotonic()
                # Purge timestamps outside the window
                self._timestamps = [
                    t for t in self._timestamps if now - t < self._window
                ]
                if len(self._timestamps) < self._max:
                    self._timestamps.append(now)
                    return
                # Calculate how long to wait
                oldest = self._timestamps[0]
                wait = self._window - (now - oldest) + 0.05

            logger.debug("Rate limiter: waiting %.2fs", wait)
            await asyncio.sleep(wait)

    async def __aenter__(self) -> "RateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        pass


# Pre-configured limiters for known sources
_limiters: dict[str, RateLimiter] = {}


def get_limiter(source: str, max_requests: int, window_seconds: float) -> RateLimiter:
    """Get or create a rate limiter for a given source."""
    if source not in _limiters:
        _limiters[source] = RateLimiter(max_requests, window_seconds)
    return _limiters[source]
