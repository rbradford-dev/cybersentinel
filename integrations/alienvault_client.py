"""AlienVault OTX client — queries OTX for IOC enrichment and threat intelligence.

Uses the AlienVault OTX REST API (https://otx.alienvault.com/api/v1) via httpx
for async consistency with the rest of the CyberSentinel integration layer.
Provides IP reputation, domain reputation, malware association lookups, and
pulse search for threat intelligence enrichment.
"""

import logging
from typing import Optional

import httpx

import config
from utils.cache import TTLCache

logger = logging.getLogger("cybersentinel.integrations.alienvault")

_cache = TTLCache(default_ttl=config.OTX_CACHE_TTL)


class AlienVaultClient:
    """Async client for the AlienVault OTX API — IOC enrichment."""

    BASE_URL = config.OTX_BASE_URL

    def __init__(self) -> None:
        self._api_key: str = config.OTX_API_KEY
        self._enabled: bool = bool(self._api_key)

        # Diagnostic logging — always at WARNING so it reaches the console.
        # This is intentional: OTX init only happens a few times per session,
        # and knowing the client state is critical for debugging.
        if self._enabled:
            masked = self._api_key[:4] + "..." + self._api_key[-4:] if len(self._api_key) > 8 else "****"
            logger.warning(
                "AlienVault OTX client ENABLED — key loaded (%s), base_url=%s",
                masked, self.BASE_URL,
            )
        else:
            logger.warning(
                "AlienVault OTX client DISABLED — OTX_API_KEY is empty. "
                "Set it in .env to enable IOC enrichment."
            )

    @property
    def enabled(self) -> bool:
        """Return True if the client has a valid API key."""
        return self._enabled

    # ------------------------------------------------------------------
    # Public enrichment methods
    # ------------------------------------------------------------------

    async def get_ip_reputation(self, ip: str) -> dict:
        """Get general reputation data for an IPv4 address.

        Calls GET /indicators/IPv4/{ip}/general and returns the parsed
        response dict, or an empty dict on failure / when disabled.
        """
        if not self._enabled:
            logger.warning("OTX get_ip_reputation(%s) skipped — client disabled", ip)
            return {}

        cache_key = f"otx:ip:general:{ip}"
        data = await self._get(f"/indicators/IPv4/{ip}/general", cache_key=cache_key)
        if data is None:
            return {}

        logger.warning(
            "OTX get_ip_reputation(%s): pulse_count=%s, reputation=%s",
            ip,
            data.get("pulse_info", {}).get("count", "n/a"),
            data.get("reputation", "n/a"),
        )
        return data

    async def get_ip_malware(self, ip: str) -> list[dict]:
        """Get malware samples associated with an IPv4 address.

        Calls GET /indicators/IPv4/{ip}/malware and returns a list of
        malware sample dicts, or an empty list on failure / when disabled.
        """
        if not self._enabled:
            logger.warning("OTX get_ip_malware(%s) skipped — client disabled", ip)
            return []

        cache_key = f"otx:ip:malware:{ip}"
        data = await self._get(f"/indicators/IPv4/{ip}/malware", cache_key=cache_key)
        if data is None:
            return []

        samples = data.get("data", [])
        logger.warning(
            "OTX get_ip_malware(%s): %d malware samples found",
            ip, len(samples),
        )
        return samples

    async def get_domain_reputation(self, domain: str) -> dict:
        """Get general reputation data for a domain.

        Calls GET /indicators/domain/{domain}/general and returns the
        parsed response dict, or an empty dict on failure / when disabled.
        """
        if not self._enabled:
            logger.warning("OTX get_domain_reputation(%s) skipped — client disabled", domain)
            return {}

        cache_key = f"otx:domain:general:{domain}"
        data = await self._get(f"/indicators/domain/{domain}/general", cache_key=cache_key)
        if data is None:
            return {}

        logger.warning(
            "OTX get_domain_reputation(%s): pulse_count=%s, whois=%s",
            domain,
            data.get("pulse_info", {}).get("count", "n/a"),
            "present" if data.get("whois") else "absent",
        )
        return data

    async def search_pulses(self, query: str, limit: int = 10) -> list[dict]:
        """Search OTX pulses for threat intelligence.

        Calls GET /search/pulses?q={query}&limit={limit} and returns a
        list of pulse dicts, or an empty list on failure / when disabled.
        """
        if not self._enabled:
            logger.warning("OTX search_pulses(%r) skipped — client disabled", query)
            return []

        cache_key = f"otx:pulses:{query[:60]}:{limit}"
        data = await self._get(
            f"/search/pulses?q={query}&limit={limit}",
            cache_key=cache_key,
        )
        if data is None:
            return []

        results = data.get("results", [])
        logger.warning(
            "OTX search_pulses(%r): %d pulses returned (limit=%d)",
            query[:60], len(results), limit,
        )
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get(self, endpoint: str, cache_key: Optional[str] = None) -> Optional[dict]:
        """Make an authenticated GET request to the OTX API.

        Handles caching, auth headers, and standard error responses.
        Returns the parsed JSON dict on success, or None on failure.
        """
        # Check cache first
        if cache_key:
            cached = _cache.get(cache_key)
            if cached is not None:
                logger.warning(
                    "OTX cache hit for %s", cache_key,
                )
                return cached

        url = f"{self.BASE_URL}{endpoint}"
        headers = {
            "X-OTX-API-KEY": self._api_key,
        }

        logger.warning("OTX GET %s", endpoint)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(url, headers=headers)

            logger.warning(
                "OTX %s responded: HTTP %d (%d bytes)",
                endpoint, resp.status_code, len(resp.content),
            )

            if resp.status_code == 200:
                data = resp.json()
                if cache_key and data:
                    _cache.set(cache_key, data)
                return data

            if resp.status_code == 401:
                logger.warning(
                    "OTX API: INVALID API KEY (401). Check OTX_API_KEY in .env. "
                    "Response: %s", resp.text[:300],
                )
                self._enabled = False
                return None

            if resp.status_code == 429:
                logger.warning("OTX API: rate limited (429). Response: %s", resp.text[:200])
                return None

            if resp.status_code >= 500:
                logger.warning(
                    "OTX API server error: HTTP %d — %s",
                    resp.status_code, resp.text[:300],
                )
                return None

            logger.warning(
                "OTX API error: HTTP %d — %s", resp.status_code, resp.text[:300],
            )
            return None

        except httpx.HTTPError as exc:
            logger.warning("OTX HTTP connection error: %s", exc)
            return None
