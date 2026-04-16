"""AbuseIPDB client — checks IP address abuse reports and reputation data.

Uses the AbuseIPDB REST API (https://api.abuseipdb.com/api/v2) via httpx for
async consistency with the rest of the CyberSentinel integration layer.
Provides IP reputation lookups including abuse confidence scores, report
counts, category breakdowns, and geographic information.
"""

import asyncio
import logging
from typing import Optional

import httpx

import config
from utils.cache import TTLCache

logger = logging.getLogger("cybersentinel.integrations.abuseipdb")

_cache = TTLCache(default_ttl=config.ABUSEIPDB_CACHE_TTL)

# AbuseIPDB category ID -> human-readable name mapping.
# See https://www.abuseipdb.com/categories
_CATEGORY_NAMES: dict[int, str] = {
    3: "Fraud",
    4: "DDoS",
    5: "FTP Brute-Force",
    10: "Web App Attack",
    11: "Email Spam",
    14: "Port Scan",
    15: "Hacking",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploit",
    21: "SQL Injection",
    22: "Spoofing",
    23: "Open Proxy",
}


class AbuseIPDBClient:
    """Async client for the AbuseIPDB API — IP reputation and abuse checking."""

    BASE_URL = config.ABUSEIPDB_BASE_URL

    def __init__(self) -> None:
        self._api_key: str = config.ABUSEIPDB_API_KEY
        self._enabled: bool = bool(self._api_key)

        # Diagnostic logging — always at WARNING so it reaches the console.
        # This is intentional: AbuseIPDB init only happens a few times per
        # session, and knowing the client state is critical for debugging.
        if self._enabled:
            masked = self._api_key[:4] + "..." + self._api_key[-4:] if len(self._api_key) > 8 else "****"
            logger.warning(
                "AbuseIPDB client ENABLED — key loaded (%s), base_url=%s",
                masked, self.BASE_URL,
            )
        else:
            logger.warning(
                "AbuseIPDB client DISABLED — ABUSEIPDB_API_KEY is empty. "
                "Set it in .env to enable IP reputation checks."
            )

    @property
    def enabled(self) -> bool:
        """Return True if the client has a valid API key."""
        return self._enabled

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    async def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """Check a single IP address against AbuseIPDB.

        Args:
            ip: The IP address to check.
            max_age_days: How far back (in days) to look for reports.
                Defaults to 90.

        Returns:
            A dict with the ``data`` payload from AbuseIPDB (keys such as
            ``ipAddress``, ``abuseConfidenceScore``, ``totalReports``,
            ``countryCode``, ``domain``, ``isp``, etc.), or an empty dict
            when the client is disabled or the request fails.
        """
        if not self._enabled:
            logger.warning("AbuseIPDB check_ip(%s) skipped — client disabled", ip)
            return {}

        cache_key = f"abuseipdb:check:{ip}:{max_age_days}"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": "",
        }

        logger.warning(
            "AbuseIPDB check_ip: ip=%s max_age_days=%d",
            ip, max_age_days,
        )

        data = await self._get("/check", params=params, cache_key=cache_key)
        if data is None:
            return {}

        result = data.get("data", {})
        score = result.get("abuseConfidenceScore", 0)
        total = result.get("totalReports", 0)
        logger.warning(
            "AbuseIPDB check_ip(%s): confidence=%d%%, reports=%d, malicious=%s",
            ip, score, total, self.is_malicious(result),
        )
        return result

    async def check_ip_bulk(self, ips: list[str]) -> list[dict]:
        """Check multiple IP addresses against AbuseIPDB.

        Iterates ``check_ip`` for up to 10 IPs concurrently. IPs beyond the
        first 10 are silently dropped to stay within reasonable rate limits.

        Args:
            ips: A list of IP address strings.

        Returns:
            A list of result dicts (one per IP). Failed lookups are included
            as empty dicts to keep the list aligned with the input order.
            Returns an empty list when the client is disabled.
        """
        if not self._enabled:
            logger.warning("AbuseIPDB check_ip_bulk skipped — client disabled")
            return []

        if not ips:
            return []

        # Cap at 10 IPs to be respectful of rate limits.
        capped = ips[:10]
        if len(ips) > 10:
            logger.warning(
                "AbuseIPDB check_ip_bulk: %d IPs provided, capped to 10",
                len(ips),
            )

        logger.warning(
            "AbuseIPDB check_ip_bulk: checking %d IPs", len(capped),
        )

        tasks = [self.check_ip(ip) for ip in capped]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed: list[dict] = []
        for ip, result in zip(capped, results):
            if isinstance(result, Exception):
                logger.warning(
                    "AbuseIPDB check_ip_bulk: exception for %s — %s", ip, result,
                )
                processed.append({})
            else:
                processed.append(result)

        logger.warning(
            "AbuseIPDB check_ip_bulk: completed %d/%d lookups",
            sum(1 for r in processed if r), len(capped),
        )
        return processed

    @staticmethod
    def is_malicious(ip_data: dict) -> bool:
        """Determine whether an IP should be considered malicious.

        Args:
            ip_data: The ``data`` dict returned by ``check_ip`` (must contain
                an ``abuseConfidenceScore`` key).

        Returns:
            ``True`` if the abuse confidence score meets or exceeds the
            configured threshold (``config.ABUSEIPDB_CONFIDENCE_THRESHOLD``).
        """
        score = ip_data.get("abuseConfidenceScore", 0)
        return score >= config.ABUSEIPDB_CONFIDENCE_THRESHOLD

    @staticmethod
    def get_abuse_category_name(category_id: int) -> str:
        """Map an AbuseIPDB category ID to its human-readable name.

        Args:
            category_id: The numeric category ID from AbuseIPDB.

        Returns:
            The category name string, or ``"Unknown (ID)"`` for unmapped IDs.
        """
        return _CATEGORY_NAMES.get(category_id, f"Unknown ({category_id})")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get(
        self,
        endpoint: str,
        params: dict,
        cache_key: Optional[str] = None,
    ) -> Optional[dict]:
        """Make an authenticated GET request to the AbuseIPDB API.

        Handles caching, HTTP error classification (401 disables the client,
        429 is transient, 5xx is logged), and network-level exceptions.

        Args:
            endpoint: API path relative to BASE_URL (e.g. ``"/check"``).
            params: Query parameters to include.
            cache_key: Optional cache key. When provided, the response is
                cached and subsequent calls return the cached value until TTL
                expiry.

        Returns:
            The parsed JSON dict on success, or ``None`` on any failure.
        """
        # Check cache first.
        if cache_key:
            cached = _cache.get(cache_key)
            if cached is not None:
                logger.warning(
                    "AbuseIPDB cache hit for %s", cache_key,
                )
                return cached

        url = f"{self.BASE_URL}{endpoint}"
        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(url, params=params, headers=headers)

            logger.warning(
                "AbuseIPDB %s responded: HTTP %d (%d bytes)",
                endpoint, resp.status_code, len(resp.content),
            )

            if resp.status_code == 200:
                data = resp.json()
                if cache_key:
                    _cache.set(cache_key, data)
                return data

            if resp.status_code == 401:
                logger.warning(
                    "AbuseIPDB API: INVALID API KEY (401). Check "
                    "ABUSEIPDB_API_KEY in .env. Response: %s",
                    resp.text[:300],
                )
                self._enabled = False
                return None

            if resp.status_code == 429:
                logger.warning(
                    "AbuseIPDB API: rate limited (429). Daily limit may be "
                    "exhausted (free tier: %d/day). Response: %s",
                    config.ABUSEIPDB_RATE_LIMIT, resp.text[:200],
                )
                return None

            if resp.status_code >= 500:
                logger.warning(
                    "AbuseIPDB API server error: HTTP %d — %s",
                    resp.status_code, resp.text[:300],
                )
                return None

            # Any other non-200 status.
            logger.warning(
                "AbuseIPDB API error: HTTP %d — %s",
                resp.status_code, resp.text[:300],
            )
            return None

        except httpx.HTTPError as exc:
            logger.warning("AbuseIPDB HTTP connection error: %s", exc)
            return None
