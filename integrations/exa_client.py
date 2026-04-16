"""Exa web search client — enriches findings with real-time security intelligence.

Uses the Exa REST API (https://api.exa.ai) via httpx for async consistency
with the rest of the CyberSentinel integration layer. Provides security-focused
search methods for CVE write-ups, vendor advisories, threat actor intel, and
general OSINT enrichment.
"""

import json
import logging
from typing import Optional

import httpx

import config
from utils.cache import TTLCache

logger = logging.getLogger("cybersentinel.integrations.exa")

_cache = TTLCache(default_ttl=config.EXA_CACHE_TTL)


class ExaSearchResult:
    """A single result from an Exa search."""

    def __init__(self, data: dict) -> None:
        self.title: str = data.get("title", "")
        self.url: str = data.get("url", "")
        self.published_date: Optional[str] = data.get("publishedDate")
        self.author: Optional[str] = data.get("author")
        self.score: float = data.get("score", 0.0)
        self.highlights: list[str] = data.get("highlights", [])
        self.text: Optional[str] = data.get("text")

    def to_dict(self) -> dict:
        """Serialize to a dict for storage / JSON export."""
        return {
            "title": self.title,
            "url": self.url,
            "published_date": self.published_date,
            "author": self.author,
            "score": self.score,
            "highlights": self.highlights,
        }


class ExaClient:
    """Async client for the Exa search API — security-focused web intelligence."""

    BASE_URL = config.EXA_BASE_URL

    def __init__(self) -> None:
        self._api_key: str = config.EXA_API_KEY
        self._enabled: bool = bool(self._api_key)

        # Diagnostic logging — always at WARNING so it reaches the console.
        # This is intentional: Exa init only happens a few times per session,
        # and knowing the client state is critical for debugging.
        if self._enabled:
            masked = self._api_key[:4] + "..." + self._api_key[-4:] if len(self._api_key) > 8 else "****"
            logger.warning(
                "Exa client ENABLED — key loaded (%s), base_url=%s",
                masked, self.BASE_URL,
            )
        else:
            logger.warning(
                "Exa client DISABLED — EXA_API_KEY is empty. "
                "Set it in .env to enable web search enrichment."
            )

    @property
    def enabled(self) -> bool:
        """Return True if the client has a valid API key."""
        return self._enabled

    # ------------------------------------------------------------------
    # Security-focused search methods
    # ------------------------------------------------------------------

    async def search_cve(
        self, cve_id: str, num_results: Optional[int] = None
    ) -> list[ExaSearchResult]:
        """Search for write-ups, advisories, and PoC info about a specific CVE."""
        if not self._enabled:
            logger.warning("Exa search_cve(%s) skipped — client disabled", cve_id)
            return []
        query = (
            f"{cve_id} vulnerability analysis exploit advisory remediation"
        )
        return await self._search(
            query=query,
            num_results=num_results or config.EXA_NUM_RESULTS,
            cache_key=f"exa:cve:{cve_id}",
        )

    async def search_threat_intel(
        self, query: str, num_results: Optional[int] = None
    ) -> list[ExaSearchResult]:
        """Search for threat intelligence — actors, campaigns, TTPs."""
        if not self._enabled:
            return []
        enriched_query = f"{query} threat intelligence cybersecurity"
        return await self._search(
            query=enriched_query,
            num_results=num_results or config.EXA_NUM_RESULTS,
            category="news",
            cache_key=f"exa:threat:{query[:60]}",
        )

    async def search_security_advisory(
        self, vendor: str, product: str, num_results: Optional[int] = None
    ) -> list[ExaSearchResult]:
        """Search for vendor-specific security advisories."""
        if not self._enabled:
            return []
        query = f"{vendor} {product} security advisory patch update"
        return await self._search(
            query=query,
            num_results=num_results or config.EXA_NUM_RESULTS,
            cache_key=f"exa:advisory:{vendor}:{product}",
        )

    async def search_exploit(
        self, cve_id: str, num_results: Optional[int] = None
    ) -> list[ExaSearchResult]:
        """Search for public exploit code and proof-of-concept details."""
        if not self._enabled:
            return []
        query = f"{cve_id} exploit proof of concept PoC"
        return await self._search(
            query=query,
            num_results=num_results or min(config.EXA_NUM_RESULTS, 3),
            include_domains=["github.com", "exploit-db.com", "packetstormsecurity.com"],
            cache_key=f"exa:exploit:{cve_id}",
        )

    async def get_contents(self, urls: list[str]) -> list[ExaSearchResult]:
        """Retrieve content from known URLs via Exa /contents endpoint."""
        if not self._enabled or not urls:
            return []
        # /contents uses highlights at the top level, NOT nested under "contents"
        payload: dict = {
            "urls": urls[:10],
            "highlights": {"max_characters": config.EXA_HIGHLIGHTS_MAX_CHARS},
        }
        data = await self._post("/contents", payload)
        if data is None:
            return []
        return [ExaSearchResult(r) for r in data.get("results", [])]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _search(
        self,
        query: str,
        num_results: int = 5,
        search_type: Optional[str] = None,
        category: Optional[str] = None,
        include_domains: Optional[list[str]] = None,
        exclude_domains: Optional[list[str]] = None,
        cache_key: Optional[str] = None,
    ) -> list[ExaSearchResult]:
        """Execute a search against the Exa /search endpoint."""
        # Check cache
        if cache_key:
            cached = _cache.get(cache_key)
            if cached is not None:
                logger.warning(
                    "Exa cache hit for %s — returning %d cached results",
                    cache_key, len(cached),
                )
                return cached

        # Build payload matching the Exa REST API snake_case convention.
        # Highlights are nested under "contents" for the /search endpoint.
        payload: dict = {
            "query": query,
            "type": search_type or config.EXA_SEARCH_TYPE,
            "num_results": num_results,
            "contents": {
                "highlights": {"max_characters": config.EXA_HIGHLIGHTS_MAX_CHARS},
            },
        }
        if category:
            payload["category"] = category
        if include_domains:
            payload["includeDomains"] = include_domains
        if exclude_domains:
            payload["excludeDomains"] = exclude_domains

        logger.warning(
            "Exa search: query=%r type=%s num_results=%d",
            query[:80], payload["type"], num_results,
        )

        data = await self._post("/search", payload)
        if data is None:
            logger.warning("Exa search returned None (API error or empty response)")
            return []

        results = [ExaSearchResult(r) for r in data.get("results", [])]
        logger.warning(
            "Exa search: %d results for %r", len(results), query[:60],
        )

        if cache_key and results:
            _cache.set(cache_key, results)

        return results

    async def _post(self, endpoint: str, payload: dict) -> Optional[dict]:
        """Make an authenticated POST request to the Exa API."""
        url = f"{self.BASE_URL}{endpoint}"
        headers = {
            "x-api-key": self._api_key,
            "Content-Type": "application/json",
        }

        logger.debug(
            "Exa POST %s — payload: %s",
            endpoint, json.dumps(payload, default=str)[:500],
        )

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=payload, headers=headers)

            logger.warning(
                "Exa %s responded: HTTP %d (%d bytes)",
                endpoint, resp.status_code, len(resp.content),
            )

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code == 401:
                logger.warning(
                    "Exa API: INVALID API KEY (401). Check EXA_API_KEY in .env. "
                    "Response: %s", resp.text[:300],
                )
                self._enabled = False
                return None

            if resp.status_code == 429:
                logger.warning("Exa API: rate limited (429). Response: %s", resp.text[:200])
                return None

            logger.warning(
                "Exa API error: HTTP %d — %s", resp.status_code, resp.text[:300],
            )
            return None

        except httpx.HTTPError as exc:
            logger.warning("Exa HTTP connection error: %s", exc)
            return None
