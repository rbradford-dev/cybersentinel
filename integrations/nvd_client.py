"""NVD REST API v2.0 client — fetches and normalizes CVE data."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

import config

logger = logging.getLogger("cybersentinel.integrations.nvd")

# Rate-limit semaphore: released every request, capped per window
_semaphore: Optional[asyncio.Semaphore] = None


def _get_semaphore() -> asyncio.Semaphore:
    """Lazily create the rate-limit semaphore."""
    global _semaphore
    if _semaphore is None:
        limit = config.NVD_RATE_LIMIT if config.NVD_API_KEY else 5
        _semaphore = asyncio.Semaphore(limit)
    return _semaphore


class NVDClient:
    """Async client for the NIST NVD CVE API v2.0."""

    BASE_URL = config.NVD_BASE_URL
    MAX_RETRIES = 3
    BACKOFF_BASE = 2  # seconds

    def __init__(self) -> None:
        self._headers: dict[str, str] = {}
        if config.NVD_API_KEY:
            self._headers["apiKey"] = config.NVD_API_KEY

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_cve(self, cve_id: str) -> Optional[dict]:
        """Fetch a single CVE by ID. Returns normalized CVE dict or None."""
        params = {"cveId": cve_id}
        data = await self._request(params)
        if data is None:
            return None

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        return self._normalize(vulns[0].get("cve", {}))

    async def search_cves(
        self,
        keyword: Optional[str] = None,
        cvss_min: Optional[float] = None,
        has_kev: bool = False,
        results_per_page: int = 20,
    ) -> list[dict]:
        """Search CVEs by keyword, CVSS threshold, and/or KEV membership."""
        params: dict = {"resultsPerPage": str(results_per_page)}
        if keyword:
            params["keywordSearch"] = keyword
        if cvss_min is not None:
            params["cvssV3Severity"] = self._severity_from_score(cvss_min)
        if has_kev:
            params["hasKev"] = ""

        data = await self._request(params)
        if data is None:
            return []

        results: list[dict] = []
        for item in data.get("vulnerabilities", []):
            cve = self._normalize(item.get("cve", {}))
            if cve:
                # Post-filter exact CVSS minimum if set
                if cvss_min is not None:
                    score = self._get_score(cve)
                    if score is not None and score < cvss_min:
                        continue
                results.append(cve)
        return results

    async def get_recent_cves(self, days: int = 7, cvss_min: float = 7.0) -> list[dict]:
        """Fetch CVEs published in the last N days above a CVSS threshold."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days)
        params: dict = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": "40",
        }

        sev = self._severity_from_score(cvss_min)
        if sev:
            params["cvssV3Severity"] = sev

        data = await self._request(params)
        if data is None:
            return []

        results: list[dict] = []
        for item in data.get("vulnerabilities", []):
            cve = self._normalize(item.get("cve", {}))
            if cve:
                score = self._get_score(cve)
                if score is not None and score >= cvss_min:
                    results.append(cve)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _request(self, params: dict) -> Optional[dict]:
        """Make a rate-limited GET request to the NVD API with retries."""
        sem = _get_semaphore()

        for attempt in range(1, self.MAX_RETRIES + 1):
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        logger.debug("NVD request: %s params=%s", self.BASE_URL, params)
                        resp = await client.get(
                            self.BASE_URL, params=params, headers=self._headers
                        )

                    if resp.status_code == 200:
                        return resp.json()

                    if resp.status_code == 404:
                        logger.info("NVD 404 for params=%s", params)
                        return None

                    if resp.status_code in (403, 429):
                        wait = self.BACKOFF_BASE ** attempt
                        logger.warning(
                            "NVD rate limit (%d), retrying in %ds (attempt %d/%d)",
                            resp.status_code,
                            wait,
                            attempt,
                            self.MAX_RETRIES,
                        )
                        await asyncio.sleep(wait)
                        continue

                    logger.error("NVD unexpected status %d: %s", resp.status_code, resp.text[:200])
                    return None

                except httpx.HTTPError as exc:
                    logger.error("NVD HTTP error: %s (attempt %d/%d)", exc, attempt, self.MAX_RETRIES)
                    if attempt < self.MAX_RETRIES:
                        await asyncio.sleep(self.BACKOFF_BASE ** attempt)
                    else:
                        return None

        return None

    @staticmethod
    def _normalize(cve_obj: dict) -> Optional[dict]:
        """Normalize a raw NVD CVE object into our internal format."""
        if not cve_obj:
            return None

        cve_id = cve_obj.get("id", "")
        descriptions = cve_obj.get("descriptions", [])
        metrics = cve_obj.get("metrics", {})

        return {
            "id": cve_id,
            "cve_id": cve_id,
            "descriptions": descriptions,
            "metrics": metrics,
            "configurations": cve_obj.get("configurations", []),
            "references": cve_obj.get("references", []),
            "vulnStatus": cve_obj.get("vulnStatus", ""),
            "published": cve_obj.get("published", ""),
            "lastModified": cve_obj.get("lastModified", ""),
        }

    @staticmethod
    def _get_score(cve: dict) -> Optional[float]:
        """Extract CVSS v3.1 base score from a normalized CVE."""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                return entries[0].get("cvssData", {}).get("baseScore")
        return None

    @staticmethod
    def _severity_from_score(score: float) -> Optional[str]:
        """Map a CVSS score to the NVD severity query parameter."""
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return None
