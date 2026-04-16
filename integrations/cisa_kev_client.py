"""CISA KEV feed client — downloads, caches, and queries the KEV catalog."""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx

import config

logger = logging.getLogger("cybersentinel.integrations.kev")


class CISAKEVClient:
    """Async client for the CISA Known Exploited Vulnerabilities JSON feed."""

    FEED_URL = config.CISA_KEV_URL
    CACHE_FILE = Path(config.CACHE_DIR) / "kev_catalog.json"
    CACHE_META_FILE = Path(config.CACHE_DIR) / "kev_catalog_meta.json"

    def __init__(self) -> None:
        self._catalog: list[dict] = []
        self._cve_set: set[str] = set()
        self._cve_map: dict[str, dict] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_catalog(self) -> list[dict]:
        """Download and cache the full KEV catalog, respecting TTL."""
        if self._loaded:
            return self._catalog

        # Check cache first
        cached = self._load_cache()
        if cached is not None:
            self._ingest(cached)
            return self._catalog

        # Fetch fresh
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                logger.info("Fetching CISA KEV catalog from %s", self.FEED_URL)
                resp = await client.get(self.FEED_URL)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch CISA KEV catalog: %s", exc)
            # Try stale cache as fallback
            stale = self._load_cache(ignore_ttl=True)
            if stale is not None:
                logger.warning("Using stale KEV cache as fallback")
                self._ingest(stale)
                return self._catalog
            return []

        vulns = data.get("vulnerabilities", [])
        self._save_cache(vulns)
        self._ingest(vulns)
        return self._catalog

    def is_exploited(self, cve_id: str) -> bool:
        """O(1) check whether a CVE is in the KEV catalog."""
        return cve_id.upper() in self._cve_set

    def get_kev_entry(self, cve_id: str) -> Optional[dict]:
        """Return the full KEV entry for a CVE, or None."""
        return self._cve_map.get(cve_id.upper())

    def get_recent_additions(self, days: int = 30) -> list[dict]:
        """Return KEV entries added in the last N days, sorted newest first."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        recent: list[dict] = []
        for entry in self._catalog:
            date_str = entry.get("dateAdded", "")
            try:
                added = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if added >= cutoff:
                    recent.append(entry)
            except ValueError:
                continue
        recent.sort(key=lambda e: e.get("dateAdded", ""), reverse=True)
        return recent

    def get_ransomware_associated(self) -> list[dict]:
        """Return entries where knownRansomwareCampaignUse == 'Known'."""
        return [
            e for e in self._catalog
            if e.get("knownRansomwareCampaignUse") == "Known"
        ]

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _load_cache(self, ignore_ttl: bool = False) -> Optional[list[dict]]:
        """Load KEV catalog from local cache if fresh."""
        if not self.CACHE_FILE.exists() or not self.CACHE_META_FILE.exists():
            return None

        try:
            with open(self.CACHE_META_FILE, "r") as f:
                meta = json.load(f)
            cached_at = meta.get("cached_at", 0)
            if not ignore_ttl and (time.time() - cached_at) > config.CISA_KEV_CACHE_TTL:
                logger.debug("KEV cache expired (age=%ds)", int(time.time() - cached_at))
                return None
            with open(self.CACHE_FILE, "r") as f:
                data = json.load(f)
            logger.info("Loaded KEV catalog from cache (%d entries)", len(data))
            return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read KEV cache: %s", exc)
            return None

    def _save_cache(self, vulns: list[dict]) -> None:
        """Persist KEV catalog and metadata to local cache."""
        os.makedirs(self.CACHE_FILE.parent, exist_ok=True)
        try:
            with open(self.CACHE_FILE, "w") as f:
                json.dump(vulns, f)
            with open(self.CACHE_META_FILE, "w") as f:
                json.dump({"cached_at": time.time(), "count": len(vulns)}, f)
            logger.info("Cached KEV catalog (%d entries)", len(vulns))
        except OSError as exc:
            logger.warning("Failed to write KEV cache: %s", exc)

    def _ingest(self, vulns: list[dict]) -> None:
        """Build internal lookup structures from the catalog."""
        self._catalog = vulns
        self._cve_set = {v.get("cveID", "").upper() for v in vulns}
        self._cve_map = {v.get("cveID", "").upper(): v for v in vulns}
        self._loaded = True
        logger.debug("Ingested %d KEV entries", len(vulns))
