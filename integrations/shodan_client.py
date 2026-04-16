"""Shodan client — queries Shodan for exposed services and banners.

Phase 2 placeholder. Will query the Shodan API for host information including
open ports, services, banners, and known vulnerabilities on internet-facing assets.
"""


class ShodanClient:
    """Shodan API client for internet-facing asset discovery."""

    async def lookup_host(self, ip: str) -> dict:
        """Look up host details on Shodan."""
        raise NotImplementedError("ShodanClient is planned for Phase 2.")
