"""AlienVault OTX client — queries OTX for threat intelligence.

Phase 2 placeholder. Will provide IOC enrichment from AlienVault OTX pulses,
including IP reputation, domain lookups, and file hash analysis.
"""


class AlienVaultClient:
    """AlienVault OTX API client for IOC enrichment."""

    async def check_ip(self, ip: str) -> dict:
        """Check IP reputation against OTX."""
        raise NotImplementedError("AlienVaultClient is planned for Phase 2.")

    async def check_domain(self, domain: str) -> dict:
        """Check domain reputation against OTX."""
        raise NotImplementedError("AlienVaultClient is planned for Phase 2.")
