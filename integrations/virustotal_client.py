"""VirusTotal client — scans files, URLs, and IPs against VT database.

Phase 2 placeholder. Will query the VirusTotal API v3 for file hash lookups,
URL scans, IP reports, and domain reports with multi-engine detection results.
"""


class VirusTotalClient:
    """VirusTotal API v3 client."""

    async def check_hash(self, file_hash: str) -> dict:
        """Look up a file hash on VirusTotal."""
        raise NotImplementedError("VirusTotalClient is planned for Phase 2.")

    async def check_ip(self, ip: str) -> dict:
        """Check IP reputation on VirusTotal."""
        raise NotImplementedError("VirusTotalClient is planned for Phase 2.")
