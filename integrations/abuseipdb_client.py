"""AbuseIPDB client — checks IP address abuse reports.

Phase 2 placeholder. Will query AbuseIPDB for IP reputation data including
abuse confidence scores, report counts, and geographic information.
"""


class AbuseIPDBClient:
    """AbuseIPDB API client for IP reputation checks."""

    async def check_ip(self, ip: str) -> dict:
        """Check IP against AbuseIPDB."""
        raise NotImplementedError("AbuseIPDBClient is planned for Phase 2.")
