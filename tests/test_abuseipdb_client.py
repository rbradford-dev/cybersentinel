"""Unit tests for the AbuseIPDB IP reputation client."""

import pytest

import config
from integrations.abuseipdb_client import AbuseIPDBClient, _cache

# ---------------------------------------------------------------------------
# Sample AbuseIPDB API responses
# ---------------------------------------------------------------------------

SAMPLE_CHECK_RESPONSE = {
    "data": {
        "ipAddress": "198.51.100.23",
        "isPublic": True,
        "abuseConfidenceScore": 85,
        "countryCode": "RU",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Evil ISP LLC",
        "domain": "evil.example.com",
        "totalReports": 247,
        "numDistinctUsers": 89,
        "lastReportedAt": "2024-10-28T12:00:00+00:00",
    }
}

SAMPLE_CHECK_CLEAN = {
    "data": {
        "ipAddress": "8.8.8.8",
        "isPublic": True,
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "usageType": "Content Delivery Network",
        "isp": "Google LLC",
        "domain": "google.com",
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
    }
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable_client():
    """Temporarily set an API key so the client is enabled during tests."""
    original = config.ABUSEIPDB_API_KEY
    config.ABUSEIPDB_API_KEY = "test-abuseipdb-key-for-unit-tests"
    yield
    config.ABUSEIPDB_API_KEY = original


@pytest.fixture
def abuseipdb_client() -> AbuseIPDBClient:
    # Clear the module-level TTL cache before each test so cached results
    # from a prior test don't mask HTTP calls in error-path tests.
    _cache.clear()
    return AbuseIPDBClient()


# ---------------------------------------------------------------------------
# AbuseIPDBClient tests
# ---------------------------------------------------------------------------


class TestAbuseIPDBClient:
    """Tests for the AbuseIPDBClient methods."""

    @pytest.mark.asyncio
    async def test_check_ip_returns_data(self, httpx_mock, abuseipdb_client):
        """Test that check_ip returns the inner 'data' dict on success."""
        httpx_mock.add_response(json=SAMPLE_CHECK_RESPONSE)

        result = await abuseipdb_client.check_ip("198.51.100.23")

        assert result["ipAddress"] == "198.51.100.23"
        assert result["abuseConfidenceScore"] == 85
        assert result["countryCode"] == "RU"
        assert result["totalReports"] == 247
        assert result["isp"] == "Evil ISP LLC"

    @pytest.mark.asyncio
    async def test_check_ip_clean(self, httpx_mock, abuseipdb_client):
        """Test that a clean IP returns a low abuse score."""
        httpx_mock.add_response(json=SAMPLE_CHECK_CLEAN)

        result = await abuseipdb_client.check_ip("8.8.8.8")

        assert result["ipAddress"] == "8.8.8.8"
        assert result["abuseConfidenceScore"] == 0
        assert result["totalReports"] == 0
        assert result["lastReportedAt"] is None

    @pytest.mark.asyncio
    async def test_check_ip_empty_response(self, httpx_mock, abuseipdb_client):
        """Test that an empty/null API response returns an empty dict."""
        httpx_mock.add_response(json={"data": {}})

        result = await abuseipdb_client.check_ip("192.0.2.1")

        assert result == {}

    def test_is_malicious_true(self):
        """Test that a score of 85 (>= threshold 50) is malicious."""
        ip_data = SAMPLE_CHECK_RESPONSE["data"]
        assert AbuseIPDBClient.is_malicious(ip_data) is True

    def test_is_malicious_false(self):
        """Test that a score of 0 (< threshold 50) is not malicious."""
        ip_data = SAMPLE_CHECK_CLEAN["data"]
        assert AbuseIPDBClient.is_malicious(ip_data) is False

    def test_is_malicious_at_threshold(self):
        """Test that a score exactly at the threshold (50) is malicious."""
        ip_data = {"abuseConfidenceScore": 50}
        assert AbuseIPDBClient.is_malicious(ip_data) is True

    def test_get_abuse_category_name(self):
        """Test that known category IDs map to correct names."""
        assert AbuseIPDBClient.get_abuse_category_name(15) == "Hacking"
        assert AbuseIPDBClient.get_abuse_category_name(18) == "Brute-Force"
        assert AbuseIPDBClient.get_abuse_category_name(4) == "DDoS"
        assert AbuseIPDBClient.get_abuse_category_name(14) == "Port Scan"
        assert AbuseIPDBClient.get_abuse_category_name(21) == "SQL Injection"

    def test_get_abuse_category_unknown(self):
        """Test that an unknown category ID returns 'Unknown (ID)'."""
        assert AbuseIPDBClient.get_abuse_category_name(99) == "Unknown (99)"
        assert AbuseIPDBClient.get_abuse_category_name(0) == "Unknown (0)"

    @pytest.mark.asyncio
    async def test_disabled_when_no_key(self):
        """Test that the client is disabled and returns empty when no key."""
        config.ABUSEIPDB_API_KEY = ""
        client = AbuseIPDBClient()
        assert not client.enabled

        result = await client.check_ip("198.51.100.23")
        assert result == {}

    @pytest.mark.asyncio
    async def test_401_disables_client(self, httpx_mock, abuseipdb_client):
        """Test that a 401 response disables the client."""
        httpx_mock.add_response(status_code=401, text="Unauthorized")

        result = await abuseipdb_client.check_ip("198.51.100.23")

        assert result == {}
        assert not abuseipdb_client.enabled

    @pytest.mark.asyncio
    async def test_429_rate_limit(self, httpx_mock, abuseipdb_client):
        """Test that a 429 response returns empty but keeps client enabled."""
        httpx_mock.add_response(status_code=429, text="Too Many Requests")

        result = await abuseipdb_client.check_ip("198.51.100.23")

        assert result == {}
        # Rate limit is transient — client should still be enabled.
        assert abuseipdb_client.enabled

    @pytest.mark.asyncio
    async def test_cache_hit(self, httpx_mock, abuseipdb_client):
        """Test that repeated lookups use the cache (no second HTTP call)."""
        httpx_mock.add_response(json=SAMPLE_CHECK_RESPONSE)

        # First call — hits the API.
        result1 = await abuseipdb_client.check_ip("198.51.100.23")
        assert result1["ipAddress"] == "198.51.100.23"

        # Second call — should use cache, no HTTP call.
        # (httpx_mock would fail if a second request was made
        #  because only one response was registered.)
        result2 = await abuseipdb_client.check_ip("198.51.100.23")
        assert result2["ipAddress"] == "198.51.100.23"
