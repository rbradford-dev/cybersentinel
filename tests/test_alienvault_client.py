"""Unit tests for the AlienVault OTX client."""

import pytest

import config
from integrations.alienvault_client import AlienVaultClient, _cache

# ---------------------------------------------------------------------------
# Sample AlienVault OTX API responses
# ---------------------------------------------------------------------------

SAMPLE_IP_GENERAL = {
    "indicator": "198.51.100.23",
    "pulse_info": {"count": 5, "pulses": [{"name": "Malware C2"}]},
    "reputation": 50,
    "country_code": "RU",
    "asn": "AS12345",
}

SAMPLE_IP_MALWARE = {
    "data": [
        {"hash": "abc123", "detections": {"avast": "Win32:Malware-gen"}},
        {"hash": "def456", "detections": {"kaspersky": "Trojan.Generic"}},
    ]
}

SAMPLE_DOMAIN_GENERAL = {
    "indicator": "evil.example.com",
    "pulse_info": {"count": 3, "pulses": [{"name": "Phishing Campaign"}]},
    "whois": "registered 2024-01-01",
}

SAMPLE_PULSES_SEARCH = {
    "results": [
        {"name": "APT29 Infrastructure", "id": "pulse-1", "created": "2024-10-01"},
        {"name": "Healthcare Targeting", "id": "pulse-2", "created": "2024-09-15"},
    ]
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable_client():
    """Temporarily set an API key so the client is enabled during tests."""
    original = config.OTX_API_KEY
    config.OTX_API_KEY = "test-otx-key-for-unit-tests"
    yield
    config.OTX_API_KEY = original


@pytest.fixture
def otx_client() -> AlienVaultClient:
    # Clear the module-level TTL cache before each test so cached results
    # from a prior test don't mask HTTP calls in error-path tests.
    _cache.clear()
    return AlienVaultClient()


# ---------------------------------------------------------------------------
# AlienVaultClient tests
# ---------------------------------------------------------------------------


class TestAlienVaultClient:
    """Tests for AlienVaultClient enrichment methods."""

    @pytest.mark.asyncio
    async def test_get_ip_reputation(self, httpx_mock, otx_client):
        """Test that get_ip_reputation returns a dict with expected keys."""
        httpx_mock.add_response(json=SAMPLE_IP_GENERAL)

        result = await otx_client.get_ip_reputation("198.51.100.23")

        assert isinstance(result, dict)
        assert result["indicator"] == "198.51.100.23"
        assert result["reputation"] == 50
        assert result["pulse_info"]["count"] == 5
        assert result["country_code"] == "RU"
        assert result["asn"] == "AS12345"

    @pytest.mark.asyncio
    async def test_get_ip_malware(self, httpx_mock, otx_client):
        """Test that get_ip_malware returns a list of malware samples."""
        httpx_mock.add_response(json=SAMPLE_IP_MALWARE)

        result = await otx_client.get_ip_malware("198.51.100.23")

        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["hash"] == "abc123"
        assert result[1]["detections"]["kaspersky"] == "Trojan.Generic"

    @pytest.mark.asyncio
    async def test_get_domain_reputation(self, httpx_mock, otx_client):
        """Test that get_domain_reputation returns a dict with expected keys."""
        httpx_mock.add_response(json=SAMPLE_DOMAIN_GENERAL)

        result = await otx_client.get_domain_reputation("evil.example.com")

        assert isinstance(result, dict)
        assert result["indicator"] == "evil.example.com"
        assert result["pulse_info"]["count"] == 3
        assert result["whois"] == "registered 2024-01-01"

    @pytest.mark.asyncio
    async def test_search_pulses(self, httpx_mock, otx_client):
        """Test that search_pulses returns a list of pulse dicts."""
        httpx_mock.add_response(json=SAMPLE_PULSES_SEARCH)

        result = await otx_client.search_pulses("APT29")

        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["name"] == "APT29 Infrastructure"
        assert result[1]["id"] == "pulse-2"

    @pytest.mark.asyncio
    async def test_disabled_when_no_key(self):
        """Test that the client is disabled and returns empty when no key."""
        config.OTX_API_KEY = ""
        client = AlienVaultClient()
        assert not client.enabled

        assert await client.get_ip_reputation("198.51.100.23") == {}
        assert await client.get_ip_malware("198.51.100.23") == []
        assert await client.get_domain_reputation("evil.example.com") == {}
        assert await client.search_pulses("APT29") == []

    @pytest.mark.asyncio
    async def test_401_disables_client(self, httpx_mock, otx_client):
        """Test that a 401 response disables the client for future requests."""
        httpx_mock.add_response(status_code=401, text="Unauthorized")

        result = await otx_client.get_ip_reputation("198.51.100.23")

        assert result == {}
        assert not otx_client.enabled

    @pytest.mark.asyncio
    async def test_429_rate_limit(self, httpx_mock, otx_client):
        """Test that a 429 returns empty but client stays enabled."""
        httpx_mock.add_response(status_code=429, text="Too Many Requests")

        result = await otx_client.get_ip_reputation("198.51.100.23")

        assert result == {}
        # Rate limiting is transient — client should remain enabled.
        assert otx_client.enabled

    @pytest.mark.asyncio
    async def test_500_server_error(self, httpx_mock, otx_client):
        """Test that a 500 server error returns empty gracefully."""
        httpx_mock.add_response(status_code=500, text="Internal Server Error")

        result = await otx_client.get_ip_reputation("198.51.100.23")

        assert result == {}
        # Server errors are transient — client should remain enabled.
        assert otx_client.enabled

    @pytest.mark.asyncio
    async def test_cache_hit(self, httpx_mock, otx_client):
        """Test that repeated calls use the cache (no second HTTP call)."""
        httpx_mock.add_response(json=SAMPLE_IP_GENERAL)

        # First call — hits the API.
        result1 = await otx_client.get_ip_reputation("198.51.100.23")
        assert result1["indicator"] == "198.51.100.23"

        # Second call — should use cache, no HTTP call.
        # (httpx_mock would fail if a second request was made
        #  because only one response was registered.)
        result2 = await otx_client.get_ip_reputation("198.51.100.23")
        assert result2["indicator"] == "198.51.100.23"
