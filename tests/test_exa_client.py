"""Unit tests for the Exa web search client."""

import pytest
from unittest.mock import patch

import config
from integrations.exa_client import ExaClient, ExaSearchResult, _cache

# ---------------------------------------------------------------------------
# Sample Exa API responses
# ---------------------------------------------------------------------------

SAMPLE_SEARCH_RESPONSE = {
    "results": [
        {
            "title": "CVE-2024-38094: SharePoint RCE Analysis and Mitigation",
            "url": "https://example.com/cve-2024-38094-analysis",
            "publishedDate": "2024-10-20T12:00:00.000Z",
            "author": "Security Research Team",
            "score": 0.92,
            "highlights": [
                "CVE-2024-38094 is a critical deserialization vulnerability in Microsoft "
                "SharePoint Server that allows authenticated attackers to execute arbitrary "
                "code. The vulnerability has been actively exploited in the wild since "
                "October 2024.",
            ],
        },
        {
            "title": "Microsoft SharePoint Server Patch Tuesday October 2024",
            "url": "https://example.com/sharepoint-patch-oct-2024",
            "publishedDate": "2024-10-08T00:00:00.000Z",
            "author": None,
            "score": 0.85,
            "highlights": [
                "Microsoft released security updates for SharePoint Server addressing "
                "CVE-2024-38094. Organizations should apply KB5002606 immediately.",
            ],
        },
    ]
}

SAMPLE_CONTENTS_RESPONSE = {
    "results": [
        {
            "title": "CVE-2024-38094 Full Advisory",
            "url": "https://example.com/advisory",
            "score": 0.95,
            "highlights": ["Full technical details of the vulnerability."],
        }
    ]
}

SAMPLE_EMPTY_RESPONSE = {"results": []}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable_exa():
    """Temporarily set an API key so the client is enabled during tests."""
    original = config.EXA_API_KEY
    config.EXA_API_KEY = "test-api-key-for-unit-tests"
    yield
    config.EXA_API_KEY = original


@pytest.fixture
def exa_client() -> ExaClient:
    # Clear the module-level TTL cache before each test so cached results
    # from a prior test don't mask HTTP calls in error-path tests.
    _cache.clear()
    return ExaClient()


# ---------------------------------------------------------------------------
# ExaSearchResult tests
# ---------------------------------------------------------------------------


class TestExaSearchResult:
    """Tests for the ExaSearchResult data class."""

    def test_from_dict(self):
        """Test that a result is constructed from a raw dict."""
        raw = SAMPLE_SEARCH_RESPONSE["results"][0]
        result = ExaSearchResult(raw)
        assert result.title == "CVE-2024-38094: SharePoint RCE Analysis and Mitigation"
        assert result.url == "https://example.com/cve-2024-38094-analysis"
        assert result.score == 0.92
        assert len(result.highlights) == 1

    def test_to_dict(self):
        """Test serialization back to a dict."""
        raw = SAMPLE_SEARCH_RESPONSE["results"][0]
        result = ExaSearchResult(raw)
        d = result.to_dict()
        assert d["title"] == raw["title"]
        assert d["url"] == raw["url"]
        assert d["score"] == raw["score"]
        assert "highlights" in d

    def test_missing_fields_default(self):
        """Test that missing fields get safe defaults."""
        result = ExaSearchResult({})
        assert result.title == ""
        assert result.url == ""
        assert result.score == 0.0
        assert result.highlights == []
        assert result.text is None


# ---------------------------------------------------------------------------
# ExaClient tests
# ---------------------------------------------------------------------------


class TestExaClient:
    """Tests for the ExaClient search methods."""

    @pytest.mark.asyncio
    async def test_search_cve_returns_results(self, httpx_mock, exa_client):
        """Test that search_cve returns parsed results."""
        httpx_mock.add_response(json=SAMPLE_SEARCH_RESPONSE)

        results = await exa_client.search_cve("CVE-2024-38094")

        assert len(results) == 2
        assert results[0].title == "CVE-2024-38094: SharePoint RCE Analysis and Mitigation"
        assert results[0].score == 0.92

    @pytest.mark.asyncio
    async def test_search_cve_empty(self, httpx_mock, exa_client):
        """Test that an empty result set returns an empty list."""
        httpx_mock.add_response(json=SAMPLE_EMPTY_RESPONSE)

        results = await exa_client.search_cve("CVE-9999-99999")
        assert results == []

    @pytest.mark.asyncio
    async def test_search_threat_intel(self, httpx_mock, exa_client):
        """Test threat intelligence search."""
        httpx_mock.add_response(json=SAMPLE_SEARCH_RESPONSE)

        results = await exa_client.search_threat_intel("APT29 healthcare")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_search_security_advisory(self, httpx_mock, exa_client):
        """Test vendor advisory search."""
        httpx_mock.add_response(json=SAMPLE_SEARCH_RESPONSE)

        results = await exa_client.search_security_advisory("Microsoft", "SharePoint")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_search_exploit(self, httpx_mock, exa_client):
        """Test exploit/PoC search with domain filters."""
        httpx_mock.add_response(json=SAMPLE_SEARCH_RESPONSE)

        results = await exa_client.search_exploit("CVE-2024-38094")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_get_contents(self, httpx_mock, exa_client):
        """Test content retrieval from known URLs."""
        httpx_mock.add_response(json=SAMPLE_CONTENTS_RESPONSE)

        results = await exa_client.get_contents(["https://example.com/advisory"])
        assert len(results) == 1
        assert results[0].title == "CVE-2024-38094 Full Advisory"

    @pytest.mark.asyncio
    async def test_disabled_when_no_api_key(self):
        """Test that the client gracefully returns empty when disabled."""
        config.EXA_API_KEY = ""
        client = ExaClient()
        assert not client.enabled

        results = await client.search_cve("CVE-2024-38094")
        assert results == []

    @pytest.mark.asyncio
    async def test_api_error_returns_empty(self, httpx_mock, exa_client):
        """Test that API errors return empty lists, not exceptions."""
        httpx_mock.add_response(status_code=500, text="Internal Server Error")

        results = await exa_client.search_cve("CVE-2024-38094")
        assert results == []

    @pytest.mark.asyncio
    async def test_401_disables_client(self, httpx_mock, exa_client):
        """Test that an invalid API key response disables further requests."""
        httpx_mock.add_response(status_code=401, text="Unauthorized")

        results = await exa_client.search_cve("CVE-2024-38094")
        assert results == []
        assert not exa_client.enabled

    @pytest.mark.asyncio
    async def test_429_rate_limit(self, httpx_mock, exa_client):
        """Test that rate-limit response returns empty gracefully."""
        httpx_mock.add_response(status_code=429, text="Too Many Requests")

        results = await exa_client.search_cve("CVE-2024-38094")
        assert results == []
        # Should still be enabled (rate limit is transient)
        assert exa_client.enabled

    @pytest.mark.asyncio
    async def test_cache_hit(self, httpx_mock, exa_client):
        """Test that repeated searches use the cache (no second HTTP call)."""
        httpx_mock.add_response(json=SAMPLE_SEARCH_RESPONSE)

        # First call — hits the API
        results1 = await exa_client.search_cve("CVE-2024-38094")
        assert len(results1) == 2

        # Second call — should use cache, no HTTP call
        # (httpx_mock would fail if a second request was made
        #  because only one response was registered)
        results2 = await exa_client.search_cve("CVE-2024-38094")
        assert len(results2) == 2
