"""Unit tests for the NVD API client."""

import pytest
import httpx
import pytest_asyncio

from integrations.nvd_client import NVDClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-38094",
                "published": "2024-07-09T17:15:00.000",
                "lastModified": "2024-10-10T12:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Microsoft SharePoint Remote Code Execution Vulnerability",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                            },
                        }
                    ]
                },
                "references": [
                    {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38094"}
                ],
                "configurations": [],
            }
        }
    ],
}


@pytest.fixture
def nvd_client() -> NVDClient:
    return NVDClient()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_cve_success(httpx_mock, nvd_client):
    """Test that a successful CVE fetch returns normalized data."""
    httpx_mock.add_response(json=SAMPLE_NVD_RESPONSE)

    result = await nvd_client.get_cve("CVE-2024-38094")

    assert result is not None
    assert result["id"] == "CVE-2024-38094"
    assert result["cve_id"] == "CVE-2024-38094"
    assert len(result["descriptions"]) == 1
    assert result["descriptions"][0]["lang"] == "en"

    # Verify CVSS metrics are present
    metrics = result["metrics"]
    assert "cvssMetricV31" in metrics
    cvss = metrics["cvssMetricV31"][0]["cvssData"]
    assert cvss["baseScore"] == 8.8
    assert cvss["baseSeverity"] == "HIGH"
    assert cvss["attackVector"] == "NETWORK"


@pytest.mark.asyncio
async def test_get_cve_not_found(httpx_mock, nvd_client):
    """Test that a 404 returns None."""
    httpx_mock.add_response(status_code=404)

    result = await nvd_client.get_cve("CVE-9999-99999")
    assert result is None


@pytest.mark.asyncio
async def test_get_cve_rate_limit_retry(httpx_mock, nvd_client):
    """Test that 429 triggers retry and eventual success."""
    # First call returns 429, second returns success
    httpx_mock.add_response(status_code=429)
    httpx_mock.add_response(json=SAMPLE_NVD_RESPONSE)

    result = await nvd_client.get_cve("CVE-2024-38094")

    assert result is not None
    assert result["id"] == "CVE-2024-38094"


@pytest.mark.asyncio
async def test_cvss_extraction(httpx_mock, nvd_client):
    """Test CVSS extraction from a complex nested response."""
    httpx_mock.add_response(json=SAMPLE_NVD_RESPONSE)

    result = await nvd_client.get_cve("CVE-2024-38094")
    assert result is not None

    cvss = result["metrics"]["cvssMetricV31"][0]["cvssData"]
    assert cvss["baseScore"] == 8.8
    assert cvss["attackComplexity"] == "LOW"
    assert cvss["privilegesRequired"] == "LOW"
    assert cvss["confidentialityImpact"] == "HIGH"
    assert cvss["integrityImpact"] == "HIGH"
    assert cvss["availabilityImpact"] == "HIGH"


@pytest.mark.asyncio
async def test_search_cves(httpx_mock, nvd_client):
    """Test keyword-based CVE search returns a list."""
    httpx_mock.add_response(json=SAMPLE_NVD_RESPONSE)

    results = await nvd_client.search_cves(keyword="SharePoint")
    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["id"] == "CVE-2024-38094"


@pytest.mark.asyncio
async def test_get_cve_empty_response(httpx_mock, nvd_client):
    """Test handling of an empty vulnerability list."""
    httpx_mock.add_response(json={"vulnerabilities": [], "totalResults": 0})

    result = await nvd_client.get_cve("CVE-2024-00000")
    assert result is None
