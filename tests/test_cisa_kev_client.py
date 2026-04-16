"""Unit tests for the CISA KEV client."""

import json
import pytest
from unittest.mock import patch
from pathlib import Path

from integrations.cisa_kev_client import CISAKEVClient

# ---------------------------------------------------------------------------
# Sample KEV catalog
# ---------------------------------------------------------------------------

SAMPLE_KEV_CATALOG = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2024.10.28",
    "dateReleased": "2024-10-28T00:00:00.000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-38094",
            "vendorProject": "Microsoft",
            "product": "SharePoint",
            "vulnerabilityName": "Microsoft SharePoint Deserialization Vulnerability",
            "dateAdded": "2024-10-22",
            "shortDescription": "Microsoft SharePoint contains a deserialization vulnerability.",
            "requiredAction": "Apply mitigations per vendor instructions or discontinue use.",
            "dueDate": "2024-11-12",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "CVE-2024-9999",
            "vendorProject": "TestVendor",
            "product": "TestProduct",
            "vulnerabilityName": "Test Vulnerability",
            "dateAdded": "2024-10-01",
            "shortDescription": "A test vulnerability.",
            "requiredAction": "Patch immediately.",
            "dueDate": "2024-10-22",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2023-00001",
            "vendorProject": "OldVendor",
            "product": "OldProduct",
            "vulnerabilityName": "Old Vulnerability",
            "dateAdded": "2023-01-15",
            "shortDescription": "An old vulnerability.",
            "requiredAction": "Patch or mitigate.",
            "dueDate": "2023-02-05",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


@pytest.fixture
def kev_client() -> CISAKEVClient:
    client = CISAKEVClient()
    # Pre-load catalog to avoid HTTP calls
    client._ingest(SAMPLE_KEV_CATALOG["vulnerabilities"])
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_catalog(httpx_mock, tmp_path):
    """Test that fetch_catalog downloads and ingests the catalog."""
    httpx_mock.add_response(json=SAMPLE_KEV_CATALOG)

    client = CISAKEVClient()
    # Use pytest's per-test tmp_path so no stale cache file from a prior
    # run can short-circuit the HTTP request and leave the mock unused.
    client.CACHE_FILE = tmp_path / "kev_catalog.json"
    client.CACHE_META_FILE = tmp_path / "kev_catalog_meta.json"

    catalog = await client.fetch_catalog()
    assert len(catalog) == 3
    assert client.is_exploited("CVE-2024-38094")


def test_is_exploited_true(kev_client):
    """Test that a known KEV entry returns True."""
    assert kev_client.is_exploited("CVE-2024-38094") is True


def test_is_exploited_false(kev_client):
    """Test that a non-KEV CVE returns False."""
    assert kev_client.is_exploited("CVE-2024-00000") is False


def test_is_exploited_case_insensitive(kev_client):
    """Test that lookup is case-insensitive."""
    assert kev_client.is_exploited("cve-2024-38094") is True


def test_get_kev_entry(kev_client):
    """Test that a full KEV entry is returned."""
    entry = kev_client.get_kev_entry("CVE-2024-38094")
    assert entry is not None
    assert entry["vendorProject"] == "Microsoft"
    assert entry["product"] == "SharePoint"
    assert entry["dueDate"] == "2024-11-12"


def test_get_kev_entry_missing(kev_client):
    """Test that a missing CVE returns None."""
    assert kev_client.get_kev_entry("CVE-2099-00000") is None


def test_get_recent_additions(kev_client):
    """Test that recent additions filters by date correctly."""
    # With a large enough window, all fixture entries should show up.
    # Window must cover dateAdded=2023-01-15 from today's date.
    recent = kev_client.get_recent_additions(days=365 * 5)
    cve_ids = [e["cveID"] for e in recent]
    assert "CVE-2024-38094" in cve_ids
    assert "CVE-2024-9999" in cve_ids
    assert "CVE-2023-00001" in cve_ids


def test_get_recent_additions_narrow_window(kev_client):
    """Test that a narrow window excludes old entries."""
    # 1 day window — should only include very recent entries
    recent = kev_client.get_recent_additions(days=1)
    # None of our sample data is from today
    assert len(recent) == 0


def test_get_ransomware_associated(kev_client):
    """Test filtering for ransomware-associated entries."""
    ransomware = kev_client.get_ransomware_associated()
    assert len(ransomware) == 1
    assert ransomware[0]["cveID"] == "CVE-2024-9999"
