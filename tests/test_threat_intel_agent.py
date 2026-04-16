"""Unit tests for the Threat Intelligence Agent."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

import config
from agents.threat_intel_agent import ThreatIntelAgent
from core.agent_result import AgentResult

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_ABUSEIPDB_RESPONSE = {
    "ipAddress": "198.51.100.23",
    "abuseConfidenceScore": 85,
    "totalReports": 150,
    "countryCode": "RU",
    "isp": "Evil ISP",
    "domain": "evil.example.com",
    "usageType": "Data Center/Web Hosting/Transit",
}

SAMPLE_OTX_IP_REPUTATION = {
    "pulse_info": {
        "count": 5,
        "pulses": [{"name": "Malware C2 Servers", "id": "abc123"}],
    },
    "reputation": 50,
    "country_code": "RU",
    "asn": "AS12345",
}

SAMPLE_OTX_IP_MALWARE = [
    {"hash": "abc123def456", "detections": {"avast": "Win32:Malware-gen"}},
]

SAMPLE_OTX_DOMAIN_REPUTATION = {
    "pulse_info": {
        "count": 7,
        "pulses": [
            {"name": "Phishing Infrastructure", "id": "domain_pulse_1"},
            {"name": "Healthcare Targeting Campaign", "id": "domain_pulse_2"},
        ],
    },
    "whois": "Registrar: Shady Registrar Inc.",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _mock_config():
    original = config.USE_MOCK_LLM
    config.USE_MOCK_LLM = True
    yield
    config.USE_MOCK_LLM = original


@pytest.fixture
def agent() -> ThreatIntelAgent:
    return ThreatIntelAgent()


def _make_mock_clients(
    abuse_data=None,
    otx_ip_data=None,
    otx_malware_data=None,
    otx_domain_data=None,
):
    """Create mock AbuseIPDB and AlienVault clients with configurable returns."""
    mock_abuseipdb = AsyncMock()
    mock_abuseipdb.check_ip = AsyncMock(
        return_value=abuse_data if abuse_data is not None else SAMPLE_ABUSEIPDB_RESPONSE,
    )

    mock_otx = AsyncMock()
    mock_otx.get_ip_reputation = AsyncMock(
        return_value=otx_ip_data if otx_ip_data is not None else SAMPLE_OTX_IP_REPUTATION,
    )
    mock_otx.get_ip_malware = AsyncMock(
        return_value=otx_malware_data if otx_malware_data is not None else SAMPLE_OTX_IP_MALWARE,
    )
    mock_otx.get_domain_reputation = AsyncMock(
        return_value=otx_domain_data if otx_domain_data is not None else SAMPLE_OTX_DOMAIN_REPUTATION,
    )

    return mock_abuseipdb, mock_otx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ip_enrichment_success(agent):
    """Single IP with both AbuseIPDB and OTX returning data produces a finding."""
    mock_abuseipdb, mock_otx = _make_mock_clients()

    with patch("integrations.abuseipdb_client.AbuseIPDBClient", return_value=mock_abuseipdb), \
         patch("integrations.alienvault_client.AlienVaultClient", return_value=mock_otx):
        result = await agent.execute({"ip": "198.51.100.23"})

    assert isinstance(result, AgentResult)
    assert result.status == "success"
    assert result.agent_name == "threat_intel_agent"
    assert result.finding_count() >= 1

    # Verify the finding references the enriched IP
    finding = result.findings[0]
    assert finding["affected_asset"] == "198.51.100.23"
    assert finding["finding_type"] == "threat_intel"
    assert len(finding["evidence"]) > 0


@pytest.mark.asyncio
async def test_ip_enrichment_malicious_severity(agent):
    """IP with abuse confidence score >= 80 should be classified as critical."""
    abuse_data = {**SAMPLE_ABUSEIPDB_RESPONSE, "abuseConfidenceScore": 85}
    mock_abuseipdb, mock_otx = _make_mock_clients(abuse_data=abuse_data)

    with patch("integrations.abuseipdb_client.AbuseIPDBClient", return_value=mock_abuseipdb), \
         patch("integrations.alienvault_client.AlienVaultClient", return_value=mock_otx):
        result = await agent.execute({"ip": "198.51.100.23"})

    assert result.status == "success"
    finding = result.findings[0]
    assert finding["severity"] == "critical"


@pytest.mark.asyncio
async def test_ip_enrichment_low_severity(agent):
    """IP with abuse confidence score < 25 and low pulse count should be low severity."""
    abuse_data = {**SAMPLE_ABUSEIPDB_RESPONSE, "abuseConfidenceScore": 10, "totalReports": 2}
    otx_data = {
        "pulse_info": {"count": 1, "pulses": []},
        "reputation": 5,
        "country_code": "US",
        "asn": "AS99999",
    }
    mock_abuseipdb, mock_otx = _make_mock_clients(
        abuse_data=abuse_data,
        otx_ip_data=otx_data,
    )

    with patch("integrations.abuseipdb_client.AbuseIPDBClient", return_value=mock_abuseipdb), \
         patch("integrations.alienvault_client.AlienVaultClient", return_value=mock_otx):
        result = await agent.execute({"ip": "192.0.2.50"})

    assert result.status == "success"
    finding = result.findings[0]
    assert finding["severity"] == "low"


@pytest.mark.asyncio
async def test_multiple_ips(agent):
    """Passing two IPs should produce two findings."""
    mock_abuseipdb, mock_otx = _make_mock_clients()

    with patch("integrations.abuseipdb_client.AbuseIPDBClient", return_value=mock_abuseipdb), \
         patch("integrations.alienvault_client.AlienVaultClient", return_value=mock_otx):
        result = await agent.execute({
            "ipv4_addresses": ["198.51.100.23", "203.0.113.45"],
        })

    assert result.status == "success"
    assert result.finding_count() == 2

    assets = [f["affected_asset"] for f in result.findings]
    assert "198.51.100.23" in assets
    assert "203.0.113.45" in assets


@pytest.mark.asyncio
async def test_no_iocs_returns_no_data(agent):
    """Empty task with no IPs or domains should return status='no_data'."""
    mock_abuseipdb, mock_otx = _make_mock_clients()

    with patch("integrations.abuseipdb_client.AbuseIPDBClient", return_value=mock_abuseipdb), \
         patch("integrations.alienvault_client.AlienVaultClient", return_value=mock_otx):
        result = await agent.execute({})

    assert result.status == "no_data"
    assert result.finding_count() == 0
    assert "No IOCs" in result.summary


@pytest.mark.asyncio
async def test_disabled_clients_still_work(agent):
    """Agent should not crash when both clients return empty data (disabled)."""
    mock_abuseipdb, mock_otx = _make_mock_clients(
        abuse_data={},
        otx_ip_data={},
        otx_malware_data=[],
    )

    with patch("integrations.abuseipdb_client.AbuseIPDBClient", return_value=mock_abuseipdb), \
         patch("integrations.alienvault_client.AlienVaultClient", return_value=mock_otx):
        result = await agent.execute({"ip": "10.0.0.1"})

    assert isinstance(result, AgentResult)
    # Agent should still return success — it produced a finding even with empty data
    assert result.status == "success"
    assert result.finding_count() >= 1


@pytest.mark.asyncio
async def test_data_sources_tracked(agent):
    """data_sources should include 'AbuseIPDB' and 'AlienVault_OTX' when clients return data."""
    mock_abuseipdb, mock_otx = _make_mock_clients()

    with patch("integrations.abuseipdb_client.AbuseIPDBClient", return_value=mock_abuseipdb), \
         patch("integrations.alienvault_client.AlienVaultClient", return_value=mock_otx):
        result = await agent.execute({"ip": "198.51.100.23"})

    assert result.status == "success"
    assert "AbuseIPDB" in result.data_sources
    assert "AlienVault_OTX" in result.data_sources


@pytest.mark.asyncio
async def test_domain_enrichment(agent):
    """Passing a domain should call OTX domain reputation and produce a finding."""
    mock_abuseipdb, mock_otx = _make_mock_clients()

    with patch("integrations.abuseipdb_client.AbuseIPDBClient", return_value=mock_abuseipdb), \
         patch("integrations.alienvault_client.AlienVaultClient", return_value=mock_otx):
        result = await agent.execute({"domain": "evil.example.com"})

    assert result.status == "success"
    assert result.finding_count() >= 1

    finding = result.findings[0]
    assert finding["affected_asset"] == "evil.example.com"
    assert finding["finding_type"] == "threat_intel"

    # Verify OTX domain method was called
    mock_otx.get_domain_reputation.assert_called_once_with("evil.example.com")
    # AbuseIPDB check_ip should NOT have been called (no IP in task)
    mock_abuseipdb.check_ip.assert_not_called()


@pytest.mark.asyncio
async def test_finding_schema_completeness(agent):
    """Every finding returned should conform to the standard finding schema."""
    mock_abuseipdb, mock_otx = _make_mock_clients()

    with patch("integrations.abuseipdb_client.AbuseIPDBClient", return_value=mock_abuseipdb), \
         patch("integrations.alienvault_client.AlienVaultClient", return_value=mock_otx):
        result = await agent.execute({"ip": "198.51.100.23"})

    for finding in result.findings:
        assert "finding_id" in finding
        assert "finding_type" in finding
        assert "title" in finding
        assert "description" in finding
        assert "severity" in finding
        assert "confidence" in finding
        assert "affected_asset" in finding
        assert "evidence" in finding
        assert isinstance(finding["evidence"], list)
        assert "mitre_techniques" in finding
        assert isinstance(finding["mitre_techniques"], list)
        assert "is_kev" in finding
        assert "timestamp" in finding


@pytest.mark.asyncio
async def test_determine_severity_thresholds(agent):
    """Verify _determine_severity follows the documented threshold rules."""
    # critical: abuse >= 80 OR pulses >= 10
    assert agent._determine_severity(80, 0) == "critical"
    assert agent._determine_severity(0, 10) == "critical"
    assert agent._determine_severity(95, 15) == "critical"

    # high: abuse >= 50 OR pulses >= 5
    assert agent._determine_severity(50, 0) == "high"
    assert agent._determine_severity(0, 5) == "high"
    assert agent._determine_severity(79, 4) == "high"

    # medium: abuse >= 25 OR pulses >= 2
    assert agent._determine_severity(25, 0) == "medium"
    assert agent._determine_severity(0, 2) == "medium"
    assert agent._determine_severity(49, 1) == "medium"

    # low: everything below
    assert agent._determine_severity(0, 0) == "low"
    assert agent._determine_severity(24, 1) == "low"
    assert agent._determine_severity(10, 0) == "low"
