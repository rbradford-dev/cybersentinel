"""Unit tests for the Report Agent."""

import json

import pytest
from unittest.mock import AsyncMock, patch

import config
from agents.report_agent import ReportAgent
from core.agent_result import AgentResult

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_FINDINGS = [
    {
        "finding_id": "f1",
        "finding_type": "vulnerability",
        "agent_name": "vulnerability_agent",
        "title": "CVE-2024-38094: Critical SharePoint RCE",
        "description": "Remote code execution vulnerability",
        "severity": "critical",
        "confidence": 0.9,
        "evidence": '["CVSS v3.1: 9.8"]',
        "mitre_techniques": '["T1190"]',
        "status": "open",
        "raw_data": "{}",
    },
    {
        "finding_id": "f2",
        "finding_type": "vulnerability",
        "agent_name": "vulnerability_agent",
        "title": "CVE-2024-12345: Medium SQLi",
        "description": "SQL injection in web app",
        "severity": "medium",
        "confidence": 0.7,
        "evidence": '["CVSS v3.1: 5.3"]',
        "mitre_techniques": '["T1190"]',
        "status": "open",
        "raw_data": "{}",
    },
]

SAMPLE_CVE_FINDINGS = [
    {
        "cve_id": "CVE-2024-38094",
        "cvss_score": 9.8,
        "severity": "critical",
        "is_kev": 1,
        "kev_due_date": "2024-11-12",
        "remediation": "Apply KB5002606",
        "status": "open",
    },
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def agent() -> ReportAgent:
    """Create a ReportAgent with mock LLM enabled."""
    config.USE_MOCK_LLM = True
    return ReportAgent()


@pytest.fixture
def mock_repo():
    """Create a mock Repository whose get_findings and get_cve_findings are async."""
    repo = AsyncMock()
    repo.get_findings = AsyncMock(return_value=SAMPLE_FINDINGS)
    repo.get_cve_findings = AsyncMock(return_value=SAMPLE_CVE_FINDINGS)
    return repo


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_executive_report_success(agent, mock_repo):
    """Default report type (executive) returns AgentResult with status='success'."""
    with patch("db.repository.Repository", return_value=mock_repo):
        result = await agent.execute({"report_type": "executive"})

    assert isinstance(result, AgentResult)
    assert result.status == "success"
    assert result.agent_name == "report_agent"


@pytest.mark.asyncio
async def test_technical_report_type(agent, mock_repo):
    """Passing report_type='technical' uses that type in the generated report."""
    with patch("db.repository.Repository", return_value=mock_repo):
        result = await agent.execute({"report_type": "technical"})

    assert result.status == "success"
    # The raw_data dict should reflect the report type that was requested
    assert result.raw_data is not None
    assert result.raw_data["report_type"] == "technical"


@pytest.mark.asyncio
async def test_compliance_report_type(agent, mock_repo):
    """Passing report_type='compliance' uses that type in the generated report."""
    with patch("db.repository.Repository", return_value=mock_repo):
        result = await agent.execute({"report_type": "compliance"})

    assert result.status == "success"
    assert result.raw_data is not None
    assert result.raw_data["report_type"] == "compliance"


@pytest.mark.asyncio
async def test_no_findings_returns_no_data(agent):
    """When both get_findings and get_cve_findings return empty, status is 'no_data'."""
    empty_repo = AsyncMock()
    empty_repo.get_findings = AsyncMock(return_value=[])
    empty_repo.get_cve_findings = AsyncMock(return_value=[])

    with patch("db.repository.Repository", return_value=empty_repo):
        result = await agent.execute({})

    assert result.status == "no_data"
    assert result.finding_count() == 0
    assert "No findings" in result.summary


@pytest.mark.asyncio
async def test_report_contains_findings(agent, mock_repo):
    """The raw_data on a successful report contains report structure keys."""
    with patch("db.repository.Repository", return_value=mock_repo):
        result = await agent.execute({"report_type": "executive"})

    assert result.raw_data is not None
    # The mock LLM returns a JSON dict that _parse_report extracts, then run()
    # adds report_type, generated_at, findings_analyzed, cve_findings_analyzed.
    assert "report_type" in result.raw_data
    assert "generated_at" in result.raw_data
    assert "findings_analyzed" in result.raw_data
    assert result.raw_data["findings_analyzed"] == len(SAMPLE_FINDINGS)
    assert result.raw_data["cve_findings_analyzed"] == len(SAMPLE_CVE_FINDINGS)


@pytest.mark.asyncio
async def test_report_finding_type(agent, mock_repo):
    """The single finding produced has finding_type='report' and severity='info'."""
    with patch("db.repository.Repository", return_value=mock_repo):
        result = await agent.execute({"report_type": "executive"})

    assert result.finding_count() == 1
    finding = result.findings[0]
    assert finding["finding_type"] == "report"
    assert finding["severity"] == "info"


@pytest.mark.asyncio
async def test_data_sources_includes_sqlite(agent, mock_repo):
    """Verify data_sources includes 'sqlite' (the database source)."""
    with patch("db.repository.Repository", return_value=mock_repo):
        result = await agent.execute({"report_type": "executive"})

    assert "sqlite" in result.data_sources


@pytest.mark.asyncio
async def test_invalid_report_type_defaults(agent, mock_repo):
    """An invalid report_type falls back to 'executive'."""
    with patch("db.repository.Repository", return_value=mock_repo):
        result = await agent.execute({"report_type": "invalid_type"})

    assert result.status == "success"
    assert result.raw_data is not None
    assert result.raw_data["report_type"] == "executive"


@pytest.mark.asyncio
async def test_report_summary_generated(agent, mock_repo):
    """The result summary is a non-empty string."""
    with patch("db.repository.Repository", return_value=mock_repo):
        result = await agent.execute({"report_type": "executive"})

    assert isinstance(result.summary, str)
    assert len(result.summary) > 0
    # The summary should mention the report type
    assert "Executive" in result.summary or "executive" in result.summary.lower()
