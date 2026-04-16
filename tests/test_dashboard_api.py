"""Tests for the dashboard JSON API endpoints."""

import pytest
from fastapi.testclient import TestClient

from output.dashboard.app import create_app


@pytest.fixture(scope="module")
def client():
    """Create a TestClient for the dashboard app."""
    app = create_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /api/v1/stats
# ---------------------------------------------------------------------------


class TestStatsEndpoint:
    def test_stats_returns_200(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200

    def test_stats_has_required_keys(self, client):
        data = client.get("/api/v1/stats").json()
        for key in (
            "total_findings",
            "total_iocs",
            "total_cves",
            "total_sessions",
            "critical_findings",
            "high_findings",
            "last_scan",
        ):
            assert key in data, f"Missing key: {key}"

    def test_stats_values_are_integers(self, client):
        data = client.get("/api/v1/stats").json()
        for key in ("total_findings", "total_iocs", "total_cves", "total_sessions"):
            assert isinstance(data[key], int)


# ---------------------------------------------------------------------------
# GET /api/v1/findings
# ---------------------------------------------------------------------------


class TestFindingsEndpoint:
    def test_findings_returns_200(self, client):
        resp = client.get("/api/v1/findings")
        assert resp.status_code == 200

    def test_findings_has_required_keys(self, client):
        data = client.get("/api/v1/findings").json()
        assert "findings" in data
        assert "total" in data
        assert "page" in data
        assert isinstance(data["findings"], list)

    def test_findings_severity_filter(self, client):
        resp = client.get("/api/v1/findings?severity=critical")
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data

    def test_findings_pagination(self, client):
        resp = client.get("/api/v1/findings?limit=5&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 1


# ---------------------------------------------------------------------------
# GET /api/v1/findings/stats
# ---------------------------------------------------------------------------


class TestFindingsStatsEndpoint:
    def test_findings_stats_returns_200(self, client):
        resp = client.get("/api/v1/findings/stats")
        assert resp.status_code == 200

    def test_findings_stats_has_severity_keys(self, client):
        data = client.get("/api/v1/findings/stats").json()
        for key in ("critical", "high", "medium", "low", "info", "total"):
            assert key in data


# ---------------------------------------------------------------------------
# GET /api/v1/iocs
# ---------------------------------------------------------------------------


class TestIOCsEndpoint:
    def test_iocs_returns_200(self, client):
        resp = client.get("/api/v1/iocs")
        assert resp.status_code == 200

    def test_iocs_has_required_keys(self, client):
        data = client.get("/api/v1/iocs").json()
        assert "iocs" in data
        assert "total" in data
        assert isinstance(data["iocs"], list)


# ---------------------------------------------------------------------------
# GET /api/v1/cves
# ---------------------------------------------------------------------------


class TestCVEsEndpoint:
    def test_cves_returns_200(self, client):
        resp = client.get("/api/v1/cves")
        assert resp.status_code == 200

    def test_cves_has_required_keys(self, client):
        data = client.get("/api/v1/cves").json()
        assert "cves" in data
        assert "total" in data


# ---------------------------------------------------------------------------
# GET /api/v1/agents/status
# ---------------------------------------------------------------------------


class TestAgentsStatusEndpoint:
    def test_agents_status_returns_200(self, client):
        resp = client.get("/api/v1/agents/status")
        assert resp.status_code == 200

    def test_agents_status_has_agents_list(self, client):
        data = client.get("/api/v1/agents/status").json()
        assert "agents" in data
        agents = data["agents"]
        assert isinstance(agents, list)
        assert len(agents) == 4  # vuln, threat_intel, log_analysis, report

    def test_agent_entry_schema(self, client):
        data = client.get("/api/v1/agents/status").json()
        agent = data["agents"][0]
        for key in ("name", "description", "capabilities", "model", "enabled"):
            assert key in agent, f"Agent missing key: {key}"


# ---------------------------------------------------------------------------
# GET /api/v1/sessions
# ---------------------------------------------------------------------------


class TestSessionsEndpoint:
    def test_sessions_returns_200(self, client):
        resp = client.get("/api/v1/sessions")
        assert resp.status_code == 200

    def test_sessions_has_list(self, client):
        data = client.get("/api/v1/sessions").json()
        assert "sessions" in data
        assert isinstance(data["sessions"], list)


# ---------------------------------------------------------------------------
# GET /api/v1/integrations/status
# ---------------------------------------------------------------------------


class TestIntegrationsEndpoint:
    def test_integrations_returns_200(self, client):
        resp = client.get("/api/v1/integrations/status")
        assert resp.status_code == 200

    def test_integrations_has_all_sources(self, client):
        data = client.get("/api/v1/integrations/status").json()
        for key in ("nvd", "cisa_kev", "exa", "otx", "abuseipdb", "anthropic"):
            assert key in data, f"Missing integration: {key}"
            assert isinstance(data[key], bool)

    def test_cisa_kev_always_enabled(self, client):
        data = client.get("/api/v1/integrations/status").json()
        assert data["cisa_kev"] is True


# ---------------------------------------------------------------------------
# POST /api/v1/query
# ---------------------------------------------------------------------------


class TestQueryEndpoint:
    def test_query_returns_200(self, client):
        resp = client.post(
            "/api/v1/query",
            json={"query": "CVE-2024-38094", "type": "cve_lookup"},
        )
        assert resp.status_code == 200

    def test_query_returns_session_id(self, client):
        data = client.post(
            "/api/v1/query",
            json={"query": "Check IP 198.51.100.23", "type": "ip_check"},
        ).json()
        assert "session_id" in data
        assert "status" in data
        assert data["status"] == "queued"
        assert len(data["session_id"]) > 0

    def test_query_requires_body(self, client):
        resp = client.post("/api/v1/query")
        assert resp.status_code == 422  # validation error
