"""Tests for the dashboard HTML page routes and static assets."""

import pytest
from fastapi.testclient import TestClient

from output.dashboard.app import create_app


@pytest.fixture(scope="module")
def client():
    """Create a TestClient for the dashboard app."""
    app = create_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# HTML page routes
# ---------------------------------------------------------------------------


class TestPageRoutes:
    def test_dashboard_home(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "CyberSentinel" in resp.text

    def test_dashboard_home_contains_stats(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        # The dashboard page should contain stat card labels
        assert "FINDINGS" in resp.text.upper() or "findings" in resp.text.lower()

    def test_findings_page(self, client):
        resp = client.get("/findings")
        assert resp.status_code == 200
        assert "findings" in resp.text.lower()

    def test_iocs_page(self, client):
        resp = client.get("/iocs")
        assert resp.status_code == 200
        text_lower = resp.text.lower()
        assert "ioc" in text_lower or "indicator" in text_lower

    def test_cves_page(self, client):
        resp = client.get("/cves")
        assert resp.status_code == 200
        assert "CVE" in resp.text or "cve" in resp.text.lower()

    def test_run_page(self, client):
        resp = client.get("/run")
        assert resp.status_code == 200
        text_lower = resp.text.lower()
        assert "query" in text_lower or "run" in text_lower

    def test_agents_page(self, client):
        resp = client.get("/agents")
        assert resp.status_code == 200
        text_lower = resp.text.lower()
        assert "agent" in text_lower

    def test_agents_page_lists_all_agents(self, client):
        resp = client.get("/agents")
        assert resp.status_code == 200
        assert "vulnerability_agent" in resp.text
        assert "threat_intel_agent" in resp.text
        assert "log_analysis_agent" in resp.text
        assert "report_agent" in resp.text


# ---------------------------------------------------------------------------
# Static assets
# ---------------------------------------------------------------------------


class TestStaticAssets:
    def test_static_css(self, client):
        resp = client.get("/static/css/dashboard.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers.get("content-type", "")

    def test_css_has_severity_badges(self, client):
        resp = client.get("/static/css/dashboard.css")
        assert ".badge-critical" in resp.text
        assert ".badge-high" in resp.text

    def test_static_js(self, client):
        resp = client.get("/static/js/dashboard.js")
        assert resp.status_code == 200
        assert "javascript" in resp.headers.get("content-type", "")

    def test_js_has_chart_init(self, client):
        resp = client.get("/static/js/dashboard.js")
        assert "initSeverityChart" in resp.text

    def test_js_has_sse_handler(self, client):
        resp = client.get("/static/js/dashboard.js")
        assert "connectAgentStream" in resp.text


# ---------------------------------------------------------------------------
# Content-type and template rendering
# ---------------------------------------------------------------------------


class TestTemplateRendering:
    def test_html_pages_return_html_content_type(self, client):
        for path in ("/", "/findings", "/iocs", "/cves", "/run", "/agents"):
            resp = client.get(path)
            assert resp.status_code == 200, f"{path} returned {resp.status_code}"
            content_type = resp.headers.get("content-type", "")
            assert "text/html" in content_type, f"{path} content-type: {content_type}"

    def test_pages_contain_doctype(self, client):
        for path in ("/", "/findings", "/iocs", "/cves", "/run", "/agents"):
            resp = client.get(path)
            assert "<!DOCTYPE html>" in resp.text, f"{path} missing DOCTYPE"

    def test_pages_include_tailwind(self, client):
        resp = client.get("/")
        assert "tailwindcss" in resp.text

    def test_pages_include_htmx(self, client):
        resp = client.get("/")
        assert "htmx.org" in resp.text

    def test_nonexistent_page_returns_404(self, client):
        resp = client.get("/nonexistent-page-xyz")
        assert resp.status_code == 404
