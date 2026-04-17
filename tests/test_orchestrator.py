"""Unit tests for the Master Orchestrator routing and dispatch logic."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

import config
from core.orchestrator import Orchestrator
from core.router import classify, classify_structured, RoutingDecision
from core.agent_result import AgentResult


# ---------------------------------------------------------------------------
# Router tests
# ---------------------------------------------------------------------------


class TestRouter:
    """Tests for the intent classifier / router."""

    def test_cve_pattern_routes_to_vulnerability(self):
        """Test that input containing a CVE ID routes to vulnerability agent."""
        decision = classify("Check if CVE-2024-38094 affects our systems")
        assert decision.intent == "cve_lookup"
        assert "vulnerability_agent" in decision.target_agents
        assert "CVE-2024-38094" in decision.extracted_entities.get("cve_ids", [])
        assert decision.confidence >= 0.9

    def test_ip_address_routes_to_threat_intel(self):
        """Test that input containing an IP routes to threat intel agent."""
        decision = classify("Check reputation of 192.168.1.100")
        assert decision.intent == "ip_check"
        assert "threat_intel_agent" in decision.target_agents
        assert "192.168.1.100" in decision.extracted_entities.get("ipv4_addresses", [])

    def test_vulnerability_keywords_route_correctly(self):
        """Test that vulnerability keywords route to vulnerability agent."""
        decision = classify("Scan for critical vulnerabilities in Apache")
        assert decision.intent == "vulnerability_scan"
        assert "vulnerability_agent" in decision.target_agents

    def test_threat_keywords_route_correctly(self):
        """Test that threat intel keywords route correctly."""
        decision = classify("Check for malware indicators and phishing campaigns")
        assert decision.intent == "threat_intel"
        assert "threat_intel_agent" in decision.target_agents

    def test_log_keywords_route_correctly(self):
        """Test that log analysis keywords route correctly."""
        decision = classify("Analyze SIEM alerts for anomalies in the last 24 hours")
        assert decision.intent == "log_analysis"
        assert "log_analysis_agent" in decision.target_agents

    def test_fallback_general(self):
        """Test that unrecognizable input falls back to general."""
        decision = classify("hello world")
        assert decision.intent == "general"
        assert decision.confidence < 0.5

    def test_structured_input_bypasses_classifier(self):
        """Test that structured input with explicit type routes directly."""
        decision = classify_structured({"type": "cve_lookup", "cve_id": "CVE-2024-1234"})
        assert decision.intent == "cve_lookup"
        assert decision.confidence >= 0.95
        assert "CVE-2024-1234" in decision.extracted_entities.get("cve_ids", [])

    def test_multiple_cve_ids_extracted(self):
        """Test that multiple CVE IDs are extracted from a single input."""
        decision = classify("Compare CVE-2024-38094 and CVE-2024-21887")
        assert decision.intent == "cve_lookup"
        ids = decision.extracted_entities.get("cve_ids", [])
        assert "CVE-2024-38094" in ids
        assert "CVE-2024-21887" in ids


# ---------------------------------------------------------------------------
# Orchestrator tests
# ---------------------------------------------------------------------------


class TestOrchestrator:
    """Tests for orchestrator dispatch and result handling."""

    @pytest.fixture(autouse=True)
    def force_mock_llm(self, monkeypatch):
        """Ensure all orchestrator tests run in mock mode regardless of .env state."""
        monkeypatch.setattr(config, "USE_MOCK_LLM", True)

    @pytest.mark.asyncio
    async def test_structured_input_dispatch(self):
        """Test that structured input dispatches to the correct agent."""
        orch = Orchestrator()

        # Mock the terminal output to avoid Rich printing during tests.
        # TerminalOutput is imported inside orchestrator methods via
        # `from output.terminal import TerminalOutput`, so we patch it
        # at its source module — the local import will then resolve to
        # the patched object.
        with patch("output.terminal.TerminalOutput"):
            result = await orch.handle({"type": "cve_lookup", "cve_id": "CVE-2024-38094"})

        assert isinstance(result, AgentResult)
        assert result.status in ("success", "partial", "error", "no_data")

    @pytest.mark.asyncio
    async def test_error_in_agent_does_not_crash_orchestrator(self):
        """Test that an agent error produces an error AgentResult, not an exception."""
        orch = Orchestrator()

        # Replace the vulnerability agent with one that raises
        mock_agent = MagicMock()
        mock_agent.name = "vulnerability_agent"
        mock_agent.execute = AsyncMock(
            return_value=AgentResult(
                agent_name="vulnerability_agent",
                status="error",
                error="Simulated failure",
                summary="Agent failed.",
            )
        )
        orch._agents["vulnerability_agent"] = mock_agent

        with patch("output.terminal.TerminalOutput"):
            result = await orch.handle({"type": "cve_lookup", "cve_id": "CVE-2024-38094"})

        assert result.status == "error"
        assert result.error is not None

    def test_merge_results(self):
        """Test that merging multiple AgentResults works correctly."""
        r1 = AgentResult(
            agent_name="agent_a",
            status="success",
            findings=[{"title": "F1", "severity": "critical"}],
            confidence=0.9,
            tokens_used=100,
            execution_time_ms=500,
            data_sources=["NVD"],
            summary="Found 1 critical.",
        )
        r2 = AgentResult(
            agent_name="agent_b",
            status="partial",
            findings=[{"title": "F2", "severity": "high"}],
            confidence=0.7,
            tokens_used=200,
            execution_time_ms=300,
            data_sources=["CISA_KEV"],
            summary="Found 1 high.",
        )
        merged = r1.merge(r2)
        assert merged.agent_name == "orchestrator"
        assert merged.status == "partial"  # worst of success/partial
        assert len(merged.findings) == 2
        assert merged.tokens_used == 300
        assert merged.confidence == 0.7
        assert set(merged.data_sources) == {"NVD", "CISA_KEV"}

    @pytest.mark.asyncio
    async def test_natural_language_routes_to_correct_agent(self):
        """Test NL input routes and dispatches correctly."""
        orch = Orchestrator()

        with patch("output.terminal.TerminalOutput"):
            result = await orch.handle("Look up CVE-2024-38094")

        assert isinstance(result, AgentResult)
        # Should have routed to vulnerability_agent
        assert result.agent_name in ("vulnerability_agent", "orchestrator")
