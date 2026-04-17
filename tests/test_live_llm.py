"""Tests for Phase 4 live LLM behavior.

All tests mock at the ``anthropic.AsyncAnthropic`` boundary so no real API
calls are made and no ANTHROPIC_API_KEY is required.

Test classes:
    TestLiveCallLLM      — core/base_agent._call_llm() in live mode
    TestCostCalculation  — _calculate_cost() arithmetic
    TestCostTracker      — CostTracker accumulation logic
    TestOrchestratorSSE  — session queue and event emission
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(text: str, input_tokens: int = 50, output_tokens: int = 100):
    """Build a minimal mock Anthropic message response."""
    response = MagicMock()
    response.content = [MagicMock(text=text)]
    response.usage = MagicMock(input_tokens=input_tokens, output_tokens=output_tokens)
    return response


# ---------------------------------------------------------------------------
# TestLiveCallLLM
# ---------------------------------------------------------------------------

class TestLiveCallLLM:
    """Tests for BaseAgent._call_llm() in live mode (USE_MOCK_LLM=False)."""

    @pytest.mark.asyncio
    async def test_live_call_returns_text(self, monkeypatch):
        """_call_llm() returns the content[0].text from the API response."""
        monkeypatch.setattr(config, "USE_MOCK_LLM", False)
        monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(config, "LLM_MAX_RETRIES", 1)

        expected_text = '[{"cve_id": "CVE-2024-1234", "severity": "critical"}]'
        mock_response = _make_response(expected_text)

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        with patch("anthropic.AsyncAnthropic", return_value=mock_client):
            from agents.vulnerability_agent import VulnerabilityAgent
            agent = VulnerabilityAgent()
            result = await agent._call_llm("test prompt", max_tokens=512)

        assert result == expected_text

    @pytest.mark.asyncio
    async def test_rate_limit_triggers_retry(self, monkeypatch):
        """RateLimitError on first attempt causes a retry that succeeds."""
        monkeypatch.setattr(config, "USE_MOCK_LLM", False)
        monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(config, "LLM_MAX_RETRIES", 3)
        monkeypatch.setattr(config, "LLM_RETRY_BASE_DELAY", 0.0)  # no real sleep in tests

        import anthropic

        expected_text = "retry succeeded"
        success_response = _make_response(expected_text)

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            side_effect=[
                anthropic.RateLimitError.__new__(anthropic.RateLimitError),  # first call fails
                success_response,  # second call succeeds
            ]
        )

        call_count = 0

        async def create_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise anthropic.RateLimitError(
                    message="rate_limit",
                    response=MagicMock(status_code=429, headers={}),
                    body={},
                )
            return success_response

        mock_client.messages.create = create_side_effect

        with patch("anthropic.AsyncAnthropic", return_value=mock_client):
            with patch("asyncio.sleep", new_callable=AsyncMock):  # skip real delays
                from agents.vulnerability_agent import VulnerabilityAgent
                agent = VulnerabilityAgent()
                result = await agent._call_llm("test prompt", max_tokens=512)

        assert result == expected_text
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_api_error_returns_error_json(self, monkeypatch):
        """APIError on every attempt returns JSON with 'error' key, never raises."""
        monkeypatch.setattr(config, "USE_MOCK_LLM", False)
        monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(config, "LLM_MAX_RETRIES", 2)
        monkeypatch.setattr(config, "LLM_RETRY_BASE_DELAY", 0.0)

        import anthropic

        async def always_fail(**kwargs):
            raise anthropic.APIError(
                message="server error",
                request=MagicMock(),
                body={},
            )

        mock_client = AsyncMock()
        mock_client.messages.create = always_fail

        with patch("anthropic.AsyncAnthropic", return_value=mock_client):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                from agents.vulnerability_agent import VulnerabilityAgent
                agent = VulnerabilityAgent()
                result = await agent._call_llm("test prompt", max_tokens=512)

        # Must not raise; must return a JSON-parseable error string
        parsed = json.loads(result)
        assert "error" in parsed

    @pytest.mark.asyncio
    async def test_token_usage_tracked(self, monkeypatch):
        """After a successful call, self._last_usage contains token counts and cost."""
        monkeypatch.setattr(config, "USE_MOCK_LLM", False)
        monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(config, "LLM_MAX_RETRIES", 1)

        mock_response = _make_response("ok", input_tokens=100, output_tokens=50)

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        with patch("anthropic.AsyncAnthropic", return_value=mock_client):
            from agents.vulnerability_agent import VulnerabilityAgent
            agent = VulnerabilityAgent()
            await agent._call_llm("test", max_tokens=512)

        assert agent._last_usage["input_tokens"] == 100
        assert agent._last_usage["output_tokens"] == 50
        assert agent._last_usage["cost_usd"] > 0.0

    @pytest.mark.asyncio
    async def test_mock_mode_no_api_call(self, monkeypatch):
        """With USE_MOCK_LLM=True, the Anthropic client is never instantiated."""
        monkeypatch.setattr(config, "USE_MOCK_LLM", True)

        with patch("anthropic.AsyncAnthropic") as mock_cls:
            from agents.vulnerability_agent import VulnerabilityAgent
            agent = VulnerabilityAgent()
            result = await agent._call_llm("CVE-2024-1234")

        mock_cls.assert_not_called()
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_parse_llm_json_strips_markdown_fences(self):
        """_parse_llm_json correctly strips ```json ... ``` fences."""
        from core.base_agent import BaseAgent

        fenced = '```json\n[{"key": "value"}]\n```'
        result = BaseAgent._parse_llm_json(fenced)
        assert isinstance(result, list)
        assert result[0]["key"] == "value"

    @pytest.mark.asyncio
    async def test_parse_llm_json_plain_json(self):
        """_parse_llm_json works on plain JSON without fences."""
        from core.base_agent import BaseAgent

        plain = '[{"severity": "critical", "cve_id": "CVE-2024-9999"}]'
        result = BaseAgent._parse_llm_json(plain)
        assert isinstance(result, list)
        assert result[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# TestCostCalculation
# ---------------------------------------------------------------------------

class TestCostCalculation:
    """Tests for _calculate_cost() arithmetic."""

    def test_sonnet_cost(self):
        from core.base_agent import _calculate_cost
        # 1M input + 1M output at sonnet pricing: $3.00 + $15.00 = $18.00
        cost = _calculate_cost("claude-sonnet-4-6", 1_000_000, 1_000_000)
        assert abs(cost - 18.0) < 0.001

    def test_opus_cost(self):
        from core.base_agent import _calculate_cost
        # 500K input + 250K output at opus: $2.50 + $6.25 = $8.75
        cost = _calculate_cost("claude-opus-4-6", 500_000, 250_000)
        assert abs(cost - 8.75) < 0.001

    def test_haiku_cost(self):
        from core.base_agent import _calculate_cost
        # 100K input + 50K output at haiku: $0.10 + $0.25 = $0.35
        cost = _calculate_cost("claude-haiku-4-5", 100_000, 50_000)
        assert abs(cost - 0.35) < 0.001

    def test_unknown_model_defaults_to_sonnet(self):
        from core.base_agent import _calculate_cost
        cost_sonnet = _calculate_cost("claude-sonnet-4-6", 1000, 500)
        cost_unknown = _calculate_cost("claude-unknown-model", 1000, 500)
        assert cost_sonnet == cost_unknown

    def test_zero_tokens(self):
        from core.base_agent import _calculate_cost
        assert _calculate_cost("claude-sonnet-4-6", 0, 0) == 0.0


# ---------------------------------------------------------------------------
# TestCostTracker
# ---------------------------------------------------------------------------

class TestCostTracker:
    """Tests for CostTracker accumulation and formatting."""

    @pytest.mark.asyncio
    async def test_record_and_get_session_total(self, monkeypatch):
        """record() accumulates correctly; get_session_total() returns right values."""
        monkeypatch.setattr(config, "COST_TRACKING_ENABLED", True)
        from core.cost_tracker import CostTracker
        ct = CostTracker()

        await ct.record("sess-1", "vulnerability_agent", "claude-sonnet-4-6", 100, 50, 0.001)
        await ct.record("sess-1", "threat_intel_agent", "claude-sonnet-4-6", 200, 80, 0.003)

        total = ct.get_session_total("sess-1")
        assert total["total_input_tokens"] == 300
        assert total["total_output_tokens"] == 130
        assert abs(total["total_cost_usd"] - 0.004) < 1e-9
        assert "vulnerability_agent" in total["cost_by_agent"]
        assert "threat_intel_agent" in total["cost_by_agent"]

    @pytest.mark.asyncio
    async def test_empty_session_returns_zeros(self):
        """get_session_total() returns zeroes for an unknown session_id."""
        from core.cost_tracker import CostTracker
        ct = CostTracker()
        total = ct.get_session_total("nonexistent-session")
        assert total["total_cost_usd"] == 0.0
        assert total["total_input_tokens"] == 0

    def test_format_cost(self):
        from core.cost_tracker import CostTracker
        assert CostTracker.format_cost(0.0) == "$0.0000"
        assert CostTracker.format_cost(0.0042) == "$0.0042"
        assert CostTracker.format_cost(0.00001) == "$0.000010"

    def test_is_mock_mode(self, monkeypatch):
        monkeypatch.setattr(config, "USE_MOCK_LLM", True)
        from core.cost_tracker import CostTracker
        assert CostTracker.is_mock_mode() is True

        monkeypatch.setattr(config, "USE_MOCK_LLM", False)
        assert CostTracker.is_mock_mode() is False


# ---------------------------------------------------------------------------
# TestOrchestratorSSE
# ---------------------------------------------------------------------------

class TestOrchestratorSSE:
    """Tests for orchestrator SSE event queue mechanics."""

    @pytest.mark.asyncio
    async def test_orchestrator_emits_routing_and_done_events(self, monkeypatch):
        """run() with a session_id populates the queue with routing and done events."""
        monkeypatch.setattr(config, "USE_MOCK_LLM", True)

        from core.orchestrator import (
            Orchestrator,
            get_session_queue,
            cleanup_session_queue,
            _session_queues,
        )

        session_id = "test-sse-session-001"

        # Pre-register the queue
        queue = get_session_queue(session_id)

        try:
            orch = Orchestrator()
            await orch.run("CVE-2024-38094", session_id=session_id)

            # Drain the queue into a list
            events = []
            while not queue.empty():
                events.append(await queue.get())

            event_types = [e.get("type") for e in events]

            assert "routing" in event_types, f"routing missing; got: {event_types}"
            assert "done" in event_types, f"done missing; got: {event_types}"
        finally:
            cleanup_session_queue(session_id)

    @pytest.mark.asyncio
    async def test_done_event_is_last(self, monkeypatch):
        """The 'done' event must be the last event emitted."""
        monkeypatch.setattr(config, "USE_MOCK_LLM", True)

        from core.orchestrator import (
            Orchestrator,
            get_session_queue,
            cleanup_session_queue,
        )

        session_id = "test-sse-session-002"
        queue = get_session_queue(session_id)

        try:
            orch = Orchestrator()
            await orch.run("Check IP 1.2.3.4", session_id=session_id)

            events = []
            while not queue.empty():
                events.append(await queue.get())

            assert events, "No events emitted"
            assert events[-1]["type"] == "done", (
                f"Last event was '{events[-1]['type']}', expected 'done'"
            )
        finally:
            cleanup_session_queue(session_id)

    @pytest.mark.asyncio
    async def test_no_session_id_emits_no_queue_events(self, monkeypatch):
        """Without a session_id, _emit_event is a no-op (no queue created)."""
        monkeypatch.setattr(config, "USE_MOCK_LLM", True)

        from core.orchestrator import Orchestrator, _session_queues

        initial_queue_count = len(_session_queues)

        orch = Orchestrator()
        await orch.run("CVE-2024-38094", session_id=None)

        # No new queue should have been created
        assert len(_session_queues) == initial_queue_count
