"""Abstract base class that all CyberSentinel agents inherit from."""

import asyncio
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from typing import Optional

import config
from core.agent_result import AgentResult
from core.mock_llm import MockLLM

logger = logging.getLogger("cybersentinel.agent")


# ---------------------------------------------------------------------------
# Module-level cost calculation helper (used by base_agent and cost_tracker)
# ---------------------------------------------------------------------------

def _calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate API cost in USD based on Anthropic pricing (as of 2026).

    Pricing per 1M tokens:
    - claude-opus-4-6:   $5.00 input,  $25.00 output
    - claude-sonnet-4-6: $3.00 input,  $15.00 output
    - claude-haiku-4-5:  $1.00 input,   $5.00 output
    """
    pricing: dict[str, tuple[float, float]] = {
        "claude-opus-4-6":   (5.00, 25.00),
        "claude-sonnet-4-6": (3.00, 15.00),
        "claude-haiku-4-5":  (1.00,  5.00),
    }
    input_price, output_price = pricing.get(model, (3.00, 15.00))
    return (input_tokens * input_price + output_tokens * output_price) / 1_000_000


# ---------------------------------------------------------------------------
# BaseAgent
# ---------------------------------------------------------------------------

class BaseAgent(ABC):
    """Base class providing LLM access, timing, cost tracking, and logging to all agents."""

    name: str = "base_agent"
    description: str = ""
    capabilities: list[str] = []
    model: str = config.SUBAGENT_MODEL

    def __init__(self) -> None:
        self._client: Optional[object] = None
        # Last LLM call token usage — populated by _call_llm() every call.
        self._last_usage: dict = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
        }

    async def execute(self, task: dict) -> AgentResult:
        """Run the agent with automatic timing, logging, and error handling.

        Also auto-populates ``result.tokens_used_detail`` from ``self._last_usage``
        after ``run()`` returns.
        """
        logger.info("Agent '%s' starting | task keys: %s", self.name, list(task.keys()))
        start = time.perf_counter_ns()
        try:
            result = await self.run(task)
            elapsed_ms = int((time.perf_counter_ns() - start) / 1_000_000)
            result.execution_time_ms = elapsed_ms
            # Capture token usage from the last LLM call on this agent
            result.tokens_used_detail = dict(self._last_usage)
            logger.info(
                "Agent '%s' completed | status=%s findings=%d time=%dms cost=$%.4f",
                self.name,
                result.status,
                result.finding_count(),
                elapsed_ms,
                self._last_usage.get("cost_usd", 0.0),
            )
            return result
        except Exception as exc:
            elapsed_ms = int((time.perf_counter_ns() - start) / 1_000_000)
            logger.error("Agent '%s' failed: %s", self.name, exc, exc_info=True)
            return AgentResult(
                agent_name=self.name,
                status="error",
                execution_time_ms=elapsed_ms,
                error=str(exc),
                summary=f"Agent {self.name} encountered an error: {exc}",
            )

    @abstractmethod
    async def run(self, task: dict) -> AgentResult:
        """Implement the agent's core logic. Must return an AgentResult."""
        ...

    # ------------------------------------------------------------------
    # LLM call — mock or real
    # ------------------------------------------------------------------

    async def _call_llm(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.1,
    ) -> str:
        """Call the LLM — mock or real based on ``config.USE_MOCK_LLM``.

        Always returns a string. Never raises — returns error JSON on failure.
        Updates ``self._last_usage`` with token counts and cost for each call.
        """
        if config.USE_MOCK_LLM:
            response = await MockLLM.generate(self.name, prompt)
            self._last_usage = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
            return response

        # ---- Real Anthropic API call ----
        import anthropic  # late import — only needed in live mode

        client = anthropic.AsyncAnthropic(api_key=config.ANTHROPIC_API_KEY)

        kwargs: dict = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        last_error: Optional[Exception] = None

        for attempt in range(config.LLM_MAX_RETRIES):
            try:
                response = await client.messages.create(**kwargs)

                # Track token usage
                usage = response.usage
                cost = _calculate_cost(self.model, usage.input_tokens, usage.output_tokens)
                self._last_usage = {
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "cost_usd": cost,
                }

                # Warn if above configured threshold
                if (
                    config.COST_TRACKING_ENABLED
                    and cost > config.COST_WARNING_THRESHOLD_USD
                ):
                    logger.warning(
                        "LLM cost exceeded threshold: $%.4f > $%.2f",
                        cost,
                        config.COST_WARNING_THRESHOLD_USD,
                    )

                logger.warning(
                    "LLM call: agent=%s model=%s in=%d out=%d cost=$%.4f",
                    self.name,
                    self.model,
                    usage.input_tokens,
                    usage.output_tokens,
                    cost,
                )

                return response.content[0].text

            except anthropic.RateLimitError:
                wait = config.LLM_RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "Rate limit hit for agent '%s', waiting %.1fs (attempt %d/%d)",
                    self.name,
                    wait,
                    attempt + 1,
                    config.LLM_MAX_RETRIES,
                )
                await asyncio.sleep(wait)

            except anthropic.APIError as exc:
                last_error = exc
                logger.error(
                    "Anthropic API error for agent '%s' (attempt %d): %s",
                    self.name,
                    attempt + 1,
                    exc,
                )
                if attempt < config.LLM_MAX_RETRIES - 1:
                    await asyncio.sleep(config.LLM_RETRY_BASE_DELAY)

        # All retries exhausted
        self._last_usage = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
        error_msg = str(last_error) if last_error else "Max retries exceeded"
        return json.dumps({"error": error_msg, "findings": []})

    # ------------------------------------------------------------------
    # JSON parse helper — strips markdown fences if the LLM adds them
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_llm_json(text: str) -> "list | dict":
        """Parse LLM JSON response, stripping markdown code fences if present.

        The LLM occasionally wraps its JSON in ```json ... ``` even when
        instructed not to.  This method normalises the response before parsing.

        Raises ``json.JSONDecodeError`` if the text cannot be parsed.
        """
        text = text.strip()
        if text.startswith("```"):
            # Strip opening fence (```json or just ```)
            text = re.sub(r"^```(?:json)?\n?", "", text)
            # Strip closing fence
            text = re.sub(r"\n?```$", "", text.rstrip())
        return json.loads(text)
