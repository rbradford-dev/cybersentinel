"""Abstract base class that all CyberSentinel agents inherit from."""

import time
import logging
from abc import ABC, abstractmethod
from typing import Optional

import config
from core.agent_result import AgentResult
from core.mock_llm import MockLLM

logger = logging.getLogger("cybersentinel.agent")


class BaseAgent(ABC):
    """Base class providing LLM access, timing, and logging to all agents."""

    name: str = "base_agent"
    description: str = ""
    capabilities: list[str] = []
    model: str = config.SUBAGENT_MODEL

    def __init__(self) -> None:
        self._client: Optional[object] = None

    async def execute(self, task: dict) -> AgentResult:
        """Run the agent with automatic timing, logging, and error handling."""
        logger.info("Agent '%s' starting | task keys: %s", self.name, list(task.keys()))
        start = time.perf_counter_ns()
        try:
            result = await self.run(task)
            elapsed_ms = int((time.perf_counter_ns() - start) / 1_000_000)
            result.execution_time_ms = elapsed_ms
            logger.info(
                "Agent '%s' completed | status=%s findings=%d time=%dms",
                self.name,
                result.status,
                result.finding_count(),
                elapsed_ms,
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

    async def _call_llm(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Call the LLM — mock or real depending on config.USE_MOCK_LLM."""
        if config.USE_MOCK_LLM:
            return await MockLLM.generate(self.name, prompt)
        return await self._call_real_llm(prompt, system_prompt)

    async def _call_real_llm(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Call the real Anthropic API. Lazy-inits the client."""
        import anthropic

        if self._client is None:
            self._client = anthropic.AsyncAnthropic(api_key=config.ANTHROPIC_API_KEY)

        kwargs: dict = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        response = await self._client.messages.create(**kwargs)
        return response.content[0].text
