"""Shared context / state across agent calls within a single session."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from core.agent_result import AgentResult


@dataclass
class SessionContext:
    """Holds shared state for a single orchestrator session."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    original_input: Optional[str] = None
    intent: Optional[str] = None
    agent_results: list[AgentResult] = field(default_factory=list)
    conversation: list[dict] = field(default_factory=list)
    entities: dict = field(default_factory=dict)

    def add_user_message(self, content: str) -> None:
        """Record a user message in the conversation history."""
        self.conversation.append(
            {
                "role": "user",
                "content": content,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def add_assistant_message(self, content: str, agent_name: Optional[str] = None) -> None:
        """Record an assistant / agent message in the conversation history."""
        self.conversation.append(
            {
                "role": "assistant",
                "content": content,
                "agent_name": agent_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def add_result(self, result: AgentResult) -> None:
        """Store an agent result and append a summary to the conversation."""
        self.agent_results.append(result)
        self.add_assistant_message(result.summary, agent_name=result.agent_name)

    def total_findings(self) -> int:
        """Return the combined count of findings across all agent results."""
        return sum(r.finding_count() for r in self.agent_results)

    def all_findings(self) -> list[dict]:
        """Return a flat list of all findings from all agents."""
        findings: list[dict] = []
        for result in self.agent_results:
            findings.extend(result.findings)
        return findings
