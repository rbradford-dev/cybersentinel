"""Report generation agent — produces executive and technical reports.

Phase 2 placeholder. Will consume findings from all agents and generate
formatted PDF/HTML reports with executive summaries, technical details,
and remediation timelines.
"""

from core.agent_result import AgentResult
from core.base_agent import BaseAgent


class ReportAgent(BaseAgent):
    """Generates executive and technical security reports from findings."""

    name = "report_agent"
    description = "Automated security report generation"
    capabilities = ["executive_report", "technical_report", "compliance_report"]

    async def run(self, task: dict) -> AgentResult:
        """Planned for Phase 2."""
        raise NotImplementedError("ReportAgent is planned for Phase 2.")
