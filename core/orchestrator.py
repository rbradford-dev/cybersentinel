"""Master Orchestrator — coordinates all agents, synthesizes results."""

import asyncio
import json
import logging
import time
from typing import Optional, Union

import config
from core.agent_result import AgentResult
from core.base_agent import BaseAgent, _calculate_cost
from core.context_manager import SessionContext
from core.mock_llm import MockLLM
from core.router import RoutingDecision, classify, classify_structured

logger = logging.getLogger("cybersentinel.orchestrator")

ORCHESTRATOR_SYSTEM_PROMPT = """\
You are CyberSentinel, a master security orchestrator for Cleveland Clinic's cybersecurity \
intelligence team. You coordinate specialized security agents and synthesize their findings \
into clear, actionable intelligence for the security operations team.

Your responsibilities:
1. Classify incoming security queries and route to appropriate specialist agents
2. Synthesize multi-agent findings into unified threat assessments
3. Prioritize findings by risk to healthcare operations and patient data
4. Generate clear remediation recommendations with specific timelines

Output format: Always respond in valid JSON matching the specified schema.
Security context: Healthcare environment — HIPAA compliance, patient data protection, \
and operational continuity are paramount priorities.

Anti-hallucination rule: Only report findings directly supported by agent output data. \
State "insufficient data" rather than speculating. Never fabricate CVE IDs, IP addresses, \
or threat actor names.\
"""


# ---------------------------------------------------------------------------
# Module-level SSE session queues — one asyncio.Queue per active session.
# The SSE stream endpoint creates a queue before launching the orchestrator;
# the orchestrator pushes events into it; the SSE generator reads and yields.
# ---------------------------------------------------------------------------

_session_queues: dict[str, asyncio.Queue] = {}


def get_session_queue(session_id: str) -> asyncio.Queue:
    """Return (creating if absent) the event queue for *session_id*."""
    if session_id not in _session_queues:
        _session_queues[session_id] = asyncio.Queue()
    return _session_queues[session_id]


def cleanup_session_queue(session_id: str) -> None:
    """Remove the queue for *session_id* after the SSE stream is closed."""
    _session_queues.pop(session_id, None)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """Master orchestrator that routes input, dispatches agents, and synthesizes results."""

    def __init__(self) -> None:
        self.model = config.ORCHESTRATOR_MODEL
        self._agents: dict[str, BaseAgent] = {}
        self._client: Optional[object] = None
        self._register_agents()

    # ------------------------------------------------------------------
    # Agent registry
    # ------------------------------------------------------------------

    def _register_agents(self) -> None:
        """Register all available agents."""
        from agents.vulnerability_agent import VulnerabilityAgent
        from agents.threat_intel_agent import ThreatIntelAgent
        from agents.log_analysis_agent import LogAnalysisAgent
        from agents.report_agent import ReportAgent

        for agent_cls in (VulnerabilityAgent, ThreatIntelAgent, LogAnalysisAgent, ReportAgent):
            agent = agent_cls()
            self._agents[agent.name] = agent

    def get_agent(self, name: str) -> Optional[BaseAgent]:
        """Retrieve a registered agent by name."""
        return self._agents.get(name)

    # ------------------------------------------------------------------
    # SSE event emission
    # ------------------------------------------------------------------

    async def _emit_event(
        self, session_id: Optional[str], event_type: str, data: dict
    ) -> None:
        """Push an event into the session's SSE queue (no-op if no queue)."""
        if session_id and session_id in _session_queues:
            await _session_queues[session_id].put({"type": event_type, **data})

    # ------------------------------------------------------------------
    # LLM helpers
    # ------------------------------------------------------------------

    async def _call_llm(self, prompt: str) -> str:
        """Call the LLM for orchestrator-level synthesis."""
        if config.USE_MOCK_LLM:
            return await MockLLM.generate("orchestrator", prompt)
        return await self._call_real_llm(prompt)

    async def _call_real_llm(self, prompt: str) -> str:
        """Call the real Anthropic API for synthesis."""
        import anthropic

        if self._client is None:
            self._client = anthropic.AsyncAnthropic(api_key=config.ANTHROPIC_API_KEY)

        for attempt in range(config.LLM_MAX_RETRIES):
            try:
                response = await self._client.messages.create(
                    model=self.model,
                    max_tokens=config.ORCHESTRATOR_MAX_TOKENS,
                    system=ORCHESTRATOR_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                )
                usage = response.usage
                cost = _calculate_cost(self.model, usage.input_tokens, usage.output_tokens)
                logger.warning(
                    "Orchestrator LLM call: in=%d out=%d cost=$%.4f",
                    usage.input_tokens,
                    usage.output_tokens,
                    cost,
                )
                return response.content[0].text
            except anthropic.RateLimitError:
                wait = config.LLM_RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning("Orchestrator rate limit, waiting %.1fs", wait)
                await asyncio.sleep(wait)
            except anthropic.APIError as exc:
                logger.error("Orchestrator API error: %s", exc)
                if attempt == config.LLM_MAX_RETRIES - 1:
                    return json.dumps({"synthesis": "LLM synthesis unavailable.", "error": str(exc)})
                await asyncio.sleep(config.LLM_RETRY_BASE_DELAY)

        return json.dumps({"synthesis": "Max retries exceeded."})

    # ------------------------------------------------------------------
    # Main entry points
    # ------------------------------------------------------------------

    async def run(self, query: str, session_id: Optional[str] = None) -> AgentResult:
        """Convenience entry point that accepts a plain string query.

        Wraps ``handle()`` and threads ``session_id`` through for SSE streaming.
        This is the primary entry point used by the dashboard's SSE stream endpoint.
        """
        return await self.handle(query, session_id=session_id)

    async def handle(
        self,
        user_input: Union[str, dict],
        session_id: Optional[str] = None,
    ) -> AgentResult:
        """Accept natural language or structured input, route, dispatch, synthesize."""
        # Lazy import to avoid circular import at module level
        from output.terminal import TerminalOutput as term

        ctx = SessionContext()

        # Step 1 — Classify input
        if isinstance(user_input, dict):
            routing = classify_structured(user_input)
            ctx.original_input = json.dumps(user_input)
        else:
            routing = classify(user_input)
            ctx.original_input = user_input

        ctx.intent = routing.intent
        ctx.entities = routing.extracted_entities
        ctx.add_user_message(ctx.original_input)

        logger.info(
            "Orchestrator received input | intent=%s agents=%s session=%s",
            routing.intent,
            routing.target_agents,
            session_id,
        )

        # Step 2 — Print routing decision + emit SSE routing event
        term.print_routing_decision(routing)
        await self._emit_event(session_id, "routing", {
            "session_id": session_id,
            "intent": routing.intent,
            "agents": routing.target_agents,
            "confidence": routing.confidence,
            "reasoning": routing.reasoning,
        })

        # Step 3 — Build tasks for each target agent
        task = self._build_task(routing, user_input)

        # Step 4 — Dispatch agents (parallel if multiple) with SSE emission
        results = await self._dispatch(routing.target_agents, task, term, session_id)

        # Step 5 — Merge results
        merged = self._merge_results(results)
        for r in results:
            ctx.add_result(r)

        # Step 6 — Synthesize via LLM
        synthesis_prompt = self._build_synthesis_prompt(merged)
        synthesis_raw = await self._call_llm(synthesis_prompt)
        synthesis = self._parse_synthesis(synthesis_raw)

        merged.summary = synthesis.get("synthesis") or merged.summary

        # Emit synthesis SSE event
        await self._emit_event(session_id, "synthesis", {
            "session_id": session_id,
            "summary": merged.summary,
            "risk_level": synthesis.get("risk_level", "unknown"),
        })

        # Step 7 — Save to database
        await self._save_findings(merged, ctx)

        # Step 8 — Print final output
        if merged.findings:
            term.print_findings_table(merged.findings)
        term.print_orchestrator_summary(
            merged.summary,
            merged.finding_count(),
            merged.critical_count(),
            merged.high_count(),
        )

        # Emit done SSE event
        total_cost = merged.tokens_used_detail.get("cost_usd", 0.0)
        await self._emit_event(session_id, "done", {
            "session_id": session_id,
            "total_findings": merged.finding_count(),
            "critical_findings": merged.critical_count(),
            "high_findings": merged.high_count(),
            "summary": merged.summary,
            "status": merged.status,
            "cost_usd": round(total_cost, 6),
        })

        return merged

    async def handle_cve(self, cve_id: str) -> AgentResult:
        """Convenience method for direct CVE lookup."""
        return await self.handle({"type": "cve_lookup", "cve_id": cve_id})

    async def handle_scan(self, days: int = 7, cvss_min: float = 9.0) -> AgentResult:
        """Convenience method for scanning recent critical CVEs."""
        return await self.handle(
            {"type": "vulnerability_scan", "keyword": "recent", "days": days, "cvss_min": cvss_min}
        )

    async def handle_kev(self, days: int = 30) -> AgentResult:
        """Convenience method for listing recent KEV additions."""
        return await self.handle(
            {"type": "cve_lookup", "keyword": "kev_recent", "days": days}
        )

    async def handle_ip(self, ip: str) -> AgentResult:
        """Convenience method for IP enrichment."""
        return await self.handle({"type": "ip_check", "ip": ip})

    async def handle_log(self, log_source: str, log_lines: Optional[list[str]] = None) -> AgentResult:
        """Convenience method for log analysis."""
        task: dict = {"type": "log_analysis", "log_source": log_source}
        if log_lines is not None:
            task["log_lines"] = log_lines
        return await self.handle(task)

    async def handle_report(self, report_type: str = "executive") -> AgentResult:
        """Convenience method for report generation."""
        return await self.handle({"type": "generate_report", "report_type": report_type})

    async def handle_assess(
        self,
        ip: Optional[str] = None,
        cve_id: Optional[str] = None,
    ) -> AgentResult:
        """Convenience method for full multi-agent assessment."""
        task: dict = {"type": "full_assessment"}
        if ip:
            task["ip"] = ip
        if cve_id:
            task["cve_id"] = cve_id
        return await self.handle(task)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_task(self, routing: RoutingDecision, user_input: Union[str, dict]) -> dict:
        """Build the task dict to pass to agents."""
        if isinstance(user_input, dict):
            task = dict(user_input)
        else:
            task = {"query": user_input}

        task["intent"] = routing.intent
        task.update(routing.extracted_entities)
        return task

    async def _dispatch(
        self,
        agent_names: list[str],
        task: dict,
        term: object,
        session_id: Optional[str] = None,
    ) -> list[AgentResult]:
        """Dispatch to one or more agents in parallel, emitting SSE events."""
        from output.terminal import TerminalOutput

        coros = []
        for name in agent_names:
            agent = self.get_agent(name)
            if agent is None:
                logger.warning("Agent '%s' not registered — skipping", name)
                coros.append(self._make_not_implemented_result(name))
            else:
                task_label = str(task.get("query", task.get("cve_id", task.get("ip", ""))))
                TerminalOutput.print_agent_start(agent.name, task_label)
                # Emit SSE agent_start
                await self._emit_event(session_id, "agent_start", {
                    "session_id": session_id,
                    "agent": agent.name,
                    "task": task_label or "Analyzing…",
                })
                coros.append(agent.execute(task))

        start_times: dict[str, float] = {name: time.perf_counter() for name in agent_names}
        results_raw = await asyncio.gather(*coros, return_exceptions=True)

        # Wrap any unexpected exceptions; emit agent_complete / per-finding events
        safe_results: list[AgentResult] = []
        for idx, r in enumerate(results_raw):
            name = agent_names[idx] if idx < len(agent_names) else "unknown"
            elapsed_ms = int((time.perf_counter() - start_times.get(name, 0)) * 1000)

            if isinstance(r, AgentResult):
                from output.terminal import TerminalOutput as _t
                _t.print_agent_complete(r)

                # Emit a finding event for each finding
                for finding in r.findings:
                    await self._emit_event(session_id, "finding", {
                        "session_id": session_id,
                        "severity": finding.get("severity", "unknown"),
                        "title": finding.get("title", ""),
                        "cve_id": finding.get("cve_id"),
                        "cvss": finding.get("cvss_score"),
                        "is_kev": finding.get("is_kev", False),
                        "finding_type": finding.get("finding_type", ""),
                    })

                # Emit agent_complete
                await self._emit_event(session_id, "agent_complete", {
                    "session_id": session_id,
                    "agent": r.agent_name,
                    "status": r.status,
                    "findings_count": r.finding_count(),
                    "execution_ms": r.execution_time_ms or elapsed_ms,
                    "cost_usd": r.tokens_used_detail.get("cost_usd", 0.0),
                })

                safe_results.append(r)

            elif isinstance(r, Exception):
                logger.error("Agent '%s' raised exception: %s", name, r)
                err_result = AgentResult(
                    agent_name=name,
                    status="error",
                    error=str(r),
                    summary=f"Agent {name} encountered an error: {r}",
                )
                await self._emit_event(session_id, "agent_complete", {
                    "session_id": session_id,
                    "agent": name,
                    "status": "error",
                    "findings_count": 0,
                    "execution_ms": elapsed_ms,
                    "error": str(r),
                })
                safe_results.append(err_result)
            else:
                err_result = AgentResult(
                    agent_name=name,
                    status="error",
                    error=str(r),
                    summary=f"Agent {name} returned unexpected type.",
                )
                safe_results.append(err_result)

        return safe_results

    @staticmethod
    async def _make_not_implemented_result(agent_name: str) -> AgentResult:
        """Return a placeholder result for agents not yet implemented."""
        return AgentResult(
            agent_name=agent_name,
            status="error",
            error=f"Agent '{agent_name}' is not yet implemented.",
            summary=f"Agent '{agent_name}' is not yet implemented.",
        )

    @staticmethod
    def _merge_results(results: list[AgentResult]) -> AgentResult:
        """Merge multiple AgentResults into one."""
        if not results:
            return AgentResult(
                agent_name="orchestrator",
                status="no_data",
                summary="No agents produced results.",
            )
        merged = results[0]
        for r in results[1:]:
            merged = merged.merge(r)
        return merged

    def _build_synthesis_prompt(self, merged: AgentResult) -> str:
        """Build a prompt asking the LLM to synthesize agent findings."""
        findings_json = json.dumps(merged.findings, indent=2, default=str)
        return (
            f"Synthesize the following security findings into a unified threat assessment.\n\n"
            f"Agent: {merged.agent_name}\n"
            f"Status: {merged.status}\n"
            f"Total findings: {merged.finding_count()}\n"
            f"Critical: {merged.critical_count()}, High: {merged.high_count()}\n"
            f"Data sources: {', '.join(merged.data_sources)}\n\n"
            f"Findings:\n{findings_json}\n\n"
            f"Provide a JSON object with keys: synthesis, risk_level, recommended_actions, confidence."
        )

    @staticmethod
    def _parse_synthesis(raw: str) -> dict:
        """Safely parse the LLM synthesis response.

        Strips markdown code fences (```json ... ```) before parsing so the
        orchestrator summary panel never displays raw JSON.  After parsing,
        coerces the ``synthesis`` value to a plain string so terminal.py
        receives something it can render directly.
        """
        import re

        text = raw.strip() if raw else ""

        # Strip opening fence (```json or plain ```)
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\n?", "", text)
            text = re.sub(r"\n?```$", "", text.rstrip())

        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            # Fall back to using the cleaned text as the summary
            return {"synthesis": text}

        if not isinstance(parsed, dict):
            return {"synthesis": str(parsed)}

        # Ensure `synthesis` is a printable string, not a nested structure
        synthesis_val = parsed.get("synthesis", "")
        if not isinstance(synthesis_val, str):
            synthesis_val = json.dumps(synthesis_val)
        parsed["synthesis"] = synthesis_val

        return parsed

    async def _save_findings(self, result: AgentResult, ctx: SessionContext) -> None:
        """Persist findings and session info to SQLite."""
        from db.repository import Repository
        from output.terminal import TerminalOutput as term

        repo = Repository()
        try:
            saved = await repo.save_agent_result(result, ctx.session_id)
            if saved > 0:
                term.print_db_save_confirmation("findings", saved)
        except Exception as exc:
            logger.error("Failed to save findings: %s", exc, exc_info=True)
