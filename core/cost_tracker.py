"""Cost tracker — accumulates token usage and API costs across agent sessions.

Thread-safe (via asyncio.Lock) in-memory accumulator with optional SQLite
read-back for all-time totals.  Use the module-level ``cost_tracker`` singleton.

Phase 4: informational only — does NOT throttle or block API calls.
"""

import asyncio
import logging
from typing import Optional

import config

logger = logging.getLogger("cybersentinel.cost_tracker")


class CostTracker:
    """Tracks token usage and API costs across agent sessions.

    Stores per-session costs in memory and can aggregate all-time totals
    from the ``agent_sessions`` table in SQLite.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # {session_id: {agent_name: {input_tokens, output_tokens, cost_usd}}}
        self._session_costs: dict[str, dict[str, dict]] = {}

    # ------------------------------------------------------------------
    # Recording usage
    # ------------------------------------------------------------------

    async def record(
        self,
        session_id: str,
        agent_name: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
    ) -> None:
        """Record a single LLM call's usage.

        Accumulates values if the same (session_id, agent_name) pair is
        called multiple times (e.g., an agent that calls the LLM more than
        once per run).
        """
        if not config.COST_TRACKING_ENABLED:
            return

        async with self._lock:
            session = self._session_costs.setdefault(session_id, {})
            agent = session.setdefault(
                agent_name,
                {"model": model, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
            )
            agent["input_tokens"] += input_tokens
            agent["output_tokens"] += output_tokens
            agent["cost_usd"] += cost_usd
            agent["model"] = model  # overwrite — model should not change mid-session

        # Warn if session cost crosses the configured threshold
        session_total = self.get_session_total(session_id)
        if session_total["total_cost_usd"] > config.COST_WARNING_THRESHOLD_USD:
            logger.warning(
                "Session '%s' cost $%.4f exceeds warning threshold $%.2f",
                session_id,
                session_total["total_cost_usd"],
                config.COST_WARNING_THRESHOLD_USD,
            )

    # ------------------------------------------------------------------
    # Querying usage
    # ------------------------------------------------------------------

    def get_session_total(self, session_id: str) -> dict:
        """Return aggregated cost and token counts for a single session.

        Returns a dict with keys:
            session_id, total_cost_usd, total_input_tokens,
            total_output_tokens, cost_by_agent
        """
        session = self._session_costs.get(session_id, {})
        total_input = sum(v["input_tokens"] for v in session.values())
        total_output = sum(v["output_tokens"] for v in session.values())
        total_cost = sum(v["cost_usd"] for v in session.values())
        cost_by_agent = {
            agent: round(v["cost_usd"], 6) for agent, v in session.items()
        }
        return {
            "session_id": session_id,
            "total_cost_usd": round(total_cost, 6),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "cost_by_agent": cost_by_agent,
        }

    def get_all_sessions_total(self) -> dict:
        """Return aggregated totals across all in-memory sessions."""
        total_input = 0
        total_output = 0
        total_cost = 0.0
        cost_by_agent: dict[str, float] = {}
        session_count = len(self._session_costs)

        for session in self._session_costs.values():
            for agent_name, usage in session.items():
                total_input += usage["input_tokens"]
                total_output += usage["output_tokens"]
                total_cost += usage["cost_usd"]
                cost_by_agent[agent_name] = (
                    cost_by_agent.get(agent_name, 0.0) + usage["cost_usd"]
                )

        return {
            "total_cost_usd": round(total_cost, 6),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "cost_by_agent": {k: round(v, 6) for k, v in cost_by_agent.items()},
            "session_count": session_count,
        }

    def get_all_time_total(self) -> dict:
        """Aggregate totals from the agent_sessions SQLite table.

        Returns the same shape as ``get_all_sessions_total()``, but sourced
        from persisted DB rows so it survives restarts.  Falls back gracefully
        if the DB is unavailable.
        """
        try:
            from db.database import get_connection

            conn = get_connection()
            rows = conn.execute(
                """
                SELECT agent_name,
                       SUM(COALESCE(tokens_used, 0))  AS total_tokens,
                       COUNT(*)                         AS session_count
                FROM   agent_sessions
                GROUP  BY agent_name
                """
            ).fetchall()

            total_tokens = sum(r["total_tokens"] for r in rows)
            cost_by_agent: dict[str, float] = {}
            for r in rows:
                # We don't persist cost breakdown per agent in DB yet,
                # so we can only report token counts here.
                cost_by_agent[r["agent_name"]] = 0.0

            return {
                "total_cost_usd": 0.0,  # not persisted in DB
                "total_input_tokens": total_tokens,
                "total_output_tokens": 0,
                "cost_by_agent": cost_by_agent,
                "session_count": sum(r["session_count"] for r in rows),
                "note": "Cost breakdown not persisted; restart to reset in-memory totals.",
            }
        except Exception as exc:
            logger.warning("Could not read all-time totals from DB: %s", exc)
            return self.get_all_sessions_total()

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    @staticmethod
    def format_cost(cost_usd: float) -> str:
        """Format a cost as a human-readable USD string (e.g. '$0.0042')."""
        if cost_usd == 0.0:
            return "$0.0000"
        if cost_usd < 0.001:
            return f"${cost_usd:.6f}"
        return f"${cost_usd:.4f}"

    @staticmethod
    def is_mock_mode() -> bool:
        """Return True when running in mock/no-cost mode."""
        return config.USE_MOCK_LLM


# ---------------------------------------------------------------------------
# Module-level singleton — import this from anywhere in the codebase.
# ---------------------------------------------------------------------------

cost_tracker = CostTracker()
