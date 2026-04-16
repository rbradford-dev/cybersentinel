"""Server-Sent Events (SSE) router — real-time streaming endpoints.

Phase 3 (mock mode): endpoints return realistic simulated agent events.
Phase 4 will wire these to the live orchestrator pipeline.
"""

import asyncio
import json
import uuid

from fastapi import APIRouter, Query, Request
from sse_starlette.sse import EventSourceResponse

import config

router = APIRouter(tags=["stream"])


# ---------------------------------------------------------------------------
# GET /stream/agent-output — primary SSE feed for the Run Query page
# ---------------------------------------------------------------------------

@router.get("/stream/agent-output")
async def stream_agent_output(
    request: Request,
    session_id: str = Query(default=None, description="Session ID for this query run"),
):
    """Stream agent activity events in real time.

    The browser connects here after submitting a query on the Run Query page.
    Each event corresponds to a stage in the agent execution pipeline:
    routing -> agent_start -> finding(s) -> agent_complete -> synthesis -> done
    """

    async def event_generator():
        sid = session_id or str(uuid.uuid4())

        # Routing decision
        yield {
            "event": "routing",
            "data": json.dumps({
                "type": "routing",
                "session_id": sid,
                "intent": "cve_lookup",
                "agents": ["vulnerability_agent"],
                "confidence": 0.95,
                "reasoning": "Detected CVE identifier pattern",
            }),
        }
        await asyncio.sleep(0.5)

        if await request.is_disconnected():
            return

        # Agent start
        yield {
            "event": "agent_start",
            "data": json.dumps({
                "type": "agent_start",
                "session_id": sid,
                "agent": "vulnerability_agent",
                "task": "Analyzing query...",
            }),
        }
        await asyncio.sleep(1.5)

        if await request.is_disconnected():
            return

        # Finding discovered
        yield {
            "event": "finding",
            "data": json.dumps({
                "type": "finding",
                "session_id": sid,
                "severity": "critical",
                "title": "CVE-2024-38094: SharePoint RCE \u2014 Active Exploitation",
                "cve_id": "CVE-2024-38094",
                "cvss": 9.8,
                "is_kev": True,
            }),
        }
        await asyncio.sleep(0.8)

        if await request.is_disconnected():
            return

        # Agent complete
        yield {
            "event": "agent_complete",
            "data": json.dumps({
                "type": "agent_complete",
                "session_id": sid,
                "agent": "vulnerability_agent",
                "status": "success",
                "findings_count": 1,
                "execution_ms": 1842,
            }),
        }
        await asyncio.sleep(0.5)

        if await request.is_disconnected():
            return

        # Synthesis
        yield {
            "event": "synthesis",
            "data": json.dumps({
                "type": "synthesis",
                "session_id": sid,
                "summary": "Critical RCE vulnerability actively exploited. Immediate patching required.",
                "risk_level": "critical",
            }),
        }
        await asyncio.sleep(0.3)

        if await request.is_disconnected():
            return

        # Done
        yield {
            "event": "done",
            "data": json.dumps({
                "type": "done",
                "session_id": sid,
                "total_findings": 1,
                "summary": "Analysis complete. 1 critical finding requires immediate attention.",
            }),
        }

    return EventSourceResponse(event_generator(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# GET /stream/findings-feed — periodic findings count for dashboard overview
# ---------------------------------------------------------------------------

@router.get("/stream/findings-feed")
async def stream_findings_feed(request: Request):
    """Push updated findings counts whenever the total changes.

    Polls the database every 5 seconds and emits a ``stats_update`` event
    that includes the total count and a severity breakdown.  Used by the
    dashboard overview page to auto-refresh stat cards.
    """

    async def findings_feed():
        from db.database import get_connection

        last_count = -1

        while True:
            if await request.is_disconnected():
                return

            conn = get_connection()
            row = conn.execute("SELECT COUNT(*) as cnt FROM findings").fetchone()
            count = row["cnt"] if row else 0

            if count != last_count:
                last_count = count

                # Severity breakdown
                sev_rows = conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
                ).fetchall()
                severity = {r["severity"]: r["cnt"] for r in sev_rows}

                yield {
                    "event": "stats_update",
                    "data": json.dumps({
                        "type": "stats_update",
                        "total_findings": count,
                        "severity": severity,
                    }),
                }

            await asyncio.sleep(5)

    return EventSourceResponse(findings_feed(), media_type="text/event-stream")
