"""Server-Sent Events (SSE) router — real-time streaming endpoints.

Phase 4: /stream/agent-output runs the real orchestrator and streams events
from the session queue.  In mock mode (USE_MOCK_LLM=True) the same code path
runs but each agent returns instantaneous mock responses.

/stream/findings-feed polls the database every 5 s and pushes stat updates.
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
    query: str = Query(default="", description="Security query to execute"),
    query_type: str = Query(default="auto", description="Query type hint"),
    session_id: str = Query(default="", description="Session ID (generated if absent)"),
):
    """Stream agent activity events in real time.

    The browser connects here after submitting a query on the Run Query page.
    The orchestrator is run as a background asyncio task; events are pushed
    into a session queue and yielded to the SSE client as they arrive.

    Event types (in order):
        routing → agent_start → finding(s) → agent_complete → synthesis → done

    When no query is supplied, a short mock sequence is emitted so the UI
    has something meaningful to display on first load.
    """
    from core.orchestrator import (
        Orchestrator,
        get_session_queue,
        cleanup_session_queue,
    )

    sid = session_id.strip() or str(uuid.uuid4())

    async def event_generator():
        # If no query provided, emit a single informational event and exit
        if not query.strip():
            yield {
                "event": "done",
                "data": json.dumps({
                    "type": "done",
                    "session_id": sid,
                    "total_findings": 0,
                    "summary": "No query provided. Enter a query and click Run.",
                    "status": "no_data",
                }),
            }
            return

        # Register the session queue BEFORE starting the orchestrator task
        # so events emitted early in execution are not lost.
        queue = get_session_queue(sid)

        # Launch orchestrator in background — it will push events to the queue
        orchestrator = Orchestrator()
        orch_task = asyncio.create_task(
            orchestrator.run(query.strip(), session_id=sid)
        )

        try:
            # Stream events from the queue until the "done" event arrives
            while True:
                if await request.is_disconnected():
                    orch_task.cancel()
                    break

                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    # Send a heartbeat to keep the connection alive
                    yield {"event": "heartbeat", "data": "{}"}
                    continue

                yield {
                    "event": event.get("type", "message"),
                    "data": json.dumps(event),
                }

                if event.get("type") == "done":
                    break

        finally:
            cleanup_session_queue(sid)
            # Ensure the orchestrator task completes (or is cancelled)
            if not orch_task.done():
                try:
                    await asyncio.wait_for(orch_task, timeout=5.0)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass

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

            try:
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
            except Exception:
                pass  # DB may be briefly locked; skip and retry on next cycle

            await asyncio.sleep(5)

    return EventSourceResponse(findings_feed(), media_type="text/event-stream")
