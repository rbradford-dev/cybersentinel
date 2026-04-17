"""JSON API router — all data endpoints consumed by HTMX and JavaScript."""

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

import config
from db.database import get_connection
from db.repository import Repository

logger = logging.getLogger("cybersentinel.dashboard.api")

router = APIRouter(tags=["api"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class QueryRequest(BaseModel):
    """Body schema for POST /query."""

    query: str
    type: str = "general"


# ---------------------------------------------------------------------------
# GET /findings — paginated findings
# ---------------------------------------------------------------------------


@router.get("/findings")
async def get_findings(
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Return paginated findings, optionally filtered by severity."""
    repo = Repository()
    conn = get_connection()

    # Build query with optional severity filter
    if severity:
        rows = conn.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (severity, limit, offset),
        ).fetchall()
        total_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM findings WHERE severity = ?",
            (severity,),
        ).fetchone()
    else:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total_row = conn.execute("SELECT COUNT(*) as cnt FROM findings").fetchone()

    total = total_row["cnt"] if total_row else 0
    page = (offset // limit) + 1 if limit else 1

    return {
        "findings": [dict(r) for r in rows],
        "total": total,
        "page": page,
    }


# ---------------------------------------------------------------------------
# GET /findings/stats — severity distribution
# ---------------------------------------------------------------------------


@router.get("/findings/stats")
async def get_findings_stats():
    """Return finding counts grouped by severity."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT LOWER(severity) as severity, COUNT(*) as cnt FROM findings GROUP BY LOWER(severity)"
    ).fetchall()

    counts = {r["severity"]: r["cnt"] for r in rows if r["severity"]}
    total = sum(counts.values())

    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "total": total,
    }


# ---------------------------------------------------------------------------
# GET /iocs — paginated IOC list
# ---------------------------------------------------------------------------


@router.get("/iocs")
async def get_iocs(
    type: Optional[str] = Query(None, alias="type", description="Filter by IOC type"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Return paginated IOCs, optionally filtered by type."""
    conn = get_connection()

    if type:
        rows = conn.execute(
            "SELECT * FROM iocs WHERE ioc_type = ? ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            (type, limit, offset),
        ).fetchall()
        total_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM iocs WHERE ioc_type = ?",
            (type,),
        ).fetchone()
    else:
        rows = conn.execute(
            "SELECT * FROM iocs ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total_row = conn.execute("SELECT COUNT(*) as cnt FROM iocs").fetchone()

    total = total_row["cnt"] if total_row else 0

    return {
        "iocs": [dict(r) for r in rows],
        "total": total,
    }


# ---------------------------------------------------------------------------
# GET /cves — CVE findings
# ---------------------------------------------------------------------------


@router.get("/cves")
async def get_cves(
    priority: Optional[str] = Query(None, description="Filter by priority"),
    limit: int = Query(50, ge=1, le=500),
):
    """Return CVE findings, optionally filtered by priority."""
    repo = Repository()

    if priority:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM cve_findings WHERE priority = ? ORDER BY last_updated DESC LIMIT ?",
            (priority, limit),
        ).fetchall()
        cves = [dict(r) for r in rows]
    else:
        cves = await repo.get_cve_findings(limit=limit)

    return {
        "cves": cves,
        "total": len(cves),
    }


# ---------------------------------------------------------------------------
# GET /agents/status — agent health
# ---------------------------------------------------------------------------


@router.get("/agents/status")
async def get_agents_status():
    """Return status information for all registered agents."""
    from core.orchestrator import Orchestrator

    orch = Orchestrator()
    agents = []

    for name, agent in orch._agents.items():
        agents.append(
            {
                "name": agent.name,
                "description": agent.description,
                "capabilities": agent.capabilities,
                "model": agent.model,
                "enabled": True,
            }
        )

    return {"agents": agents}


# ---------------------------------------------------------------------------
# GET /sessions — recent sessions
# ---------------------------------------------------------------------------


@router.get("/sessions")
async def get_sessions(
    limit: int = Query(20, ge=1, le=200),
):
    """Return recent agent sessions."""
    repo = Repository()
    sessions = await repo.get_session_history(limit=limit)
    return {"sessions": sessions}


# ---------------------------------------------------------------------------
# GET /stats — dashboard stat cards
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_stats():
    """Return aggregate statistics for the dashboard stat cards."""
    repo = Repository()
    summary = await repo.get_db_summary()
    conn = get_connection()

    # Severity counts for findings
    critical_row = conn.execute(
        "SELECT COUNT(*) as cnt FROM findings WHERE LOWER(severity) = 'critical'"
    ).fetchone()
    high_row = conn.execute(
        "SELECT COUNT(*) as cnt FROM findings WHERE LOWER(severity) = 'high'"
    ).fetchone()

    # Last scan timestamp
    last_scan_row = conn.execute(
        "SELECT completed_at FROM agent_sessions ORDER BY completed_at DESC LIMIT 1"
    ).fetchone()

    return {
        "total_findings": summary.get("findings", 0),
        "total_iocs": summary.get("iocs", 0),
        "total_cves": summary.get("cve_findings", 0),
        "total_sessions": summary.get("agent_sessions", 0),
        "critical_findings": critical_row["cnt"] if critical_row else 0,
        "high_findings": high_row["cnt"] if high_row else 0,
        "last_scan": last_scan_row["completed_at"] if last_scan_row else None,
    }


# ---------------------------------------------------------------------------
# POST /query — submit query to orchestrator
# ---------------------------------------------------------------------------


@router.post("/query")
async def submit_query(body: QueryRequest):
    """Accept a security query and return a session ID (does not block on execution)."""
    session_id = str(uuid.uuid4())

    logger.info(
        "Query queued | session_id=%s type=%s query=%s",
        session_id,
        body.type,
        body.query[:120],
    )

    return {
        "session_id": session_id,
        "status": "queued",
    }


# ---------------------------------------------------------------------------
# GET /costs — token usage and cost summary
# ---------------------------------------------------------------------------


@router.get("/costs")
async def get_costs():
    """Return token usage and API cost summary from the in-memory cost tracker.

    In mock mode all costs are $0.00 (no real API calls are made).
    """
    from core.cost_tracker import cost_tracker

    totals = cost_tracker.get_all_sessions_total()
    return {
        "total_cost_usd": totals["total_cost_usd"],
        "total_input_tokens": totals["total_input_tokens"],
        "total_output_tokens": totals["total_output_tokens"],
        "cost_by_agent": totals["cost_by_agent"],
        "session_count": totals["session_count"],
        "mock_mode": config.USE_MOCK_LLM,
        "formatted_cost": (
            f"${totals['total_cost_usd']:.4f}"
            if totals["total_cost_usd"] > 0
            else "$0.0000"
        ),
    }


# ---------------------------------------------------------------------------
# GET /integrations/status — configured API keys
# ---------------------------------------------------------------------------


@router.get("/integrations/status")
async def get_integrations_status():
    """Report which third-party integrations have API keys configured."""
    return {
        "nvd": bool(config.NVD_API_KEY),
        "cisa_kev": True,  # no key required — public feed
        "exa": bool(config.EXA_API_KEY),
        "otx": bool(config.OTX_API_KEY),
        "abuseipdb": bool(config.ABUSEIPDB_API_KEY),
        "anthropic": bool(config.ANTHROPIC_API_KEY),
    }
