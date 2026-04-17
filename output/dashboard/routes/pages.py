"""HTML page routes for the CyberSentinel dashboard."""

import logging

from fastapi import APIRouter, Request

import config
from db.database import get_connection
from db.repository import Repository

logger = logging.getLogger("cybersentinel.dashboard.pages")

router = APIRouter()


# ------------------------------------------------------------------
# GET / — Dashboard overview
# ------------------------------------------------------------------


@router.get("/")
async def dashboard(request: Request):
    """Main dashboard with stats, recent findings, and session history."""
    templates = request.app.state.templates
    repo = Repository()

    stats = await repo.get_database_stats()
    recent_findings = await repo.get_findings(limit=10)
    sessions = await repo.get_session_history(limit=5)

    # Build severity_counts from the stats dict
    severity_counts = stats.get("findings_by_severity", {})

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "stats": stats,
            "recent_findings": recent_findings,
            "sessions": sessions,
            "config": config,
            "severity_counts": severity_counts,
            "active_page": "dashboard",
        },
    )


# ------------------------------------------------------------------
# GET /findings — Findings table
# ------------------------------------------------------------------


@router.get("/findings")
async def findings(request: Request):
    """All findings, up to 100 rows."""
    templates = request.app.state.templates
    repo = Repository()

    findings_list = await repo.get_findings(limit=100)

    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={
            "findings": findings_list,
            "config": config,
            "active_page": "findings",
        },
    )


# ------------------------------------------------------------------
# GET /iocs — IOC table
# ------------------------------------------------------------------


@router.get("/iocs")
async def iocs(request: Request):
    """Indicators of Compromise table."""
    templates = request.app.state.templates

    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM iocs ORDER BY last_seen DESC LIMIT 50"
    ).fetchall()
    iocs_list = [dict(r) for r in rows]

    return templates.TemplateResponse(
        request=request,
        name="iocs.html",
        context={
            "iocs": iocs_list,
            "config": config,
            "active_page": "iocs",
        },
    )


# ------------------------------------------------------------------
# GET /cves — CVE findings
# ------------------------------------------------------------------


@router.get("/cves")
async def cves(request: Request):
    """CVE findings table."""
    templates = request.app.state.templates
    repo = Repository()

    cves_list = await repo.get_cve_findings(limit=50)

    return templates.TemplateResponse(
        request=request,
        name="cves.html",
        context={
            "cves": cves_list,
            "config": config,
            "active_page": "cves",
        },
    )


# ------------------------------------------------------------------
# GET /run — Run query page
# ------------------------------------------------------------------


@router.get("/run")
async def run_query(request: Request):
    """Query execution page (mostly client-side JS)."""
    templates = request.app.state.templates

    return templates.TemplateResponse(
        request=request,
        name="run.html",
        context={
            "config": config,
            "active_page": "run",
        },
    )


# ------------------------------------------------------------------
# GET /agents — Agent status
# ------------------------------------------------------------------


@router.get("/agents")
async def agents(request: Request):
    """Agent registry, session history, and integration status."""
    templates = request.app.state.templates
    repo = Repository()

    # Build the agent registry list from the orchestrator
    from core.orchestrator import Orchestrator

    orch = Orchestrator()
    agents_list = []
    for name, agent in orch._agents.items():
        agents_list.append({
            "name": agent.name,
            "description": agent.description,
            "capabilities": agent.capabilities,
            "model": agent.model,
        })

    # Recent sessions
    sessions = await repo.get_session_history(limit=20)

    # Integration status
    integrations = {
        "NVD": {
            "enabled": True,
            "key_required": False,
            "note": "No key required",
        },
        "CISA KEV": {
            "enabled": True,
            "key_required": False,
            "note": "Public JSON feed",
        },
        "Exa": {
            "enabled": bool(config.EXA_API_KEY),
            "key_required": True,
        },
        "AlienVault OTX": {
            "enabled": bool(config.OTX_API_KEY),
            "key_required": True,
        },
        "AbuseIPDB": {
            "enabled": bool(config.ABUSEIPDB_API_KEY),
            "key_required": True,
        },
        "Anthropic": {
            "enabled": bool(config.ANTHROPIC_API_KEY),
            "key_required": True,
        },
    }

    # Cost / token usage summary
    from core.cost_tracker import cost_tracker

    cost_data = cost_tracker.get_all_sessions_total()
    cost_context = {
        "total_cost_usd": cost_data["total_cost_usd"],
        "total_input_tokens": cost_data["total_input_tokens"],
        "total_output_tokens": cost_data["total_output_tokens"],
        "cost_by_agent": cost_data["cost_by_agent"],
        "session_count": cost_data["session_count"],
        "mock_mode": config.USE_MOCK_LLM,
        "formatted_cost": (
            f"${cost_data['total_cost_usd']:.4f}"
            if cost_data["total_cost_usd"] > 0
            else "$0.0000"
        ),
    }

    return templates.TemplateResponse(
        request=request,
        name="agents.html",
        context={
            "agents": agents_list,
            "sessions": sessions,
            "integrations": integrations,
            "config": config,
            "active_page": "agents",
            "cost": cost_context,
        },
    )
