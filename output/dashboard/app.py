"""FastAPI application factory for the CyberSentinel dashboard."""

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import config

# Resolve paths relative to project root (not relative to this file)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DASHBOARD_DIR = Path(__file__).resolve().parent
_TEMPLATES_DIR = _DASHBOARD_DIR / "templates"
_STATIC_DIR = _DASHBOARD_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    from db.database import get_connection  # noqa: F401 — triggers migration

    get_connection()
    yield


def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""
    app = FastAPI(
        title=config.DASHBOARD_TITLE,
        description="Multi-agent cybersecurity intelligence platform",
        version=config.DASHBOARD_VERSION,
        lifespan=lifespan,
    )

    # Mount static files
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Make templates available as app state so routes can access them
    app.state.templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Register routers
    from output.dashboard.routes.pages import router as pages_router
    from output.dashboard.routes.api import router as api_router
    from output.dashboard.routes.stream import router as stream_router

    app.include_router(pages_router)
    app.include_router(api_router, prefix="/api/v1")
    app.include_router(stream_router)

    return app
