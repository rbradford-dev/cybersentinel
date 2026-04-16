"""SQLite connection manager with WAL mode."""

import logging
import sqlite3
from typing import Optional

import config
from db.migrations import run_migrations

logger = logging.getLogger("cybersentinel.db")

_connection: Optional[sqlite3.Connection] = None


def get_connection() -> sqlite3.Connection:
    """Return a shared SQLite connection, creating it on first call."""
    global _connection
    if _connection is None:
        _connection = _create_connection()
    return _connection


def _create_connection() -> sqlite3.Connection:
    """Create and configure a new SQLite connection."""
    logger.info("Opening database: %s", config.DB_PATH)
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Performance and safety pragmas
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")

    # Run migrations to ensure all tables exist
    run_migrations(conn)

    logger.info("Database ready (WAL mode enabled)")
    return conn


def close_connection() -> None:
    """Close the shared connection if open."""
    global _connection
    if _connection is not None:
        _connection.close()
        _connection = None
        logger.info("Database connection closed")
