"""Database migrations — creates all tables on first run."""

import logging
import sqlite3

logger = logging.getLogger("cybersentinel.db.migrations")

SCHEMA_SQL = """
-- Table 1: IOCs (Indicators of Compromise)
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    severity TEXT CHECK(severity IN ('critical','high','medium','low','info')),
    source TEXT NOT NULL,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    tags TEXT,
    mitre_techniques TEXT,
    is_active BOOLEAN DEFAULT 1,
    notes TEXT,
    UNIQUE(ioc_type, value)
);

-- Table 2: CVE Findings
CREATE TABLE IF NOT EXISTS cve_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    cvss_score REAL,
    severity TEXT,
    priority TEXT,
    risk_score REAL,
    is_kev BOOLEAN DEFAULT 0,
    kev_due_date TEXT,
    recommended_action TEXT,
    deadline TEXT,
    affected_assets TEXT,
    remediation TEXT,
    status TEXT DEFAULT 'open',
    first_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    raw_nvd_data TEXT,
    notes TEXT
);

-- Table 3: Agent Findings (generic findings from any agent)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL UNIQUE,
    finding_type TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    confidence REAL,
    evidence TEXT,
    mitre_techniques TEXT,
    status TEXT DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    dedup_hash TEXT UNIQUE,
    raw_data TEXT
);

-- Table 4: Agent Sessions (audit trail)
CREATE TABLE IF NOT EXISTS agent_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,
    agent_name TEXT NOT NULL,
    input_summary TEXT,
    status TEXT,
    findings_count INTEGER DEFAULT 0,
    tokens_used INTEGER DEFAULT 0,
    execution_time_ms INTEGER,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    error_message TEXT
);

-- Table 5: Conversation History
CREATE TABLE IF NOT EXISTS conversation_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    agent_name TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


def run_migrations(conn: sqlite3.Connection) -> None:
    """Execute all CREATE TABLE statements."""
    logger.info("Running database migrations")
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    logger.info("Migrations complete — all tables ready")
