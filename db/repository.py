"""CRUD operations for findings, IOCs, CVEs, and agent sessions."""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from core.agent_result import AgentResult
from db.database import get_connection

logger = logging.getLogger("cybersentinel.db.repository")


class Repository:
    """Data-access layer for all CyberSentinel persistence."""

    # ------------------------------------------------------------------
    # Agent results (bulk save)
    # ------------------------------------------------------------------

    async def save_agent_result(self, result: AgentResult, session_id: str) -> int:
        """Persist an AgentResult — saves session, findings, and CVE records."""
        conn = get_connection()
        saved = 0

        # Save the session record
        self._save_session(conn, session_id, result)

        # Save each finding
        for finding in result.findings:
            try:
                self._save_finding(conn, finding, result.agent_name)
                saved += 1

                # If it has a CVE ID, also upsert into cve_findings
                cve_id = finding.get("cve_id")
                if cve_id:
                    self._upsert_cve(conn, finding)
            except Exception as exc:
                logger.warning("Failed to save finding %s: %s", finding.get("finding_id"), exc)

        conn.commit()
        return saved

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    @staticmethod
    def _save_session(conn, session_id: str, result: AgentResult) -> None:
        """Insert an agent session record."""
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT OR REPLACE INTO agent_sessions
                (session_id, agent_name, status, findings_count, tokens_used,
                 execution_time_ms, started_at, completed_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                result.agent_name,
                result.status,
                result.finding_count(),
                result.tokens_used,
                result.execution_time_ms,
                now,
                now,
                result.error,
            ),
        )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    @staticmethod
    def _dedup_hash(finding: dict) -> str:
        """Generate a SHA-256 dedup hash from finding_type|agent_name|title."""
        raw = "|".join(
            [
                finding.get("finding_type", ""),
                finding.get("agent_name", ""),
                finding.get("title", ""),
            ]
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def _save_finding(self, conn, finding: dict, agent_name: str) -> None:
        """Insert a single finding into the findings table."""
        dedup = self._dedup_hash({**finding, "agent_name": agent_name})
        conn.execute(
            """
            INSERT OR IGNORE INTO findings
                (finding_id, finding_type, agent_name, title, description,
                 severity, confidence, evidence, mitre_techniques, status,
                 dedup_hash, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
            """,
            (
                finding.get("finding_id", ""),
                finding.get("finding_type", ""),
                agent_name,
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("severity", ""),
                finding.get("confidence", 0.0),
                json.dumps(finding.get("evidence", [])),
                json.dumps(finding.get("mitre_techniques", [])),
                dedup,
                json.dumps(finding),
            ),
        )

    # ------------------------------------------------------------------
    # CVE findings
    # ------------------------------------------------------------------

    @staticmethod
    def _upsert_cve(conn, finding: dict) -> None:
        """Insert or update a CVE finding record."""
        cve_id = finding.get("cve_id", "")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO cve_findings
                (cve_id, cvss_score, severity, is_kev, kev_due_date,
                 remediation, status, first_detected, last_updated, raw_nvd_data)
            VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                cvss_score = excluded.cvss_score,
                severity = excluded.severity,
                is_kev = excluded.is_kev,
                kev_due_date = excluded.kev_due_date,
                remediation = excluded.remediation,
                last_updated = excluded.last_updated,
                raw_nvd_data = excluded.raw_nvd_data
            """,
            (
                cve_id,
                finding.get("cvss_score"),
                finding.get("severity"),
                1 if finding.get("is_kev") else 0,
                finding.get("kev_due_date"),
                finding.get("remediation"),
                now,
                now,
                json.dumps(finding),
            ),
        )

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    @staticmethod
    async def save_ioc(
        ioc_type: str,
        value: str,
        source: str,
        confidence: float = 0.5,
        severity: Optional[str] = None,
        tags: Optional[list[str]] = None,
        mitre_techniques: Optional[list[str]] = None,
    ) -> None:
        """Insert or update an IOC record."""
        conn = get_connection()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO iocs
                (ioc_type, value, source, confidence, severity, tags,
                 mitre_techniques, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ioc_type, value) DO UPDATE SET
                confidence = MAX(excluded.confidence, iocs.confidence),
                severity = COALESCE(excluded.severity, iocs.severity),
                last_seen = excluded.last_seen
            """,
            (
                ioc_type,
                value,
                source,
                confidence,
                severity,
                json.dumps(tags or []),
                json.dumps(mitre_techniques or []),
                now,
                now,
            ),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def get_findings(status: Optional[str] = None, limit: int = 50) -> list[dict]:
        """Retrieve findings, optionally filtered by status."""
        conn = get_connection()
        if status:
            rows = conn.execute(
                "SELECT * FROM findings WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    async def get_cve_findings(status: Optional[str] = None, limit: int = 50) -> list[dict]:
        """Retrieve CVE findings, optionally filtered by status."""
        conn = get_connection()
        if status:
            rows = conn.execute(
                "SELECT * FROM cve_findings WHERE status = ? ORDER BY last_updated DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM cve_findings ORDER BY last_updated DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    async def get_db_summary() -> dict:
        """Return a summary of database record counts."""
        conn = get_connection()
        tables = ["iocs", "cve_findings", "findings", "agent_sessions", "conversation_history"]
        summary: dict = {}
        for table in tables:
            row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
            summary[table] = row["cnt"] if row else 0
        return summary

    # ------------------------------------------------------------------
    # Enhanced query methods (Phase 2)
    # ------------------------------------------------------------------

    @staticmethod
    async def get_recent_findings(
        days: int = 7, severity: Optional[str] = None, limit: int = 100
    ) -> list[dict]:
        """Retrieve findings from the last N days, optionally filtered by severity."""
        conn = get_connection()
        query = "SELECT * FROM findings WHERE created_at >= datetime('now', ?)"
        params: list = [f"-{days} days"]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    async def get_ioc_by_value(value: str) -> Optional[dict]:
        """Look up an IOC by its value (IP, domain, hash)."""
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM iocs WHERE value = ?", (value,)
        ).fetchone()
        return dict(row) if row else None

    @staticmethod
    async def get_session_history(limit: int = 20) -> list[dict]:
        """Retrieve recent agent sessions, most recent first."""
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM agent_sessions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    async def get_database_stats() -> dict:
        """Return detailed database statistics beyond simple counts."""
        conn = get_connection()
        stats: dict = {}

        # Table counts
        tables = ["iocs", "cve_findings", "findings", "agent_sessions", "conversation_history"]
        for table in tables:
            row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
            stats[f"{table}_count"] = row["cnt"] if row else 0

        # Severity breakdown for findings
        rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        ).fetchall()
        stats["findings_by_severity"] = {r["severity"]: r["cnt"] for r in rows}

        # CVE KEV count
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM cve_findings WHERE is_kev = 1"
        ).fetchone()
        stats["kev_count"] = row["cnt"] if row else 0

        # Active IOC count
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM iocs WHERE is_active = 1"
        ).fetchone()
        stats["active_iocs"] = row["cnt"] if row else 0

        return stats

    async def save_agent_session(
        self,
        session_id: str,
        agent_name: str,
        status: str,
        findings_count: int = 0,
        execution_time_ms: int = 0,
        error_message: Optional[str] = None,
    ) -> None:
        """Insert a standalone agent session record."""
        conn = get_connection()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT OR REPLACE INTO agent_sessions
                (session_id, agent_name, status, findings_count,
                 execution_time_ms, started_at, completed_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, agent_name, status, findings_count,
             execution_time_ms, now, now, error_message),
        )
        conn.commit()

    async def update_agent_session(
        self,
        session_id: str,
        status: str,
        findings_count: int = 0,
        error_message: Optional[str] = None,
    ) -> None:
        """Update an existing agent session record."""
        conn = get_connection()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            UPDATE agent_sessions
            SET status = ?, findings_count = ?, completed_at = ?, error_message = ?
            WHERE session_id = ?
            """,
            (status, findings_count, now, error_message, session_id),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Conversation history
    # ------------------------------------------------------------------

    @staticmethod
    async def save_conversation(session_id: str, role: str, content: str,
                                agent_name: Optional[str] = None) -> None:
        """Append a message to conversation history."""
        conn = get_connection()
        conn.execute(
            """
            INSERT INTO conversation_history (session_id, role, content, agent_name)
            VALUES (?, ?, ?, ?)
            """,
            (session_id, role, content, agent_name),
        )
        conn.commit()
