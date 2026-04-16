"""JSON exporter — exports findings, reports, and agent results to JSON files.

Produces timestamped JSON files for archival and integration with external
SIEM / ticketing systems (e.g. Splunk, ServiceNow, Jira).
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import config
from core.agent_result import AgentResult

logger = logging.getLogger("cybersentinel.output.json_exporter")


class JSONExporter:
    """Exports CyberSentinel data to structured JSON files."""

    def __init__(self, output_dir: Optional[str] = None) -> None:
        self._output_dir = Path(output_dir or config.REPORT_OUTPUT_DIR)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public export methods
    # ------------------------------------------------------------------

    def export_agent_result(self, result: AgentResult, tag: Optional[str] = None) -> str:
        """Export a full AgentResult to a timestamped JSON file.

        Returns the path to the written file.
        """
        data = {
            "export_type": "agent_result",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "agent_name": result.agent_name,
            "status": result.status,
            "finding_count": result.finding_count(),
            "critical_count": result.critical_count(),
            "high_count": result.high_count(),
            "confidence": result.confidence,
            "execution_time_ms": result.execution_time_ms,
            "data_sources": result.data_sources,
            "summary": result.summary,
            "error": result.error,
            "findings": result.findings,
            "raw_data": result.raw_data,
        }

        filename = self._build_filename("result", result.agent_name, tag)
        return self._write_json(filename, data)

    def export_findings(self, findings: list[dict], tag: Optional[str] = None) -> str:
        """Export a list of findings to a timestamped JSON file.

        Returns the path to the written file.
        """
        severities: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severities[sev] = severities.get(sev, 0) + 1

        data = {
            "export_type": "findings",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "severity_breakdown": severities,
            "findings": findings,
        }

        filename = self._build_filename("findings", None, tag)
        return self._write_json(filename, data)

    def export_report(self, report_data: dict, tag: Optional[str] = None) -> str:
        """Export a generated report to a timestamped JSON file.

        Returns the path to the written file.
        """
        data = {
            "export_type": "report",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            **report_data,
        }

        report_type = report_data.get("report_type", "general")
        filename = self._build_filename("report", report_type, tag)
        return self._write_json(filename, data)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_filename(
        export_type: str,
        qualifier: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> str:
        """Build a descriptive, timestamped filename."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        parts = ["cybersentinel", export_type]
        if qualifier:
            parts.append(qualifier)
        if tag:
            parts.append(tag)
        parts.append(ts)
        return "_".join(parts) + ".json"

    def _write_json(self, filename: str, data: dict) -> str:
        """Write a dict to a JSON file and return the full path."""
        filepath = self._output_dir / filename
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str, ensure_ascii=False)

        logger.warning("Exported JSON: %s (%d bytes)", filepath, filepath.stat().st_size)
        return str(filepath)
