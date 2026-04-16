"""JSON exporter — exports findings and reports as structured JSON files.

Phase 3 placeholder. Will export AgentResults, session summaries, and
full investigation reports to timestamped JSON files for archival and
integration with external SIEM / ticketing systems.
"""


class JSONExporter:
    """Exports findings and reports to JSON files."""

    async def export_findings(self, findings: list[dict], output_path: str) -> str:
        """Export findings list to a JSON file."""
        raise NotImplementedError("JSONExporter is planned for Phase 3.")
