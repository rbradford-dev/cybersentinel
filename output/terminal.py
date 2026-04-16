"""Rich terminal output — every user-facing print goes through this module."""

from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich import box

import config

console = Console()

BANNER_UNICODE = r"""
 ██████╗██╗   ██╗██████╗ ███████╗██████╗     ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
"""

# ASCII-safe fallback for Windows legacy consoles (cp1252)
BANNER_ASCII = r"""
  ______   __  __  ____    ______  ____       _____  ______  __  __  ______  ____  __  __  ______  __
 / ____/  / / / / / __ )  / ____/ / __ \     / ___/ / ____/ / | / / /_  __/ / _/ / | / / / ____/ / /
/ /      / /_/ / / __  | / __/   / /_/ /     \__ \ / __/   /  |/ /   / /    / / /  |/ / / __/   / /
/ /___  / __  / / /_/ / / /___  / _, _/     ___/ // /___  / /|  /   / /   _/ / / /|  / / /___  / /___
\____/  /_/ /_/ /_____/ /_____/ /_/ |_|     /____//_____/ /_/ |_/   /_/   /___//_/ |_/ /_____/ /_____/
"""


def _pick_banner() -> str:
    """Return the Unicode banner if the terminal supports it, else ASCII."""
    try:
        BANNER_UNICODE.encode(console.file.encoding or "utf-8")
        return BANNER_UNICODE
    except (UnicodeEncodeError, LookupError):
        return BANNER_ASCII

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "white",
}


class TerminalOutput:
    """Static methods for all Rich terminal output."""

    @staticmethod
    def print_banner() -> None:
        """Print the CyberSentinel ASCII art banner with status info."""
        mode = "[MOCK MODE]" if config.USE_MOCK_LLM else "[LIVE MODE]"
        mode_style = "dim yellow" if config.USE_MOCK_LLM else "bold green"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        header = Text(_pick_banner(), style="bold red")
        info_line = Text()
        info_line.append(f"  v{config.VERSION}", style="dim white")
        info_line.append("  |  ", style="dim")
        info_line.append(mode, style=mode_style)
        info_line.append("  |  ", style="dim")
        info_line.append(now, style="dim white")
        info_line.append("  |  ", style="dim")
        info_line.append(f"Model: {config.ORCHESTRATOR_MODEL}", style="dim white")

        panel = Panel(
            header + Text("\n") + info_line,
            border_style="dark_red",
            box=box.HEAVY,
            padding=(0, 1),
        )
        console.print(panel)

    @staticmethod
    def print_routing_decision(routing: "RoutingDecision") -> None:
        """Display the router's classification decision."""
        from core.router import RoutingDecision  # noqa: F811

        content = Text()
        content.append("Intent:  ", style="bold")
        content.append(routing.intent, style="bold cyan")
        content.append("\nAgents:  ", style="bold")
        content.append(", ".join(routing.target_agents), style="cyan")
        if routing.extracted_entities:
            content.append("\nEntities: ", style="bold")
            for key, val in routing.extracted_entities.items():
                content.append(f"\n  {key}: ", style="dim")
                content.append(str(val), style="white")
        content.append(f"\nConfidence: ", style="bold")
        conf = routing.confidence
        conf_style = "green" if conf >= 0.8 else ("yellow" if conf >= 0.5 else "red")
        content.append(f"{conf:.0%}", style=conf_style)
        content.append(f"\nReasoning: ", style="bold")
        content.append(routing.reasoning, style="dim")

        if config.USE_MOCK_LLM:
            content.append("\n")
            content.append("[MOCK MODE]", style="dim yellow")

        panel = Panel(
            content,
            title="[bold]Routing Decision[/bold]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1),
        )
        console.print(panel)

    @staticmethod
    def print_agent_start(agent_name: str, task_summary: str) -> None:
        """Print agent start indicator."""
        text = Text()
        text.append("  ⟳ ", style="bold cyan")
        text.append(f"[{agent_name}]", style="bold")
        text.append(f" Starting — {task_summary[:80]}", style="dim")
        console.print(text)

    @staticmethod
    def print_agent_complete(result: "AgentResult") -> None:
        """Print agent completion status."""
        from core.agent_result import AgentResult  # noqa: F811

        status_icons = {
            "success": ("✓", "bold green"),
            "partial": ("⚠", "bold yellow"),
            "error": ("✗", "bold red"),
            "no_data": ("○", "dim"),
        }
        icon, style = status_icons.get(result.status, ("?", "dim"))

        text = Text()
        text.append(f"  {icon} ", style=style)
        text.append(f"[{result.agent_name}]", style="bold")
        text.append(f" {result.status}", style=style)
        text.append(f" | {result.finding_count()} findings", style="white")
        text.append(f" | {result.execution_time_ms}ms", style="dim")
        if result.data_sources:
            text.append(f" | sources: {', '.join(result.data_sources)}", style="dim")
        console.print(text)

    @staticmethod
    def print_findings_table(findings: list[dict]) -> None:
        """Print a Rich table of all findings."""
        table = Table(
            title="Findings",
            box=box.SIMPLE_HEAVY,
            show_lines=True,
            title_style="bold",
            header_style="bold white on dark_red",
            padding=(0, 1),
        )

        table.add_column("Severity", width=10, justify="center")
        table.add_column("CVE ID", width=18)
        table.add_column("Title", max_width=50)
        table.add_column("CVSS", width=6, justify="center")
        table.add_column("KEV", width=6, justify="center")
        table.add_column("Confidence", width=10, justify="center")

        for f in findings:
            sev = f.get("severity", "info")
            sev_style = SEVERITY_STYLES.get(sev, "white")

            cvss = f.get("cvss_score")
            cvss_str = f"{cvss:.1f}" if cvss is not None else "—"

            is_kev = f.get("is_kev", False)
            kev_str = Text("YES", style="bold red") if is_kev else Text("—", style="dim")

            conf = f.get("confidence", 0.0)
            conf_str = f"{conf:.0%}"

            title = f.get("title", "")
            if len(title) > 50:
                title = title[:47] + "..."

            table.add_row(
                Text(sev.upper(), style=sev_style),
                f.get("cve_id", "—"),
                title,
                cvss_str,
                kev_str,
                conf_str,
            )

        console.print()
        console.print(table)

    @staticmethod
    def print_orchestrator_summary(
        summary: str,
        total_findings: int,
        critical_count: int,
        high_count: int,
    ) -> None:
        """Print the final synthesis panel."""
        content = Text()
        content.append(summary, style="white")
        content.append("\n\n")
        content.append("Total findings: ", style="bold")
        content.append(str(total_findings), style="bold white")
        if critical_count > 0:
            content.append("  |  Critical: ", style="bold")
            content.append(str(critical_count), style="bold red")
        if high_count > 0:
            content.append("  |  High: ", style="bold")
            content.append(str(high_count), style="red")

        panel = Panel(
            content,
            title="[bold]Orchestrator Summary[/bold]",
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 2),
        )
        console.print()
        console.print(panel)

    @staticmethod
    def print_mock_indicator() -> None:
        """Print a subtle mock-mode badge."""
        if config.USE_MOCK_LLM:
            console.print("  [dim yellow][MOCK MODE] All LLM responses are simulated[/dim yellow]")

    @staticmethod
    def print_error(agent_name: str, error: str) -> None:
        """Print an error panel."""
        content = Text()
        content.append(f"Agent: {agent_name}\n", style="bold")
        content.append(error, style="white")

        panel = Panel(
            content,
            title="[bold red]Error[/bold red]",
            border_style="red",
            box=box.ROUNDED,
            padding=(0, 1),
        )
        console.print(panel)

    @staticmethod
    def print_db_save_confirmation(table: str, record_count: int) -> None:
        """Print a subtle database save confirmation."""
        console.print(
            f"  [dim green]✓ Saved {record_count} record(s) to {table}[/dim green]"
        )

    @staticmethod
    def print_progress_bar(description: str, total: int) -> Progress:
        """Return a Rich Progress context manager."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        )

    @staticmethod
    def print_parallel_dispatch(agent_names: list[str]) -> None:
        """Print a notice that multiple agents are being dispatched in parallel."""
        text = Text()
        text.append("  ⟴ ", style="bold magenta")
        text.append("Parallel dispatch: ", style="bold")
        text.append(", ".join(agent_names), style="cyan")
        console.print(text)

    @staticmethod
    def print_ioc_table(findings: list[dict]) -> None:
        """Print a Rich table of IOC findings."""
        table = Table(
            title="Threat Intelligence — IOC Enrichment",
            box=box.SIMPLE_HEAVY,
            show_lines=True,
            title_style="bold",
            header_style="bold white on dark_red",
            padding=(0, 1),
        )

        table.add_column("Severity", width=10, justify="center")
        table.add_column("IOC", width=20)
        table.add_column("Type", width=10)
        table.add_column("Title", max_width=45)
        table.add_column("Confidence", width=10, justify="center")

        for f in findings:
            sev = f.get("severity", "info")
            sev_style = SEVERITY_STYLES.get(sev, "white")
            ioc_value = f.get("cve_id", f.get("affected_asset", "—"))
            ioc_type = f.get("finding_type", "threat_intel")

            conf = f.get("confidence", 0.0)
            conf_str = f"{conf:.0%}"

            title = f.get("title", "")
            if len(title) > 45:
                title = title[:42] + "..."

            table.add_row(
                Text(sev.upper(), style=sev_style),
                str(ioc_value),
                ioc_type,
                title,
                conf_str,
            )

        console.print()
        console.print(table)

    @staticmethod
    def print_log_findings_table(findings: list[dict]) -> None:
        """Print a Rich table of log analysis findings."""
        table = Table(
            title="Log Analysis — Anomaly Detection",
            box=box.SIMPLE_HEAVY,
            show_lines=True,
            title_style="bold",
            header_style="bold white on dark_red",
            padding=(0, 1),
        )

        table.add_column("Severity", width=10, justify="center")
        table.add_column("Type", width=20)
        table.add_column("Title", max_width=50)
        table.add_column("MITRE", width=15)
        table.add_column("Confidence", width=10, justify="center")

        for f in findings:
            sev = f.get("severity", "info")
            sev_style = SEVERITY_STYLES.get(sev, "white")

            mitre = ", ".join(f.get("mitre_techniques", [])[:3]) or "—"

            conf = f.get("confidence", 0.0)
            conf_str = f"{conf:.0%}"

            title = f.get("title", "")
            if len(title) > 50:
                title = title[:47] + "..."

            table.add_row(
                Text(sev.upper(), style=sev_style),
                f.get("finding_type", "log_anomaly"),
                title,
                mitre,
                conf_str,
            )

        console.print()
        console.print(table)

    @staticmethod
    def print_report_summary(report_data: dict) -> None:
        """Print a Rich panel summarizing a generated report."""
        content = Text()
        content.append(report_data.get("report_title", "Security Report"), style="bold white")
        content.append(f"\nType: ", style="bold")
        content.append(report_data.get("report_type", "executive"), style="cyan")
        content.append(f"\nRisk Rating: ", style="bold")

        risk = report_data.get("risk_rating", "UNKNOWN")
        risk_style = "bold red" if risk in ("CRITICAL", "HIGH") else "yellow"
        content.append(risk, style=risk_style)

        exec_summary = report_data.get("executive_summary", "")
        if exec_summary:
            content.append(f"\n\n{exec_summary}", style="white")

        key_findings = report_data.get("key_findings", [])
        if key_findings:
            content.append("\n\nKey Findings:", style="bold")
            for kf in key_findings[:5]:
                content.append(f"\n  • {kf}", style="white")

        recommendations = report_data.get("recommendations", [])
        if recommendations:
            content.append("\n\nRecommendations:", style="bold")
            for rec in recommendations[:5]:
                content.append(f"\n  → {rec}", style="dim white")

        panel = Panel(
            content,
            title="[bold]Generated Report[/bold]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(1, 2),
        )
        console.print()
        console.print(panel)

    @staticmethod
    def print_export_confirmation(file_path: str, record_count: int) -> None:
        """Print a confirmation that data was exported to a file."""
        console.print(
            f"  [bold green]✓ Exported {record_count} record(s) to {file_path}[/bold green]"
        )

    @staticmethod
    def print_status_summary(summary: dict) -> None:
        """Print a database status summary table."""
        table = Table(
            title="Database Status",
            box=box.ROUNDED,
            header_style="bold white on dark_blue",
            padding=(0, 1),
        )
        table.add_column("Table", style="bold")
        table.add_column("Records", justify="right")

        for table_name, count in summary.items():
            table.add_row(table_name, str(count))

        console.print()
        console.print(table)
