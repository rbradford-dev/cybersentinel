"""CyberSentinel CLI entry point."""

import argparse
import asyncio
import sys

import config
from utils.logger import setup_logging
from output.terminal import TerminalOutput as term


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="cybersentinel",
        description="CyberSentinel — Multi-Agent Cybersecurity AI System",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # query — natural language
    q = sub.add_parser("query", help="Natural language security query")
    q.add_argument("text", type=str, help="The query in plain English")

    # cve — direct CVE lookup
    c = sub.add_parser("cve", help="Look up a specific CVE by ID")
    c.add_argument("cve_id", type=str, help="CVE identifier (e.g. CVE-2024-38094)")

    # scan — recent critical CVEs
    s = sub.add_parser("scan", help="Scan for recent critical vulnerabilities")
    s.add_argument("--days", type=int, default=7, help="Look-back window in days (default: 7)")
    s.add_argument("--cvss-min", type=float, default=9.0, help="Minimum CVSS score (default: 9.0)")

    # kev — CISA KEV recent additions
    k = sub.add_parser("kev", help="Show recent CISA KEV additions")
    k.add_argument("--days", type=int, default=30, help="Look-back window in days (default: 30)")

    # status — database summary
    sub.add_parser("status", help="Show database record counts")

    # interactive — Phase 2 placeholder
    sub.add_parser("interactive", help="Interactive session (Phase 2)")

    return parser


async def cmd_query(text: str) -> int:
    """Handle a natural language query."""
    from core.orchestrator import Orchestrator

    orch = Orchestrator()
    result = await orch.handle(text)
    return 0 if result.status in ("success", "partial") else 1


async def cmd_cve(cve_id: str) -> int:
    """Handle a direct CVE lookup."""
    from core.orchestrator import Orchestrator

    orch = Orchestrator()
    result = await orch.handle_cve(cve_id)
    return 0 if result.status in ("success", "partial") else 1


async def cmd_scan(days: int, cvss_min: float) -> int:
    """Handle a vulnerability scan."""
    from core.orchestrator import Orchestrator

    orch = Orchestrator()
    result = await orch.handle_scan(days=days, cvss_min=cvss_min)
    return 0 if result.status in ("success", "partial") else 1


async def cmd_kev(days: int) -> int:
    """Handle a KEV listing."""
    from core.orchestrator import Orchestrator

    orch = Orchestrator()
    result = await orch.handle_kev(days=days)
    return 0 if result.status in ("success", "partial") else 1


async def cmd_status() -> int:
    """Show database status."""
    from db.repository import Repository

    repo = Repository()
    summary = await repo.get_db_summary()
    term.print_status_summary(summary)
    return 0


def main() -> None:
    """Main entry point."""
    setup_logging()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    term.print_banner()
    term.print_mock_indicator()

    exit_code: int

    if args.command == "query":
        exit_code = asyncio.run(cmd_query(args.text))
    elif args.command == "cve":
        exit_code = asyncio.run(cmd_cve(args.cve_id))
    elif args.command == "scan":
        exit_code = asyncio.run(cmd_scan(args.days, args.cvss_min))
    elif args.command == "kev":
        exit_code = asyncio.run(cmd_kev(args.days))
    elif args.command == "status":
        exit_code = asyncio.run(cmd_status())
    elif args.command == "interactive":
        from rich import print as rprint
        rprint("[yellow]Interactive mode is planned for Phase 2.[/yellow]")
        exit_code = 0
    else:
        parser.print_help()
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
