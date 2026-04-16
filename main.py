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

    # test-exa — standalone Exa API connectivity test
    te = sub.add_parser("test-exa", help="Test Exa API key and connection directly")
    te.add_argument(
        "query",
        nargs="?",
        default="CVE-2024-38094 vulnerability analysis",
        help="Search query (default: CVE-2024-38094 vulnerability analysis)",
    )

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


async def cmd_test_exa(query: str) -> int:
    """Run a standalone Exa API search and print raw results."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    from integrations.exa_client import ExaClient

    console = Console()

    # --- Step 1: Show config diagnostics ---
    console.print()
    diag = Table(
        title="Exa Configuration Diagnostics",
        box=box.ROUNDED,
        header_style="bold",
        show_lines=True,
    )
    diag.add_column("Check", style="bold")
    diag.add_column("Value")
    diag.add_column("Status")

    key_raw = config.EXA_API_KEY
    if key_raw:
        masked = key_raw[:4] + "..." + key_raw[-4:] if len(key_raw) > 8 else "****"
        key_status = "[bold green]LOADED[/bold green]"
    else:
        masked = "(empty)"
        key_status = "[bold red]MISSING[/bold red]"
    diag.add_row("EXA_API_KEY", masked, key_status)
    diag.add_row("EXA_BASE_URL", config.EXA_BASE_URL, "[green]OK[/green]")
    diag.add_row("EXA_SEARCH_TYPE", config.EXA_SEARCH_TYPE, "[green]OK[/green]")
    diag.add_row("EXA_NUM_RESULTS", str(config.EXA_NUM_RESULTS), "[green]OK[/green]")
    diag.add_row(
        "USE_MOCK_LLM",
        str(config.USE_MOCK_LLM),
        "[dim](does not affect Exa — Exa always uses real API)[/dim]",
    )
    console.print(diag)

    if not key_raw:
        console.print(
            "\n[bold red]ERROR:[/bold red] EXA_API_KEY is empty. "
            "Add it to your .env file:\n"
            "  EXA_API_KEY=your-key-here\n"
        )
        return 1

    # --- Step 2: Create client and check enabled state ---
    client = ExaClient()
    console.print(f"\n  Client enabled: [bold]{'YES' if client.enabled else 'NO'}[/bold]")

    if not client.enabled:
        console.print("[bold red]Client is disabled even though key is set. Check logs.[/bold red]")
        return 1

    # --- Step 3: Run the search ---
    console.print(f"\n  Searching Exa for: [cyan]{query}[/cyan]\n")

    results = await client.search_cve(query) if query.startswith("CVE-") else []
    if not results:
        # Fall back to general _search if search_cve returned empty or query is not a CVE
        results = await client._search(query=query, num_results=config.EXA_NUM_RESULTS)

    # --- Step 4: Print results ---
    if not results:
        console.print(
            Panel(
                "[yellow]No results returned.[/yellow]\n\n"
                "Possible causes:\n"
                "  1. API key is invalid → check dashboard.exa.ai/api-keys\n"
                "  2. Query returned zero matches\n"
                "  3. Network / firewall issue\n\n"
                "Check cybersentinel.log for full HTTP request/response details.",
                title="[bold yellow]Exa Search: 0 Results[/bold yellow]",
                border_style="yellow",
            )
        )
        return 1

    table = Table(
        title=f"Exa Search Results ({len(results)} found)",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on dark_blue",
    )
    table.add_column("#", width=3, justify="right")
    table.add_column("Score", width=6, justify="center")
    table.add_column("Title", max_width=50)
    table.add_column("URL", max_width=55)
    table.add_column("Published", width=12)

    for i, r in enumerate(results, 1):
        pub = r.published_date[:10] if r.published_date else "—"
        table.add_row(
            str(i),
            f"{r.score:.2f}",
            r.title[:50] if r.title else "—",
            r.url[:55] if r.url else "—",
            pub,
        )

    console.print(table)

    # Print highlights from the first result for quick verification
    if results[0].highlights:
        console.print(
            Panel(
                results[0].highlights[0][:500],
                title=f"[bold]Top Highlight — {results[0].title[:40]}[/bold]",
                border_style="cyan",
            )
        )

    console.print(f"\n  [bold green]Exa API is working.[/bold green] "
                  f"{len(results)} results returned.\n")
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
    elif args.command == "test-exa":
        exit_code = asyncio.run(cmd_test_exa(args.query))
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
