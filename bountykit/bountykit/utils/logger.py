"""Logging and output formatting utilities."""

import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

console = Console()

THEME = Theme({
    "info": "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "target": "bold magenta",
    "vuln": "bold red",
})


def setup_logger(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure the application logger with rich output."""
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)

    handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )

    formatter = logging.Formatter("%(message)s", datefmt="[%X]")
    handler.setFormatter(formatter)

    logger = logging.getLogger("bountykit")
    logger.setLevel(level)

    if not logger.handlers:
        logger.addHandler(handler)

    return logger


def log_findings(findings: list, title: str = "Findings"):
    """Display scan findings in a structured format."""
    if not findings:
        console.print("[dim]No findings detected.[/dim]")
        return

    from rich.table import Table

    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("Detail")
    table.add_column("URL")

    for f in findings:
        severity = f.get("severity", "info")
        style_map = {
            "critical": "[bold red]CRITICAL[/bold red]",
            "high": "[red]HIGH[/red]",
            "medium": "[yellow]MEDIUM[/yellow]",
            "low": "[blue]LOW[/blue]",
            "info": "[dim]INFO[/dim]",
        }
        table.add_row(
            style_map.get(severity, severity),
            f.get("type", "unknown"),
            f.get("detail", "")[:60],
            f.get("url", ""),
        )

    console.print(table)


def log_recon(target: str, phase: str, status: str):
    """Log reconnaissance phase progress."""
    icon = {"running": "⟳", "done": "✓", "error": "✗"}.get(status, "•")
    console.print(f"  {icon} [{phase}] {target}")
