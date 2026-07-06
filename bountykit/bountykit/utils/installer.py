"""Tool dependency installer and checker."""

import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()

GO_TOOLS = [
    ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("katana", "github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ("dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ("interactsh-client", "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    ("ffuf", "github.com/ffuf/ffuf/v2@latest"),
    ("dalfox", "github.com/s0md3v/dalfox@latest"),
    ("gau", "github.com/lc/gau/v2/cmd/gau@latest"),
    ("anew", "github.com/tomnomnom/anew@latest"),
    ("waybackurls", "github.com/tomnomnom/waybackurls@latest"),
    ("qsreplace", "github.com/tomnomnom/qsreplace@latest"),
    ("hakrawler", "github.com/hakluke/hakrawler@latest"),
    ("gowitness", "github.com/sensepost/gowitness@latest"),
    ("feroxbuster", "https://github.com/epi052/feroxbuster/releases/latest"),
    ("kiterunner", "github.com/assetnote/kiterunner/cmd/kr@latest"),
    ("gospider", "github.com/jaeles-project/gospider@latest"),
]

PYTHON_TOOLS = [
    ("arjun", "arjun"),
    ("trufflehog", "trufflehog"),
    ("shodan", "shodan"),
    ("graphql-cop", "graphql_cop"),
    ("paramspider", "paramspider"),
]

SYSTEM_TOOLS = [
    "nmap",
    "nikto",
    "sqlmap",
    "masscan",
    "curl",
    "jq",
]


def _check_tool(name: str) -> bool:
    """Check if a tool is installed."""
    return shutil.which(name) is not None


def _install_go_tool(name: str, module: str):
    """Install a Go tool."""
    console.print(f"  [cyan]Installing {name}...[/cyan]")
    result = subprocess.run(
        ["go", "install", module],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        console.print(f"  [green]✓ {name} installed[/green]")
    else:
        console.print(f"  [red]✗ {name} failed: {result.stderr[:100]}[/red]")


def _install_python_tool(name: str, package: str):
    """Install a Python tool."""
    console.print(f"  [cyan]Installing {name}...[/cyan]")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--break-system-packages", package],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        console.print(f"  [green]✓ {name} installed[/green]")
    else:
        console.print(f"  [red]✗ {name} failed: {result.stderr[:100]}[/red]")


def run_setup():
    """Check and install all required dependencies."""
    console.print("\n[bold cyan]bountykit Setup — Checking Dependencies[/bold cyan]\n")

    # Check Go
    go_available = _check_tool("go")
    if not go_available:
        console.print("[yellow]Go is not installed. Go tools will be skipped.[/yellow]")
        console.print("[dim]Install Go: https://go.dev/dl/[/dim]\n")

    # System tools
    console.print("[bold]System Tools:[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool")
    table.add_column("Status")

    for tool in SYSTEM_TOOLS:
        found = _check_tool(tool)
        status = "[green]✓ Found[/green]" if found else "[red]✗ Missing[/red]"
        table.add_row(tool, status)

    console.print(table)
    console.print()

    # Go tools
    console.print("[bold]Go Tools:[/bold]")
    installed = 0
    for name, module in GO_TOOLS:
        if _check_tool(name):
            installed += 1
        elif go_available:
            _install_go_tool(name, module)
            installed += 1

    console.print(f"\n  [dim]{installed}/{len(GO_TOOLS)} Go tools available[/dim]\n")

    # Python tools
    console.print("[bold]Python Tools:[/bold]")
    for name, package in PYTHON_TOOLS:
        if _check_tool(name):
            console.print(f"  [green]✓ {name}[/green]")
        else:
            _install_python_tool(name, package)

    # Nuclei templates
    console.print("\n[bold]Nuclei Templates:[/bold]")
    templates_path = Path.home() / ".bountykit" / "nuclei-templates"
    if templates_path.exists():
        console.print(f"  [green]✓ Templates found at {templates_path}[/green]")
    else:
        console.print("  [cyan]Downloading nuclei templates...[/cyan]")
        result = subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            console.print("  [green]✓ Templates downloaded[/green]")
        else:
            console.print("  [yellow]Templates download skipped (nuclei not found)[/yellow]")

    console.print("\n[bold green]Setup complete![/bold green]\n")
