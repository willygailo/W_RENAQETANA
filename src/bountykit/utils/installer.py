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
    ("dalfox", "github.com/hahwul/dalfox/v2@latest"),
    ("gau", "github.com/lc/gau/v2/cmd/gau@latest"),
    ("anew", "github.com/tomnomnom/anew@latest"),
    ("waybackurls", "github.com/tomnomnom/waybackurls@latest"),
    ("qsreplace", "github.com/tomnomnom/qsreplace@latest"),
    ("hakrawler", "github.com/hakluke/hakrawler@latest"),
    ("gowitness", "github.com/sensepost/gowitness@latest"),
    ("gospider", "github.com/jaeles-project/gospider@latest"),
    ("crlfuzz", "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"),
    ("cariddi", "github.com/edoardottt/cariddi/cmd/cariddi@latest"),
    ("chaos-client", "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"),
]

PYTHON_TOOLS = [
    ("arjun", "arjun"),
    ("paramspider", "paramspider"),
    ("shodan", "shodan"),
    ("aiohttp", "aiohttp"),
    ("tenacity", "tenacity"),
    ("pydantic", "pydantic"),
    ("pyyaml", "pyyaml"),
    ("rich", "rich"),
    ("click", "click"),
    ("jinja2", "jinja2"),
    ("levenshtein", "python-Levenshtein"),
]

SYSTEM_TOOLS = [
    "nmap",
    "nikto",
    "sqlmap",
    "masscan",
    "curl",
    "jq",
]

KALI_APT_TOOLS = {
    "arjun": "arjun",
    "nmap": "nmap",
    "nikto": "nikto",
    "sqlmap": "sqlmap",
    "masscan": "masscan",
    "jq": "jq",
    "paramspider": "paramspider",
}


def _is_kali() -> bool:
    """Check if running on Kali Linux."""
    try:
        with open("/etc/os-release") as f:
            return "kali" in f.read().lower()
    except FileNotFoundError:
        return False


def _check_tool(name: str) -> bool:
    """Check if a tool is installed (binary in PATH)."""
    return shutil.which(name) is not None


def _check_pip_package(name: str) -> bool:
    """Check if a Python package is installed."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "show", name],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _install_apt_tool(package: str):
    """Install a tool via apt."""
    console.print(f"  [cyan]Installing {package} via apt...[/cyan]")
    result = subprocess.run(
        ["sudo", "apt", "install", "-y", package],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        console.print(f"  [green]✓ {package} installed via apt[/green]")
    else:
        console.print(f"  [red]✗ apt install {package} failed: {result.stderr[:150]}[/red]")


def _install_go_tool(name: str, module: str):
    """Install a Go tool."""
    console.print(f"  [cyan]Installing {name} via go install...[/cyan]")
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
    """Install a Python tool via pip."""
    console.print(f"  [cyan]Installing {name} via pip...[/cyan]")
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
    is_kali = _is_kali()
    console.print("\n[bold cyan]bountykit Setup — Checking Dependencies[/bold cyan]\n")

    if is_kali:
        console.print("[dim]Kali Linux detected — will prefer apt where available[/dim]\n")

    # Check Go
    go_available = _check_tool("go")
    if not go_available:
        console.print("[yellow]Go is not installed. Go tools will be skipped.[/yellow]")
        console.print("[dim]Install Go: https://go.dev/dl/[/dim]\n")

    # System tools — install via apt on Kali if missing
    console.print("[bold]System Tools:[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool")
    table.add_column("Status")

    for tool in SYSTEM_TOOLS:
        found = _check_tool(tool)
        if not found and is_kali and tool in KALI_APT_TOOLS:
            _install_apt_tool(KALI_APT_TOOLS[tool])
            found = _check_tool(tool)
        status = "[green]✓ Found[/green]" if found else "[red]✗ Missing[/red]"
        table.add_row(tool, status)

    console.print(table)
    console.print()

    # Go tools
    console.print("[bold]Go Tools:[/bold]")
    installed_go = 0
    skipped_go = 0
    for name, module in GO_TOOLS:
        if _check_tool(name):
            installed_go += 1
        elif go_available:
            _install_go_tool(name, module)
            if _check_tool(name):
                installed_go += 1
            else:
                skipped_go += 1
        else:
            skipped_go += 1

    console.print(f"\n  [dim]{installed_go}/{len(GO_TOOLS)} Go tools available ({skipped_go} skipped/failed)[/dim]\n")

    # Python tools — prefer apt on Kali, fall back to pip
    console.print("[bold]Python Tools:[/bold]")
    for name, package in PYTHON_TOOLS:
        if _check_tool(name) or _check_pip_package(name):
            console.print(f"  [green]✓ {name}[/green]")
            continue

        if is_kali and name in KALI_APT_TOOLS:
            _install_apt_tool(KALI_APT_TOOLS[name])

        if not (_check_tool(name) or _check_pip_package(name)):
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
