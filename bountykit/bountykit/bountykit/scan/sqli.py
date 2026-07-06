"""SQL injection testing with SQLMap."""

import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


def run_sqlmap(
    url: str,
    param: Optional[str] = None,
    dbs: bool = False,
    output_dir: str = "./results",
    level: int = 1,
    risk: int = 1,
) -> dict:
    """Run SQLMap for SQL injection testing.

    Uses safe, non-destructive payloads only.

    Args:
        url: Target URL with parameter
        param: Specific parameter to test
        dbs: Enumerate databases if True
        output_dir: Output directory
        level: Test level (1-5)
        risk: Risk level (1-3)
    """
    results = {
        "target": url,
        "tool": "sqlmap",
        "vulnerable": False,
        "injections": [],
        "databases": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",
        "--random-agent",
        f"--level={level}",
        f"--risk={risk}",
        "--timeout=10",
        "--retries=2",
        "--threads=5",
    ]

    if param:
        cmd.extend(["-p", param])

    if dbs:
        cmd.append("--dbs")

    console.print(f"  [dim]Running SQLMap against {url}...[/dim]")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        output = result.stdout + result.stderr

        # Check for injection points
        if "is vulnerable" in output.lower() or "injectable" in output.lower():
            results["vulnerable"] = True
            console.print("  [bold red]⚠ SQL injection found![/bold red]")

            # Parse injection info
            for line in output.splitlines():
                if "type:" in line.lower() or "payload:" in line.lower():
                    results["injections"].append(line.strip())

        # Parse databases
        if dbs and "available databases" in output.lower():
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("[*]"):
                    db_name = line.replace("[*]", "").strip()
                    if db_name:
                        results["databases"].append(db_name)

        if not results["vulnerable"]:
            console.print("  [green]✓ SQLMap: No SQL injection found[/green]")
        else:
            console.print(f"  [red]Found {len(results['injections'])} injection points[/red]")

    except FileNotFoundError:
        console.print("  [red]SQLMap is not installed. Run: bountykit setup[/red]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]SQLMap scan timed out[/yellow]")

    # Save results
    output_file = Path(output_dir) / "sqlmap_results.json"
    with open(output_file, "w") as f:
        import json
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results
