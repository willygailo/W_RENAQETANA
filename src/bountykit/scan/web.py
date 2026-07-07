"""Web vulnerability scanning with Nuclei."""

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


def run_nuclei(
    target: str,
    severity: str = "medium,high,critical",
    rate_limit: int = 50,
    output_dir: str = "./results",
    templates: Optional[str] = None,
) -> dict:
    """Run Nuclei scanner against a target.

    Args:
        target: Target URL to scan
        severity: Severity filter (comma-separated)
        rate_limit: Requests per second
        output_dir: Output directory
        templates: Custom templates path
    """
    results = {
        "target": target,
        "tool": "nuclei",
        "severity_filter": severity,
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        "nuclei",
        "-u", target,
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-json",
        "-silent",
        "-timeout", "10",
    ]

    if templates:
        cmd.extend(["-t", templates])

    console.print(f"  [dim]Running nuclei against {target} (severity: {severity})...[/dim]")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    findings = {
                        "template_id": data.get("template-id", ""),
                        "severity": data.get("info", {}).get("severity", "unknown"),
                        "name": data.get("info", {}).get("name", ""),
                        "matched": data.get("matched-at", ""),
                        "type": data.get("type", ""),
                        "matcher_name": data.get("matcher-name", ""),
                    }
                    results["findings"].append(findings)
                except json.JSONDecodeError:
                    continue

            console.print(f"  [green]✓ Nuclei found {len(results['findings'])} issues[/green]")
        else:
            console.print("  [yellow]Nuclei: no findings[/yellow]")

    except FileNotFoundError:
        console.print("  [red]Nuclei is not installed. Run: bountykit setup[/red]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]Nuclei scan timed out[/yellow]")

    # Save results
    output_file = Path(output_dir) / f"{target.replace('://', '_')}_nuclei.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results
