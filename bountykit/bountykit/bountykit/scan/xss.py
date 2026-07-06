"""XSS vulnerability testing with Dalfox."""

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


def run_dalfox(
    url: str,
    param: str = "q",
    output_dir: str = "./results",
    blind_url: Optional[str] = None,
) -> dict:
    """Run Dalfox for XSS vulnerability testing.

    Args:
        url: Target URL with parameter
        param: Parameter to test
        output_dir: Output directory
        blind_url: Blind XSS callback URL
    """
    results = {
        "target": url,
        "tool": "dalfox",
        "vulnerable": False,
        "xss_found": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        "dalfox", "url", url,
        "-p", param,
        "--silence",
        "--format", "json",
    ]

    if blind_url:
        cmd.extend(["--blind", blind_url])

    console.print(f"  [dim]Running Dalfox XSS scan on {url} (param: {param})...[/dim]")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    if data.get("type") == "XSS" or "poc" in str(data).lower():
                        results["vulnerable"] = True
                        results["xss_found"].append({
                            "param": data.get("param", param),
                            "payload": data.get("payload", ""),
                            "poc": data.get("poc", ""),
                            "type": data.get("type", "reflected"),
                        })
                except json.JSONDecodeError:
                    if "xss" in line.lower() or "poc" in line.lower():
                        results["vulnerable"] = True
                        results["xss_found"].append({"raw": line.strip()})

        if results["vulnerable"]:
            console.print(f"  [bold red]⚠ Found {len(results['xss_found'])} XSS vulnerabilities![/bold red]")
        else:
            console.print("  [green]✓ Dalfox: No XSS found[/green]")

    except FileNotFoundError:
        console.print("  [red]Dalfox is not installed. Run: bountykit setup[/red]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]Dalfox scan timed out[/yellow]")

    # Save results
    output_file = Path(output_dir) / "dalfox_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results
