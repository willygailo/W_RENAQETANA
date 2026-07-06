"""Endpoint discovery module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 4:
- Arjun for parameter discovery
- ParamSpider for parameter mining
- Waybackurls for historical endpoint discovery
- Gau for endpoint collection
"""

import json
import os
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()


def discover_wayback_urls(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Discover historical URLs via Wayback Machine.

    Uses waybackurls to fetch archived URLs from the Wayback Machine.

    Args:
        target: Target domain
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "waybackurls",
        "urls": [],
        "total": 0,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Querying Wayback Machine for {target}...[/dim]")

    try:
        # Try gau first (faster, includes wayback)
        cmd = ["gau", target, "--threads", "5", "--silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        if result.returncode == 0:
            urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
            results["urls"] = urls
            results["total"] = len(urls)
            console.print(f"  [green]✓ Found {len(urls)} historical URLs via gau[/green]")
        else:
            raise FileNotFoundError("gau failed")

    except FileNotFoundError:
        # Fallback to waybackurls
        try:
            cmd = f'echo "{target}" | waybackurls'
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=180,
            )
            if result.returncode == 0:
                urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
                results["urls"] = urls
                results["total"] = len(urls)
                console.print(f"  [green]✓ Found {len(urls)} historical URLs via waybackurls[/green]")
            else:
                console.print("  [yellow]waybackurls failed[/yellow]")
        except Exception as e:
            console.print(f"  [yellow]Wayback tools not available: {e}[/yellow]")

    except subprocess.TimeoutExpired:
        console.print("  [yellow]gau timed out[/yellow]")

    # Filter interesting URLs
    results["interesting"] = [
        u for u in results["urls"]
        if any(p in u.lower() for p in [
            "admin", "login", "api", "upload", "backup", "config",
            "debug", "test", "dev", "staging", ".env", "git",
            "wp-admin", "phpmyadmin", "console", "swagger",
        ])
    ]

    if results["interesting"]:
        console.print(f"  [bold cyan]📋 {len(results['interesting'])} interesting URLs found[/bold cyan]")

    # Save results
    output_file = Path(output_dir) / "wayback_urls.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def discover_parameters(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Discover hidden parameters using Arjun.

    Args:
        target: Target URL with parameter placeholder
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "arjun",
        "parameters": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Discovering parameters with Arjun...[/dim]")

    try:
        cmd = ["arjun", "-u", target, "-oJ", "-", "--silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict) and "parameters" in data:
                    results["parameters"] = data["parameters"]
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "parameters" in item:
                            results["parameters"].extend(item["parameters"])
            except json.JSONDecodeError:
                # Try line-by-line parsing
                for line in result.stdout.splitlines():
                    try:
                        data = json.loads(line)
                        if "parameters" in data:
                            results["parameters"].extend(data["parameters"])
                    except json.JSONDecodeError:
                        continue

            results["parameters"] = list(set(results["parameters"]))
            console.print(f"  [green]✓ Found {len(results['parameters'])} parameters[/green]")

            if results["parameters"]:
                for p in results["parameters"][:20]:
                    console.print(f"    [cyan]{p}[/cyan]")

    except FileNotFoundError:
        console.print("  [yellow]Arjun not installed — run: pip install arjun[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]Arjun timed out[/yellow]")

    # Save results
    output_file = Path(output_dir) / "parameters.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def mine_paramspider(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Mine parameters using ParamSpider.

    Args:
        target: Target domain
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "paramspider",
        "urls_with_params": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Mining parameters with ParamSpider...[/dim]")

    try:
        cmd = ["paramspider", "-d", target, "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
            results["urls_with_params"] = urls
            console.print(f"  [green]✓ Found {len(urls)} URLs with parameters[/green]")
        else:
            console.print("  [yellow]ParamSpider returned non-zero exit code[/yellow]")

    except FileNotFoundError:
        console.print("  [yellow]ParamSpider not installed — run: pip install paramspider[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]ParamSpider timed out[/yellow]")

    # Save results
    output_file = Path(output_dir) / "paramspider.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def discover_all_endpoints(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Run all endpoint discovery tools and merge results.

    Runs waybackurls, gau, and ParamSpider to collect all
    known endpoints for the target.

    Args:
        target: Target domain
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "combined_endpoints",
        "wayback": {},
        "paramspider": {},
        "total_unique": 0,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"[bold]  Running combined endpoint discovery for {target}[/bold]")

    # Run wayback
    results["wayback"] = discover_wayback_urls(target, output_dir)

    # Run paramspider
    results["paramspider"] = mine_paramspider(target, output_dir)

    # Merge and deduplicate
    all_urls = set()
    all_urls.update(results["wayback"].get("urls", []))
    all_urls.update(results["paramspider"].get("urls_with_params", []))
    results["total_unique"] = len(all_urls)

    # Save merged results
    merged_file = Path(output_dir) / "all_endpoints.json"
    with open(merged_file, "w") as f:
        json.dump({
            "target": target,
            "total_unique": results["total_unique"],
            "urls": sorted(all_urls),
        }, f, indent=2)

    console.print(f"[bold green]  ✓ Total unique endpoints: {results['total_unique']}[/bold green]")
    console.print(f"  [dim]Merged results saved to {merged_file}[/dim]")

    return results
