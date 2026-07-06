"""Web crawler module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 3:
- Katana for deep crawling
- Gospider for link and form discovery
- Crawl4AI for AI-assisted crawling
"""

import json
import os
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()


def crawl_katana(
    target: str,
    depth: int = 3,
    output_dir: str = "./results",
) -> dict:
    """Crawl target using Katana crawler.

    Args:
        target: Target URL
        depth: Crawl depth
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "katana",
        "urls": [],
        "total": 0,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Crawling {target} with Katana (depth={depth})...[/dim]")

    try:
        cmd = [
            "katana", "-u", target,
            "-d", str(depth),
            "-jc",
            "-silent",
            "-timeout", "10",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
            results["urls"] = urls
            results["total"] = len(urls)
            console.print(f"  [green]✓ Crawled {len(urls)} URLs[/green]")
        else:
            console.print("  [yellow]Katana returned errors — check if installed[/yellow]")

    except FileNotFoundError:
        console.print("  [yellow]Katana not installed — run: go install github.com/projectdiscovery/katana/cmd/katana@latest[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]Katana timed out (300s limit)[/yellow]")

    # Save results
    output_file = Path(output_dir) / "katana_crawl.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def crawl_gospider(
    target: str,
    depth: int = 3,
    output_dir: str = "./results",
) -> dict:
    """Crawl target using Gospider.

    Args:
        target: Target URL
        depth: Crawl depth
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "gospider",
        "urls": [],
        "forms": [],
        "links": [],
        "total": 0,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Crawling {target} with Gospider...[/dim]")

    try:
        cmd = [
            "gospider",
            "-s", target,
            "-d", str(depth),
            "-c", "5",
            "--sitemap",
            "--robots",
            "--other-source",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("[url]"):
                    results["urls"].append(line[5:].strip())
                elif line.startswith("[form]"):
                    results["forms"].append(line[6:].strip())
                elif line.startswith("[link]"):
                    results["links"].append(line[6:].strip())

            results["total"] = len(results["urls"])
            console.print(
                f"  [green]✓ Found {results['total']} URLs, "
                f"{len(results['forms'])} forms, "
                f"{len(results['links'])} links[/green]"
            )

    except FileNotFoundError:
        console.print("  [yellow]Gospider not installed — run: go install github.com/jaeles-project/gospider@latest[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]Gospider timed out[/yellow]")

    # Save results
    output_file = Path(output_dir) / "gospider_crawl.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def crawl_deep(
    target: str,
    depth: int = 3,
    output_dir: str = "./results",
) -> dict:
    """Run deep crawl using both Katana and Gospider.

    Merges results from both crawlers for comprehensive coverage.

    Args:
        target: Target URL
        depth: Crawl depth
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "deep_crawl",
        "katana": {},
        "gospider": {},
        "all_urls": [],
        "total_unique": 0,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"[bold]  Deep crawling {target}[/bold]")

    # Run both crawlers
    results["katana"] = crawl_katana(target, depth, output_dir)
    results["gospider"] = crawl_gospider(target, depth, output_dir)

    # Merge and deduplicate
    all_urls = set()
    all_urls.update(results["katana"].get("urls", []))
    all_urls.update(results["gospider"].get("urls", []))
    all_urls.update(results["gospider"].get("links", []))

    results["all_urls"] = sorted(all_urls)
    results["total_unique"] = len(all_urls)

    # Save merged results
    merged_file = Path(output_dir) / "deep_crawl.json"
    with open(merged_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"[bold green]  ✓ Total unique URLs: {results['total_unique']}[/bold green]")

    return results


def extract_forms(
    urls: list,
    output_dir: str = "./results",
) -> dict:
    """Extract forms from a list of URLs using gospider.

    Args:
        urls: List of URLs to check
        output_dir: Output directory
    """
    results = {
        "method": "form_extraction",
        "forms": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    for url in urls[:20]:  # Limit to 20 URLs
        try:
            cmd = ["gospider", "-s", url, "-d", "1", "-c", "1"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith("[form]"):
                        results["forms"].append({
                            "url": url,
                            "form": line[6:].strip(),
                        })
        except Exception:
            continue

    console.print(f"  [green]✓ Found {len(results['forms'])} forms[/green]")

    # Save results
    output_file = Path(output_dir) / "forms.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results
