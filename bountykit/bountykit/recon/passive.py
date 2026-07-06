"""Passive DNS enumeration module."""

import json
import os
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


def passive_dns(target: str, output_dir: str = "./results") -> dict:
    """Perform passive DNS enumeration using online sources.

    Uses crt.sh, Certificate Transparency logs, and DNS records
    to find subdomains without active probing.

    Returns dict with findings.
    """
    results = {
        "target": target,
        "method": "passive_dns",
        "subdomains": [],
        "certificates": [],
    }

    os.makedirs(output_dir, exist_ok=True)
    output_file = Path(output_dir) / f"{target}_passive_dns.json"

    try:
        import requests

        # crt.sh certificate transparency
        console.print("  [dim]Querying crt.sh for certificate transparency logs...[/dim]")
        crtsh_url = f"https://crt.sh/?q=%.{target}&output=json"
        resp = requests.get(crtsh_url, timeout=30)

        if resp.status_code == 200:
            certs = resp.json()
            subdomains = set()
            for cert in certs:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{target}") or sub == target:
                        if not sub.startswith("*"):
                            subdomains.add(sub)

            results["subdomains"] = sorted(subdomains)
            results["certificates"] = len(certs)
            console.print(f"  [green]✓ Found {len(subdomains)} unique subdomains via crt.sh[/green]")

    except ImportError:
        console.print("  [yellow]requests not installed — skipping passive DNS[/yellow]")
    except Exception as e:
        console.print(f"  [red]Error querying crt.sh: {e}[/red]")

    # Save results
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results
