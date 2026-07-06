"""Subdomain enumeration module."""

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

from bountykit.utils.validator import validate_target

console = Console()


def enumerate_subdomains(
    target: str,
    output_dir: str = "./results",
    brute: bool = False,
) -> dict:
    """Enumerate subdomains using multiple techniques.

    Uses subfinder, crt.sh, and optionally DNS brute-force.
    """
    valid, err = validate_target(target)
    if not valid:
        console.print(f"[red]Invalid target: {err}[/red]")
        return {"error": err}

    results = {
        "target": target,
        "methods": [],
        "subdomains": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    # Method 1: subfinder
    console.print("  [dim]Running subfinder...[/dim]")
    subdomains = _run_subfinder(target)
    if subdomains:
        results["methods"].append("subfinder")
        results["subdomains"].extend(subdomains)
        console.print(f"  [green]✓ subfinder: {len(subdomains)} subdomains[/green]")
    else:
        console.print("  [yellow]subfinder: no results or not installed[/yellow]")

    # Method 2: crt.sh
    console.print("  [dim]Querying crt.sh...[/dim]")
    crt_subs = _query_crtsh(target)
    if crt_subs:
        results["methods"].append("crtsh")
        results["subdomains"].extend(crt_subs)
        console.print(f"  [green]✓ crt.sh: {len(crt_subs)} subdomains[/green]")

    # Method 3: DNS brute-force (optional)
    if brute:
        console.print("  [dim]Running DNS brute-force...[/dim]")
        brute_subs = _dns_bruteforce(target)
        if brute_subs:
            results["methods"].append("dns_bruteforce")
            results["subdomains"].extend(brute_subs)
            console.print(f"  [green]✓ DNS brute-force: {len(brute_subs)} subdomains[/green]")

    # Deduplicate
    results["subdomains"] = sorted(set(results["subdomains"]))

    # Save
    output_file = Path(output_dir) / f"{target}_subdomains.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Found {len(results['subdomains'])} unique subdomains[/dim]")
    console.print(f"  [dim]Results saved to {output_file}[/dim]")

    return results


def _run_subfinder(target: str) -> list:
    """Run subfinder and return discovered subdomains."""
    try:
        result = subprocess.run(
            ["subfinder", "-d", target, "-silent", "-all"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        console.print("  [yellow]subfinder timed out[/yellow]")
    return []


def _query_crtsh(target: str) -> list:
    """Query crt.sh for certificate transparency logs."""
    try:
        import requests

        url = f"https://crt.sh/?q=%.{target}&output=json"
        resp = requests.get(url, timeout=30)

        if resp.status_code == 200:
            certs = resp.json()
            subdomains = set()
            for cert in certs:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if (sub.endswith(f".{target}") or sub == target) and not sub.startswith("*"):
                        subdomains.add(sub)
            return sorted(subdomains)
    except Exception:
        pass
    return []


def _dns_bruteforce(target: str) -> list:
    """Simple DNS brute-force with common subdomain names."""
    common_subs = [
        "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3",
        "dns", "webmail", "cpanel", "api", "dev", "staging", "test",
        "admin", "blog", "shop", "store", "portal", "app", "beta",
        "vpn", "remote", "git", "jenkins", "ci", "cd", "grafana",
        "prometheus", "kibana", "elastic", "db", "mysql", "postgres",
        "redis", "mongo", "s3", "cdn", "static", "media", "img",
    ]

    found = []
    import socket
    for sub in common_subs:
        fqdn = f"{sub}.{target}"
        try:
            socket.getaddrinfo(fqdn, None)
            found.append(fqdn)
        except socket.gaierror:
            pass

    return found
