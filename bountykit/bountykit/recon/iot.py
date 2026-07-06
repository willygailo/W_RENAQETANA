"""IoT and infrastructure reconnaissance module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 17:
- Shodan integration
- Censys integration
- IoT device discovery
"""

import json
import os
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()


def search_shodan(
    target: str,
    api_key: str = None,
    output_dir: str = "./results",
) -> dict:
    """Search Shodan for IoT devices and infrastructure.

    Args:
        target: Target IP or domain
        api_key: Shodan API key (optional, uses SHODAN_API_KEY env var)
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "shodan",
        "hosts": [],
        "services": [],
        "vulnerabilities": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Searching Shodan for {target}...[/dim]")

    # Try shodan CLI first
    try:
        cmd = ["shodan", "host", target]
        if api_key:
            cmd = ["shodan", "--apikey", api_key, "host", target]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            results["raw"] = result.stdout
            console.print(f"  [green]✓ Shodan data retrieved for {target}[/green]")
        else:
            console.print(f"  [yellow]Shodan CLI returned non-zero exit: {result.stderr}[/yellow]")

    except FileNotFoundError:
        console.print("  [yellow]Shodan CLI not installed — run: pip install shodan[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]Shodan timed out[/yellow]")

    # Try shodan Python API
    try:
        import shodan

        api_key = api_key or os.environ.get("SHODAN_API_KEY")
        if api_key:
            api = shodan.Shodan(api_key)
            host = api.host(target)

            results["hosts"].append({
                "ip": host.get("ip_str"),
                "org": host.get("org"),
                "os": host.get("os"),
                "country": host.get("country_name"),
                "city": host.get("city"),
            })

            for service in host.get("data", []):
                results["services"].append({
                    "port": service.get("port"),
                    "protocol": service.get("transport"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "banner": service.get("data", "")[:200],
                })

                # Check for vulnerabilities
                vulns = service.get("vulns", [])
                for vuln in vulns:
                    results["vulnerabilities"].append({
                        "cve": vuln,
                        "port": service.get("port"),
                        "product": service.get("product"),
                    })

            if results["services"]:
                console.print(f"  [green]✓ Found {len(results['services'])} services on {target}[/green]")
            if results["vulnerabilities"]:
                console.print(
                    f"  [bold red]⚠ Found {len(results['vulnerabilities'])} vulnerabilities[/bold red]"
                )
        else:
            console.print("  [yellow]No Shodan API key — set SHODAN_API_KEY env var[/yellow]")

    except ImportError:
        console.print("  [yellow]Shodan Python library not installed[/yellow]")
    except Exception as e:
        console.print(f"  [yellow]Shodan API error: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "shodan_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def search_censys(
    target: str,
    api_id: str = None,
    api_secret: str = None,
    output_dir: str = "./results",
) -> dict:
    """Search Censys for IoT devices and infrastructure.

    Args:
        target: Target IP or domain
        api_id: Censys API ID (optional, uses CENSYS_API_ID env var)
        api_secret: Censys API secret (optional, uses CENSYS_API_SECRET env var)
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "censys",
        "hosts": [],
        "services": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Searching Censys for {target}...[/dim]")

    try:
        import requests

        api_id = api_id or os.environ.get("CENSYS_API_ID")
        api_secret = api_secret or os.environ.get("CENSYS_API_SECRET")

        if not api_id or not api_secret:
            console.print("  [yellow]No Censys API credentials — set CENSYS_API_ID and CENSYS_API_SECRET[/yellow]")
            return results

        # Search hosts
        url = f"https://search.censys.io/api/v2/hosts/search"
        query = f"ip: {target} OR services.service_name: HTTP AND services.port: 80"

        resp = requests.get(
            url,
            params={"q": query, "per_page": 10},
            auth=(api_id, api_secret),
            timeout=30,
        )

        if resp.status_code == 200:
            data = resp.json()
            hits = data.get("result", {}).get("hits", [])

            for hit in hits:
                results["hosts"].append({
                    "ip": hit.get("ip"),
                    "services": hit.get("services", []),
                    "location": hit.get("location", {}),
                })

            console.print(f"  [green]✓ Found {len(results['hosts'])} hosts via Censys[/green]")
        else:
            console.print(f"  [yellow]Censys returned status {resp.status_code}[/yellow]")

    except ImportError:
        console.print("  [yellow]requests library not available[/yellow]")
    except Exception as e:
        console.print(f"  [yellow]Censys error: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "censys_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def discover_iot(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Discover IoT devices and infrastructure.

    Combines Shodan and Censys for comprehensive discovery.

    Args:
        target: Target IP or domain
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "iot_discovery",
        "shodan": {},
        "censys": {},
        "total_services": 0,
        "total_vulnerabilities": 0,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"[bold]  Discovering IoT/infrastructure for {target}[/bold]")

    # Run both searches
    results["shodan"] = search_shodan(target, output_dir=output_dir)
    results["censys"] = search_censys(target, output_dir=output_dir)

    # Aggregate results
    results["total_services"] = (
        len(results["shodan"].get("services", []))
        + len(results["censys"].get("services", []))
    )
    results["total_vulnerabilities"] = len(results["shodan"].get("vulnerabilities", []))

    # Save merged results
    merged_file = Path(output_dir) / "iot_discovery.json"
    with open(merged_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(
        f"[bold green]  ✓ Found {results['total_services']} services, "
        f"{results['total_vulnerabilities']} vulnerabilities[/bold green]"
    )

    return results
