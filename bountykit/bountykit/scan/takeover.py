"""Subdomain takeover detection module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 8:
- Subdomain takeover via CNAME dangling records
- DNS record analysis
- Fingerprint-based detection
"""

import json
import os
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Services vulnerable to subdomain takeover
VULNERABLE_SERVICES = {
    "github.io": {"service": "GitHub Pages", "verify": "There isn't a GitHub Pages site here."},
    "herokuapp.com": {"service": "Heroku", "verify": "no-such-app"},
    "ghost.io": {"service": "Ghost", "verify": "The thing you were looking for is no longer here"},
    "shopify.com": {"service": "Shopify", "verify": "Sorry, this shop is currently unavailable"},
    "bitbucket.io": {"service": "Bitbucket", "verify": "Repository not found"},
    "azurewebsites.net": {"service": "Azure", "verify": "Azure Web App - Your web app is running and waiting for your content"},
    "cloudfront.net": {"service": "CloudFront", "verify": "Bad request"},
    "s3.amazonaws.com": {"service": "AWS S3", "verify": "NoSuchBucket"},
    "s3-website": {"service": "AWS S3", "verify": "NoSuchBucket"},
    "amazonaws.com": {"service": "AWS", "verify": "NoSuchBucket"},
    "cloudapp.net": {"service": "Azure", "verify": "Azure Web App"},
    "azure-api.net": {"service": "Azure", "verify": "Azure Web App"},
    "azurehdinsight.net": {"service": "Azure", "verify": "Azure Web App"},
    "azureedge.net": {"service": "Azure", "verify": "Azure Web App"},
    "azurefd.net": {"service": "Azure", "verify": "Azure Web App"},
    "azurewebsites.net": {"service": "Azure", "verify": "Azure Web App"},
    "cargocollective.com": {"service": "Cargo", "verify": "If this is your website and you've just created it"},
    "feedpress.me": {"service": "FeedPress", "verify": "The feed could not be found"},
    "freshdesk.com": {"service": "FreshDesk", "verify": "No such account"},
    "ghost.io": {"service": "Ghost", "verify": "The thing you were looking for is no longer here"},
    "helpjuice.com": {"service": "Helpjuice", "verify": "We could not find what you're looking for"},
    "helpscoutdocs.com": {"service": "HelpScout", "verify": "No settings were found for this company"},
    "heroku.com": {"service": "Heroku", "verify": "no-such-app"},
    "hosted.zendesk.com": {"service": "Zendesk", "verify": "Help Center Closed"},
    "intercom.io": {"service": "Intercom", "verify": "This page is reserved for artistic dogs"},
    "landingi.com": {"service": "Landingi", "verify": "It looks like you're lost"},
    "launchrock.com": {"service": "LaunchRock", "verify": "It looks like you may have taken a wrong turn somewhere"},
    "mashery.com": {"service": "Mashery", "verify": "Unrecognized domain"},
    "ngrok.io": {"service": "ngrok", "verify": "Tunnel not found"},
    "pingdom.com": {"service": "Pingdom", "verify": "Sorry, couldn't find the status page"},
    "proposify.biz": {"service": "Proposify", "verify": "If you need immediate assistance"},
    "readme.io": {"service": "Readme", "verify": "Project doesnt exist"},
    "readthedocs.io": {"service": "ReadTheDocs", "verify": "unknown to Read the Docs"},
    "s3.amazonaws.com": {"service": "AWS S3", "verify": "NoSuchBucket"},
    "sentry.io": {"service": "Sentry", "verify": "Looks like you've wandered into the void"},
    "simplebooklet.com": {"service": "SimpleBooklet", "verify": "We could not find the page you requested"},
    "statuspage.io": {"service": "StatusPage", "verify": "Better StatusPage"},
    "surge.sh": {"service": "Surge", "verify": "project not found"},
    "tave.com": {"service": "Tave", "verify": "Error retrieving the account"},
    "teamwork.com": {"service": "TeamWork", "verify": "Oops - We didn't find your site"},
    "tictail.com": {"service": "Tictail", "verify": "to target this URL"},
    "tumblr.com": {"service": "Tumblr", "verify": "Whatever you were looking for doesn't currently exist at this address"},
    "uberflip.com": {"service": "Uberflip", "verify": "Blog not found"},
    "unbounce.com": {"service": "Unbounce", "verify": "The requested URL was not found on this server"},
    "uservoice.com": {"service": "UserVoice", "verify": "This UserVoice subdomain is currently available!"},
    "valuemedia.info": {"service": "ValueMedia", "verify": "Domain is not configured"},
    "webflow.io": {"service": "Webflow", "verify": "The page you are looking for doesn't exist"},
    "wishpond.com": {"service": "Wishpond", "verify": "https://www.wishpond.com/404?campaign=true"},
    "wordpress.com": {"service": "WordPress", "verify": "Do you want to register"},
    "zendesk.com": {"service": "Zendesk", "verify": "Help Center Closed"},
    "ghost.io": {"service": "Ghost", "verify": "The thing you were looking for is no longer here"},
}


def check_cname_takeover(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Check for subdomain takeover via CNAME records.

    Args:
        target: Target domain
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "cname_takeover",
        "vulnerable": False,
        "dangling_cnames": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Checking CNAME takeover for {target}...[/dim]")

    # Resolve CNAME records
    try:
        cmd = ["dig", "+short", "CNAME", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            cnames = [c.strip().rstrip(".") for c in result.stdout.splitlines() if c.strip()]

            for cname in cnames:
                # Check if CNAME points to a vulnerable service
                for service_domain, service_info in VULNERABLE_SERVICES.items():
                    if cname.endswith(service_domain):
                        # Verify by checking if the service responds
                        is_dangling = _verify_service(cname, service_info["verify"])

                        if is_dangling:
                            results["dangling_cnames"].append({
                                "subdomain": target,
                                "cname": cname,
                                "service": service_info["service"],
                                "vulnerable": True,
                            })
                            results["vulnerable"] = True
                            console.print(
                                f"  [bold red]⚠ Dangling CNAME: {target} -> {cname} "
                                f"({service_info['service']})[/bold red]"
                            )

    except FileNotFoundError:
        console.print("  [yellow]dig command not available[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]dig timed out[/yellow]")

    if not results["vulnerable"]:
        console.print(f"  [green]✓ No dangling CNAMEs found for {target}[/green]")

    # Save results
    output_file = Path(output_dir) / "cname_takeover.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def check_ns_takeover(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Check for subdomain takeover via NS records.

    Args:
        target: Target domain
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "ns_takeover",
        "vulnerable": False,
        "ns_servers": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Checking NS takeover for {target}...[/dim]")

    try:
        cmd = ["dig", "+short", "NS", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            ns_servers = [n.strip().rstrip(".") for n in result.stdout.splitlines() if n.strip()]
            results["ns_servers"] = ns_servers

            for ns in ns_servers:
                # Check if NS server is alive
                try:
                    ns_check = subprocess.run(
                        ["dig", "+short", "A", ns],
                        capture_output=True, text=True, timeout=10,
                    )
                    if not ns_check.stdout.strip():
                        results["vulnerable"] = True
                        console.print(
                            f"  [bold red]⚠ Dead NS server: {ns}[/bold red]"
                        )
                except Exception:
                    continue

    except FileNotFoundError:
        console.print("  [yellow]dig command not available[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]dig timed out[/yellow]")

    if not results["vulnerable"]:
        console.print(f"  [green]✓ No NS takeover found for {target}[/green]")

    # Save results
    output_file = Path(output_dir) / "ns_takeover.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def scan_takeover(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Run full subdomain takeover scan.

    Args:
        target: Target domain
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "full_takeover",
        "cname": {},
        "ns": {},
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"[bold]  Running subdomain takeover scan on {target}[/bold]")

    results["cname"] = check_cname_takeover(target, output_dir)
    results["ns"] = check_ns_takeover(target, output_dir)

    # Save merged results
    merged_file = Path(output_dir) / "takeover_full.json"
    with open(merged_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def _verify_service(hostname: str, expected_response: str) -> bool:
    """Verify if a service is vulnerable by checking response."""
    try:
        import requests
        resp = requests.get(f"https://{hostname}", timeout=10, verify=False)
        if expected_response.lower() in resp.text.lower():
            return True
    except Exception:
        pass
    return False
