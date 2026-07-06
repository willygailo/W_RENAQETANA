"""CVE monitor for real-time notifications."""

import json
import os
import time
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

STATE_FILE = Path.home() / ".bountykit" / "cve_monitor_state.json"


def start_monitor(
    technologies: list,
    notify: Optional[str] = None,
    interval: int = 3600,
) -> None:
    """Start real-time CVE monitoring for specified technologies.

    Args:
        technologies: List of technologies to monitor
        notify: Webhook URL for notifications
        interval: Check interval in seconds (default: 1 hour)
    """
    console.print(f"\n[bold cyan]CVE Monitor[/bold cyan]")
    console.print(f"  Monitoring: {', '.join(technologies)}")
    console.print(f"  Check interval: {interval}s")
    if notify:
        console.print(f"  Webhook: {notify}")
    console.print()

    # Load previous state
    known_cves = _load_state()

    console.print("[bold]Starting monitoring loop (Ctrl+C to stop)...[/bold]\n")

    try:
        while True:
            for tech in technologies:
                console.print(f"[dim]Checking {tech}...[/dim]")

                from bountykit.cve.search import search_cve
                new_cves = search_cve(tech, limit=10)

                # Filter new CVEs
                for cve in new_cves:
                    if cve["id"] not in known_cves:
                        known_cves.add(cve["id"])
                        console.print(f"[bold red]NEW: {cve['id']}[/bold red] — {cve['description'][:80]}")

                        if notify:
                            _send_webhook(notify, cve, tech)

            _save_state(known_cves)
            console.print(f"[dim]Next check in {interval}s...[/dim]")
            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped.[/yellow]")
        _save_state(known_cves)


def _load_state() -> set:
    """Load known CVEs from state file."""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            data = json.load(f)
            return set(data.get("known_cves", []))
    return set()


def _save_state(known_cves: set):
    """Save known CVEs to state file."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump({"known_cves": sorted(known_cves)}, f, indent=2)


def _send_webhook(url: str, cve: dict, tech: str):
    """Send webhook notification."""
    try:
        import requests

        payload = {
            "text": f"🔴 NEW CVE for {tech}: {cve['id']}\nSeverity: {cve['severity']}\n{cve['description'][:200]}\nURL: {cve['url']}",
            "tech": tech,
            "cve": cve,
        }

        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            console.print("  [green]✓ Webhook sent[/green]")
        else:
            console.print(f"  [yellow]Webhook failed: {resp.status_code}[/yellow]")

    except Exception as e:
        console.print(f"  [red]Webhook error: {e}[/red]")
