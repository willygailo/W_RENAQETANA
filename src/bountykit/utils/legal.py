"""Legal compliance and authorization checks."""

import os
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

DISCLAIMER = """
[bold red]LEGAL DISCLAIMER[/bold red]

This tool is for [bold]authorized penetration testing and bug bounty programs[/bold] only.

By using bountykit, you agree:
  1. You have [bold]written authorization[/bold] to test the target
  2. You will stay [bold]within scope[/bold] defined by the program
  3. You will [bold]never[/bold] test without permission
  4. You will follow [bold]coordinated disclosure[/bold] timelines
  5. You will not cause [bold]damage or disruption[/bold] to services

[bold red]Unauthorized access is illegal.[/bold red]
"""


def check_authorization(target: str, scope_file: Optional[str] = None) -> bool:
    """Check if target is authorized for testing.

    Returns True if target passes all authorization checks.
    """
    console.print(DISCLAIMER)

    if scope_file:
        return _check_scope_file(target, scope_file)

    return _interactive_confirm(target)


def _check_scope_file(target: str, scope_file: str) -> bool:
    """Verify target against a scope file."""
    path = Path(scope_file)

    if not path.exists():
        console.print(f"[red]Scope file not found: {scope_file}[/red]")
        return False

    with open(path) as f:
        in_scope = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    # Check exact match or wildcard
    for entry in in_scope:
        if entry == target:
            return True
        if entry.startswith("*.") and target.endswith(entry[1:]):
            return True
        if target.endswith(entry):
            return True

    console.print(f"[yellow]Target {target} not found in scope file.[/yellow]")
    return False


def _interactive_confirm(target: str) -> bool:
    """Interactive authorization confirmation."""
    console.print(f"[bold]Target:[/bold] {target}")

    response = input(
        "\nDo you have [written authorization] to test this target? (yes/no): "
    )

    if response.lower() in ("yes", "y"):
        console.print("[green]Authorization confirmed.[/green]\n")
        return True

    console.print("[red]Authorization denied. Exiting.[/red]")
    return False


def validate_scope(target: str, scope_entries: list[str]) -> tuple[bool, str]:
    """Validate target against scope entries.

    Returns (is_valid, reason).
    """
    if not scope_entries:
        return True, "No scope defined — all targets allowed"

    for entry in scope_entries:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue

        if entry == target:
            return True, f"Exact match: {entry}"

        if entry.startswith("*.") and target.endswith(entry[1:]):
            return True, f"Wildcard match: {entry}"

        if target.endswith(entry.lstrip(".")):
            return True, f"Domain match: {entry}"

    return False, f"Target {target} not in scope"
