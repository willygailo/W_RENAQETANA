"""Mobile application reconnaissance module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 16:
- APK/IPA analysis
- Hardcoded secrets extraction
- API endpoint discovery from mobile apps
"""

import json
import os
import re
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()


def analyze_apk(
    apk_path: str,
    output_dir: str = "./results",
) -> dict:
    """Analyze an Android APK file.

    Extracts permissions, activities, and potential vulnerabilities.

    Args:
        apk_path: Path to APK file
        output_dir: Output directory
    """
    results = {
        "method": "apk_analysis",
        "apk_path": apk_path,
        "permissions": [],
        "activities": [],
        "hardcoded_secrets": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Analyzing APK: {apk_path}...[/dim]")

    # Try apktool for decompilation
    try:
        cmd = ["apktool", "d", apk_path, "-o", f"{output_dir}/apk_decoded", "-f"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            console.print(f"  [green]✓ APK decompiled successfully[/green]")
            _scan_decompiled_apk(f"{output_dir}/apk_decoded", results)
        else:
            console.print(f"  [yellow]apktool failed: {result.stderr[:200]}[/yellow]")
    except FileNotFoundError:
        console.print("  [yellow]apktool not installed — run: apktool install[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]apktool timed out[/yellow]")

    # Try aapt for basic info
    try:
        cmd = ["aapt", "dump", "badging", apk_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            # Parse permissions
            for line in result.stdout.splitlines():
                if "uses-permission" in line:
                    permission = line.split("'")[1] if "'" in line else ""
                    if permission:
                        results["permissions"].append(permission)

            console.print(f"  [cyan]Found {len(results['permissions'])} permissions[/cyan]")
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass

    if results["hardcoded_secrets"]:
        console.print(
            f"  [bold red]⚠ Found {len(results['hardcoded_secrets'])} hardcoded secrets![/bold red]"
        )

    # Save results
    output_file = Path(output_dir) / "apk_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def extract_mobile_endpoints(
    apk_dir: str,
    output_dir: str = "./results",
) -> dict:
    """Extract API endpoints from decompiled mobile app.

    Args:
        apk_dir: Directory containing decompiled APK
        output_dir: Output directory
    """
    results = {
        "method": "mobile_endpoint_extraction",
        "endpoints": [],
        "api_keys": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    apk_path = Path(apk_dir)
    if not apk_path.exists():
        console.print(f"  [yellow]Decompiled directory not found: {apk_dir}[/yellow]")
        return results

    console.print(f"  [dim]Extracting endpoints from decompiled app...[/dim]")

    # Patterns for endpoint extraction
    endpoint_patterns = [
        re.compile(r'https?://[a-zA-Z0-9._\-/]+(?:\?[a-zA-Z0-9._\-=&]+)?'),
        re.compile(r'"(/api/[a-zA-Z0-9/_\-]+)"'),
        re.compile(r'"(v[0-9]+/[a-zA-Z0-9/_\-]+)"'),
    ]

    # Patterns for API key extraction
    api_key_patterns = [
        re.compile(r'api[_\-]?key["\s:=]+["\']([a-zA-Z0-9_\-]{16,})["\']'),
        re.compile(r'AKIA[0-9A-Z]{16}'),
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    ]

    # Scan smali and XML files
    for ext in ["*.smali", "*.xml", "*.java", "*.kt"]:
        for file in apk_path.rglob(ext):
            try:
                content = file.read_text(errors="ignore")

                # Extract endpoints
                for pattern in endpoint_patterns:
                    matches = pattern.findall(content)
                    for match in matches:
                        if len(match) > 5:
                            results["endpoints"].append({
                                "endpoint": match,
                                "file": str(file.relative_to(apk_path)),
                            })

                # Extract API keys
                for pattern in api_key_patterns:
                    matches = pattern.findall(content)
                    for match in matches:
                        if isinstance(match, str) and len(match) >= 16:
                            results["api_keys"].append({
                                "key": match[:20] + "...",
                                "file": str(file.relative_to(apk_path)),
                            })

            except Exception:
                continue

    # Deduplicate
    seen_endpoints = set()
    unique_endpoints = []
    for e in results["endpoints"]:
        key = e["endpoint"]
        if key not in seen_endpoints:
            seen_endpoints.add(key)
            unique_endpoints.append(e)
    results["endpoints"] = unique_endpoints

    console.print(
        f"  [green]✓ Found {len(results['endpoints'])} endpoints, "
        f"{len(results['api_keys'])} API keys[/green]"
    )

    # Save results
    output_file = Path(output_dir) / "mobile_endpoints.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def _scan_decompiled_apk(apk_dir: str, results: dict):
    """Scan decompiled APK for hardcoded secrets."""
    apk_path = Path(apk_dir)

    # Common secret patterns
    secret_patterns = {
        "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "api_key": re.compile(r'api[_\-]?key["\s:=]+["\']([a-zA-Z0-9_\-]{16,})["\']'),
        "password": re.compile(r'password["\s:=]+["\']([^"\']+)["\']'),
        "firebase": re.compile(r'https://[a-zA-Z0-9_-]+\.firebaseio\.com'),
        "google_api": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    }

    for file in apk_path.rglob("*.smali"):
        try:
            content = file.read_text(errors="ignore")
            for secret_type, pattern in secret_patterns.items():
                matches = pattern.findall(content)
                for match in matches:
                    if isinstance(match, str) and len(match) >= 8:
                        results["hardcoded_secrets"].append({
                            "type": secret_type,
                            "value": match[:30],
                            "file": str(file.relative_to(apk_path)),
                        })
        except Exception:
            continue

    # Also check XML files
    for file in apk_path.rglob("*.xml"):
        try:
            content = file.read_text(errors="ignore")
            for secret_type, pattern in secret_patterns.items():
                matches = pattern.findall(content)
                for match in matches:
                    if isinstance(match, str) and len(match) >= 8:
                        results["hardcoded_secrets"].append({
                            "type": secret_type,
                            "value": match[:30],
                            "file": str(file.relative_to(apk_path)),
                        })
        except Exception:
            continue
