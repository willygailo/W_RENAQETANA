"""Security headers analysis module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 9:
- Missing security headers detection
- Cookie security analysis
- Content Security Policy analysis
- HSTS analysis
"""

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

console = Console()

# Required security headers
REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS header missing — vulnerable to SSL stripping",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "MIME type sniffing not prevented",
        "expected": "nosniff",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Clickjacking possible — X-Frame-Options missing",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "XSS filter not enabled (legacy but still useful)",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "description": "CSP missing — no XSS mitigation",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer policy not set",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions policy not set",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "description": "COOP not set",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "low",
        "description": "CORP not set",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "low",
        "description": "COEP not set",
    },
}

# Dangerous headers (should not be present)
DANGEROUS_HEADERS = {
    "X-Powered-By": {
        "severity": "info",
        "description": "Server technology disclosure",
    },
    "Server": {
        "severity": "info",
        "description": "Server information disclosure",
    },
}

# Cookie security attributes
SECURE_COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]


def analyze_headers(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Analyze security headers of a target.

    Args:
        target: Target URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "security_headers",
        "missing_headers": [],
        "dangerous_headers": [],
        "all_headers": {},
        "score": 0,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Analyzing security headers for {target}...[/dim]")

    try:
        import requests
        resp = requests.get(target, timeout=10, verify=False)
        headers = dict(resp.headers)
        results["all_headers"] = headers

        # Check for missing required headers
        for header, info in REQUIRED_HEADERS.items():
            if header.lower() not in {k.lower() for k in headers}:
                results["missing_headers"].append({
                    "header": header,
                    "severity": info["severity"],
                    "description": info["description"],
                })

        # Check for dangerous headers
        for header, info in DANGEROUS_HEADERS.items():
            if header in headers:
                results["dangerous_headers"].append({
                    "header": header,
                    "value": headers[header][:50],
                    "severity": info["severity"],
                    "description": info["description"],
                })

        # Calculate score
        total_checks = len(REQUIRED_HEADERS)
        passed = total_checks - len(results["missing_headers"])
        results["score"] = int((passed / total_checks) * 100) if total_checks > 0 else 0

        # Display results
        if results["missing_headers"]:
            console.print(f"  [bold red]⚠ Missing {len(results['missing_headers'])} security headers[/bold red]")
            for h in results["missing_headers"]:
                console.print(f"    [red]✗ {h['header']} — {h['description']}[/red]")
        else:
            console.print(f"  [green]✓ All required security headers present[/green]")

        if results["dangerous_headers"]:
            for h in results["dangerous_headers"]:
                console.print(f"    [yellow]⚠ {h['header']}: {h['value']}[/yellow]")

        console.print(f"  [dim]Score: {results['score']}/100[/dim]")

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "security_headers.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def analyze_cookies(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Analyze cookie security attributes.

    Args:
        target: Target URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "cookie_analysis",
        "cookies": [],
        "insecure_cookies": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Analyzing cookies for {target}...[/dim]")

    try:
        import requests
        resp = requests.get(target, timeout=10, verify=False)

        for cookie in resp.cookies:
            cookie_info = {
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "http_only": cookie.has_nonstandard_attr("HttpOnly"),
                "same_site": cookie.get_nonstandard_attr("SameSite"),
            }

            results["cookies"].append(cookie_info)

            # Check for insecure cookies
            issues = []
            if not cookie.secure:
                issues.append("Missing Secure flag")
            if not cookie_info["http_only"]:
                issues.append("Missing HttpOnly flag")
            if not cookie_info["same_site"]:
                issues.append("Missing SameSite attribute")

            if issues:
                results["insecure_cookies"].append({
                    "name": cookie.name,
                    "issues": issues,
                })

        if results["insecure_cookies"]:
            console.print(f"  [bold red]⚠ Found {len(results['insecure_cookies'])} insecure cookies[/bold red]")
            for c in results["insecure_cookies"]:
                console.print(f"    [red]✗ {c['name']}: {', '.join(c['issues'])}[/red]")
        else:
            console.print(f"  [green]✓ All cookies have proper security flags[/green]")

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "cookie_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def analyze_csp(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Analyze Content Security Policy.

    Args:
        target: Target URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "csp_analysis",
        "csp_present": False,
        "csp_directives": {},
        "weaknesses": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Analyzing CSP for {target}...[/dim]")

    try:
        import requests
        resp = requests.get(target, timeout=10, verify=False)

        csp_header = resp.headers.get("Content-Security-Policy", "")
        if not csp_header:
            console.print("  [yellow]No CSP header found[/yellow]")
            return results

        results["csp_present"] = True

        # Parse CSP directives
        directives = csp_header.split(";")
        for directive in directives:
            parts = directive.strip().split()
            if parts:
                results["csp_directives"][parts[0]] = parts[1:]

        # Check for weaknesses
        _check_csp_weaknesses(results)

        if results["weaknesses"]:
            console.print(f"  [bold red]⚠ CSP has {len(results['weaknesses'])} weaknesses[/bold red]")
            for w in results["weaknesses"]:
                console.print(f"    [red]✗ {w['issue']}[/red]")
        else:
            console.print("  [green]✓ CSP looks strong[/green]")

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "csp_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def _check_csp_weaknesses(results: dict):
    """Check for CSP weaknesses."""
    directives = results["csp_directives"]

    # Check script-src
    script_src = directives.get("script-src", [])
    if "'unsafe-inline'" in script_src:
        results["weaknesses"].append({
            "issue": "script-src allows unsafe-inline — XSS possible",
            "severity": "high",
        })
    if "'unsafe-eval'" in script_src:
        results["weaknesses"].append({
            "issue": "script-src allows unsafe-eval — XSS possible",
            "severity": "high",
        })
    if "*" in script_src:
        results["weaknesses"].append({
            "issue": "script-src allows all sources — CSP ineffective",
            "severity": "critical",
        })

    # Check object-src
    object_src = directives.get("object-src", [])
    if "*" in object_src or "'unsafe-inline'" in object_src:
        results["weaknesses"].append({
            "issue": "object-src allows all sources",
            "severity": "medium",
        })

    # Check base-uri
    base_uri = directives.get("base-uri", [])
    if "'unsafe-inline'" in base_uri or "*" in base_uri:
        results["weaknesses"].append({
            "issue": "base-uri allows unsafe-inline or wildcard",
            "severity": "medium",
        })

    # Check for missing directives
    missing = ["frame-ancestors", "form-action", "default-src"]
    for directive in missing:
        if directive not in directives:
            results["weaknesses"].append({
                "issue": f"Missing {directive} directive",
                "severity": "low",
            })
