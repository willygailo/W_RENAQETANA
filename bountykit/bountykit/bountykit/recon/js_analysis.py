"""JavaScript recon and analysis module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 5:
- JS file discovery and download
- Secret extraction from JS (API keys, tokens, AWS keys, JWTs)
- DOM-based XSS hunting (dangerous sinks/sources)
- Endpoint extraction from JS files
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

# Regex patterns for secret extraction
SECRET_PATTERNS = {
    "api_key": re.compile(
        r'(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)'
        r'["\s]*[:=]["\s]*["\']?([a-zA-Z0-9_\-]{8,})',
        re.IGNORECASE,
    ),
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret_key": re.compile(
        r'(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)'
        r'["\s]*[:=]["\s]*["\']?([a-zA-Z0-9/+=]{40})',
        re.IGNORECASE,
    ),
    "jwt_token": re.compile(
        r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'
    ),
    "generic_secret": re.compile(
        r'(?:secret|password|passwd|token|auth|private[_-]?key)'
        r'["\s]*[:=]["\s]*["\']?([a-zA-Z0-9_\-]{8,})',
        re.IGNORECASE,
    ),
    "firebase_url": re.compile(
        r'https://[a-zA-Z0-9_-]+\.firebaseio\.com'
    ),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "slack_webhook": re.compile(
        r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'
    ),
    "github_token": re.compile(
        r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}'
    ),
}

# DOM XSS dangerous sinks
DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "location.assign(",
    "location.replace(",
    "document.domain",
]

# DOM XSS sources
DOM_SOURCES = [
    "location.hash",
    "location.search",
    "location.href",
    "location.pathname",
    "document.URL",
    "document.referrer",
    "document.cookie",
    "window.name",
    "postMessage",
    "localStorage",
    "sessionStorage",
]


def discover_js_files(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Discover and download JavaScript files from a target.

    Uses katana crawler or falls back to curl-based discovery.

    Args:
        target: Target URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "js_discovery",
        "js_files": [],
        "total_urls": 0,
    }

    os.makedirs(output_dir, exist_ok=True)
    js_dir = Path(output_dir) / "js_files"
    js_dir.mkdir(exist_ok=True)

    console.print(f"  [dim]Discovering JS files on {target}...[/dim]")

    # Try katana first
    try:
        cmd = ["katana", "-u", target, "-jc", "-silent", "-d", "3"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
            js_urls = [u for u in urls if u.endswith(".js") or ".js?" in u]
            results["js_files"] = js_urls
            results["total_urls"] = len(urls)
            console.print(f"  [green]✓ Found {len(js_urls)} JS files from {len(urls)} URLs[/green]")

            # Download JS files
            _download_js_files(js_urls, js_dir)

    except FileNotFoundError:
        console.print("  [yellow]katana not installed — using curl fallback[/yellow]")
        _discover_js_curl(target, js_dir, results)
    except subprocess.TimeoutExpired:
        console.print("  [yellow]katana timed out — using curl fallback[/yellow]")
        _discover_js_curl(target, js_dir, results)

    # Save results
    output_file = Path(output_dir) / "js_discovery.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def extract_secrets(
    target: str,
    js_dir: str = "./results/js_files",
    output_dir: str = "./results",
) -> dict:
    """Extract secrets and sensitive data from JavaScript files.

    Scans JS files for API keys, tokens, AWS credentials, JWTs,
    and other sensitive patterns.

    Args:
        target: Target domain
        js_dir: Directory containing JS files
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "js_secret_extraction",
        "secrets": [],
        "files_scanned": 0,
    }

    os.makedirs(output_dir, exist_ok=True)
    js_path = Path(js_dir)

    if not js_path.exists():
        console.print(f"  [yellow]JS directory {js_dir} not found — run js-discovery first[/yellow]")
        return results

    js_files = list(js_path.glob("**/*.js"))
    if not js_files:
        # Try to scan .txt file with URLs
        url_file = js_path / "js_urls.txt"
        if url_file.exists():
            js_files = [url_file]

    console.print(f"  [dim]Scanning {len(js_files)} JS files for secrets...[/dim]")

    for js_file in js_files:
        try:
            content = js_file.read_text(errors="ignore")
            results["files_scanned"] += 1

            for pattern_name, pattern in SECRET_PATTERNS.items():
                matches = pattern.findall(content) or pattern.search(content)
                if matches:
                    if isinstance(matches, list):
                        for match in matches:
                            if isinstance(match, str) and len(match) >= 8:
                                results["secrets"].append({
                                    "type": pattern_name,
                                    "value": match[:20] + "..." if len(match) > 20 else match,
                                    "file": str(js_file.name),
                                })
                    elif isinstance(matches, re.Match):
                        results["secrets"].append({
                            "type": pattern_name,
                            "value": matches.group()[:30],
                            "file": str(js_file.name),
                        })
        except Exception:
            continue

    # Deduplicate
    seen = set()
    unique_secrets = []
    for s in results["secrets"]:
        key = f"{s['type']}:{s['value']}"
        if key not in seen:
            seen.add(key)
            unique_secrets.append(s)
    results["secrets"] = unique_secrets

    if results["secrets"]:
        console.print(f"  [bold red]⚠ Found {len(results['secrets'])} potential secrets[/bold red]")
        for s in results["secrets"][:10]:
            console.print(f"    [red]{s['type']}: {s['value']} (in {s['file']})[/red]")
    else:
        console.print("  [green]✓ No secrets found in JS files[/green]")

    # Save results
    output_file = Path(output_dir) / "js_secrets.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def hunt_dom_xss(
    target: str,
    js_dir: str = "./results/js_files",
    output_dir: str = "./results",
) -> dict:
    """Hunt for DOM-based XSS vulnerabilities in JavaScript files.

    Identifies dangerous sinks (innerHTML, eval, etc.) and
    sources (location.hash, document.cookie, etc.) for potential DOM XSS.

    Args:
        target: Target domain
        js_dir: Directory containing JS files
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "dom_xss_hunt",
        "sinks_found": [],
        "sources_found": [],
        "potential_xss": [],
    }

    os.makedirs(output_dir, exist_ok=True)
    js_path = Path(js_dir)

    if not js_path.exists():
        console.print(f"  [yellow]JS directory {js_dir} not found[/yellow]")
        return results

    js_files = list(js_path.glob("**/*.js"))
    console.print(f"  [dim]Hunting DOM XSS in {len(js_files)} JS files...[/dim]")

    for js_file in js_files:
        try:
            content = js_file.read_text(errors="ignore")
            lines = content.splitlines()

            for i, line in enumerate(lines, 1):
                # Skip minified files (very long lines)
                if len(line) > 1000:
                    continue

                # Check for dangerous sinks
                for sink in DOM_SINKS:
                    if sink.lower() in line.lower():
                        results["sinks_found"].append({
                            "sink": sink,
                            "file": str(js_file.name),
                            "line": i,
                            "code": line.strip()[:100],
                        })

                # Check for sources
                for source in DOM_SOURCES:
                    if source.lower() in line.lower():
                        results["sources_found"].append({
                            "source": source,
                            "file": str(js_file.name),
                            "line": i,
                            "code": line.strip()[:100],
                        })

                # Check if sink and source are in the same file
                # (potential DOM XSS)
                if any(s.lower() in line.lower() for s in DOM_SINKS):
                    for source in DOM_SOURCES:
                        if source.lower() in content.lower():
                            results["potential_xss"].append({
                                "file": str(js_file.name),
                                "sink_line": i,
                                "source": source,
                                "code": line.strip()[:100],
                            })
                            break

        except Exception:
            continue

    # Deduplicate potential XSS
    seen = set()
    unique_xss = []
    for x in results["potential_xss"]:
        key = f"{x['file']}:{x['sink_line']}"
        if key not in seen:
            seen.add(key)
            unique_xss.append(x)
    results["potential_xss"] = unique_xss

    console.print(f"  [dim]Sinks: {len(results['sinks_found'])}, Sources: {len(results['sources_found'])}[/dim]")

    if results["potential_xss"]:
        console.print(f"  [bold red]⚠ Found {len(results['potential_xss'])} potential DOM XSS locations[/bold red]")
    else:
        console.print("  [green]✓ No obvious DOM XSS patterns found[/green]")

    # Save results
    output_file = Path(output_dir) / "dom_xss.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def extract_endpoints(
    target: str,
    js_dir: str = "./results/js_files",
    output_dir: str = "./results",
) -> dict:
    """Extract API endpoints and hidden paths from JavaScript files.

    Uses linkfinder-style regex to find URLs, paths, and API
    endpoints embedded in JS code.

    Args:
        target: Target domain
        js_dir: Directory containing JS files
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "js_endpoint_extraction",
        "endpoints": [],
        "api_paths": [],
    }

    os.makedirs(output_dir, exist_ok=True)
    js_path = Path(js_dir)

    if not js_path.exists():
        console.print(f"  [yellow]JS directory {js_dir} not found[/yellow]")
        return results

    js_files = list(js_path.glob("**/*.js"))
    console.print(f"  [dim]Extracting endpoints from {len(js_files)} JS files...[/dim]")

    # Patterns for endpoint extraction
    endpoint_patterns = [
        # Relative paths: "/api/v1/users"
        re.compile(r'["\'](/[a-zA-Z0-9_/\-\.]+(?:\?[^"\']*)?)["\']'),
        # Full URLs: https://target.com/api/...
        re.compile(rf'["\']((?:https?://)?(?:www\.)?{re.escape(target)}[/a-zA-Z0-9_/\-\.]*(?:\?[^"\']*)?)["\']'),
        # API base paths
        re.compile(r'["\'](?:/api|/v[0-9]+|/rest|/graphql|/query)["\']'),
        # fetch/axios calls
        re.compile(r'(?:fetch|axios|ajax|XMLHttpRequest)\s*\(\s*["\']([^"\']+)["\']'),
        # Window.location assignments
        re.compile(r'(?:location\.(?:href|assign|replace))\s*=\s*["\']([^"\']+)["\']'),
    ]

    all_endpoints = set()

    for js_file in js_files:
        try:
            content = js_file.read_text(errors="ignore")

            for pattern in endpoint_patterns:
                matches = pattern.findall(content)
                for match in matches:
                    if isinstance(match, str) and len(match) > 1:
                        all_endpoints.add(match)

        except Exception:
            continue

    results["endpoints"] = sorted(all_endpoints)
    results["api_paths"] = [
        e for e in all_endpoints
        if any(p in e.lower() for p in ["/api", "/v1", "/v2", "/graphql", "/rest", "/query"])
    ]

    console.print(
        f"  [green]✓ Found {len(results['endpoints'])} endpoints "
        f"({len(results['api_paths'])} API paths)[/green]"
    )

    # Save results
    output_file = Path(output_dir) / "js_endpoints.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def _download_js_files(js_urls: list, output_dir: Path):
    """Download JS files from URLs."""
    import requests

    for i, url in enumerate(js_urls[:50]):  # Limit to 50 files
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                filename = f"js_{i:04d}.js"
                (output_dir / filename).write_text(resp.text)
        except Exception:
            continue


def _discover_js_curl(target: str, js_dir: Path, results: dict):
    """Fallback JS discovery using curl."""
    try:
        resp = subprocess.run(
            ["curl", "-sk", target, "-o", "-"],
            capture_output=True, text=True, timeout=30,
        )
        if resp.returncode == 0:
            # Extract .js URLs from HTML
            import re
            js_pattern = re.compile(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']')
            matches = js_pattern.findall(resp.stdout)
            js_urls = []
            for m in matches:
                if m.startswith("//"):
                    m = "https:" + m
                elif m.startswith("/"):
                    m = target.rstrip("/") + m
                js_urls.append(m)

            results["js_files"] = js_urls
            results["total_urls"] = len(js_urls)
            console.print(f"  [green]✓ Found {len(js_urls)} JS files via curl[/green]")
            _download_js_files(js_urls, js_dir)
    except Exception:
        console.print("  [yellow]Could not discover JS files[/yellow]")
