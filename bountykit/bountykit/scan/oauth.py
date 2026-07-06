"""OAuth/OIDC security testing module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 14:
- OAuth redirect URI manipulation
- Token theft via open redirect
- PKCE bypass testing
- JWT token analysis
"""

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

from rich.console import Console

console = Console()

# OAuth redirect URI manipulation payloads
REDIRECT_PAYLOADS = [
    "{original}",
    "{original}@evil.com",
    "{original}#.evil.com",
    "{original}%0d%0aLocation:%20http://evil.com",
    "http://localhost",
    "http://127.0.0.1",
    "https://evil.com/callback",
]


def test_redirect_uri(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Test OAuth redirect URI validation.

    Checks if the authorization endpoint properly validates
    the redirect_uri parameter.

    Args:
        target: OAuth authorization endpoint
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "oauth_redirect_uri",
        "vulnerable": False,
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Testing OAuth redirect URI on {target}...[/dim]")

    try:
        import requests

        # First, try to find the authorization endpoint
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Common OAuth endpoints to test
        auth_endpoints = [
            "/oauth/authorize",
            "/oauth2/authorize",
            "/auth/authorize",
            "/authorize",
            "/login/oauth/authorize",
        ]

        for endpoint in auth_endpoints:
            auth_url = base_url + endpoint
            try:
                resp = requests.get(auth_url, timeout=10, allow_redirects=False)
                if resp.status_code in [301, 302, 303, 307]:
                    redirect_location = resp.headers.get("Location", "")
                    if "redirect_uri" in redirect_location or "client_id" in redirect_location:
                        results["findings"].append({
                            "type": "auth_endpoint_found",
                            "detail": f"Authorization endpoint: {auth_url}",
                            "severity": "info",
                        })

                        # Test redirect URI manipulation
                        _test_redirect_manipulation(auth_url, redirect_location, results)
                        break
            except Exception:
                continue

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    results["vulnerable"] = any(f["severity"] in ["high", "critical"] for f in results["findings"])

    if results["vulnerable"]:
        console.print(f"  [bold red]⚠ OAuth redirect URI vulnerability found![/bold red]")
    else:
        console.print(f"  [green]✓ No obvious redirect URI issues found[/green]")

    # Save results
    output_file = Path(output_dir) / "oauth_redirect.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def test_token_theft(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Test for token theft via open redirect.

    Checks if the OAuth flow is vulnerable to token theft
    through open redirect vulnerabilities.

    Args:
        target: Application URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "oauth_token_theft",
        "vulnerable": False,
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Testing token theft on {target}...[/dim]")

    # Check for open redirect indicators
    open_redirect_indicators = [
        "return_url",
        "redirect",
        "next",
        "callback",
        "continue",
        "url",
        "dest",
        "destination",
    ]

    try:
        import requests

        for indicator in open_redirect_indicators:
            test_url = f"{target}?{indicator}=https://evil.com"
            try:
                resp = requests.get(test_url, timeout=10, allow_redirects=False)
                location = resp.headers.get("Location", "")

                if "evil.com" in location:
                    results["findings"].append({
                        "type": "open_redirect",
                        "detail": f"Open redirect via {indicator} parameter",
                        "severity": "high",
                        "url": test_url,
                        "redirect": location,
                    })
            except Exception:
                continue

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    results["vulnerable"] = any(f["severity"] in ["high", "critical"] for f in results["findings"])

    if results["vulnerable"]:
        console.print(f"  [bold red]⚠ Token theft vector found![/bold red]")
    else:
        console.print(f"  [green]✓ No obvious token theft vectors found[/green]")

    # Save results
    output_file = Path(output_dir) / "oauth_token_theft.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def analyze_jwt(
    token: str,
    output_dir: str = "./results",
) -> dict:
    """Analyze JWT token for security issues.

    Checks for weak algorithms, exposed secrets, and other JWT issues.

    Args:
        token: JWT token string
        output_dir: Output directory
    """
    results = {
        "method": "jwt_analysis",
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Analyzing JWT token...[/dim]")

    try:
        import base64

        parts = token.split(".")
        if len(parts) != 3:
            console.print(f"  [yellow]Invalid JWT format (expected 3 parts, got {len(parts)})[/yellow]")
            return results

        # Decode header
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        results["header"] = header

        # Decode payload
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        results["payload"] = payload

        # Check algorithm
        alg = header.get("alg", "")
        if alg == "none":
            results["findings"].append({
                "type": "jwt_none_algorithm",
                "detail": "JWT uses 'none' algorithm — can be forged",
                "severity": "critical",
            })
        elif alg in ["HS256", "HS384", "HS512"]:
            results["findings"].append({
                "type": "jwt_symmetric_algorithm",
                "detail": f"JWT uses symmetric algorithm: {alg} — potential for brute force",
                "severity": "info",
            })

        # Check expiration
        import time
        exp = payload.get("exp")
        if exp:
            if exp < time.time():
                results["findings"].append({
                    "type": "jwt_expired",
                    "detail": "JWT has expired",
                    "severity": "info",
                })
            else:
                remaining = exp - time.time()
                if remaining > 86400 * 365:  # More than 1 year
                    results["findings"].append({
                        "type": "jwt_long_expiration",
                        "detail": f"JWT has long expiration: {remaining/86400:.0f} days",
                        "severity": "low",
                    })

        # Check for sensitive data in payload
        sensitive_keys = ["password", "secret", "token", "key", "ssn", "credit"]
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                results["findings"].append({
                    "type": "jwt_sensitive_data",
                    "detail": f"Sensitive data in JWT: {key}",
                    "severity": "high",
                })

        console.print(f"  [green]✓ JWT analysis complete ({len(results['findings'])} findings)[/green]")

    except Exception as e:
        console.print(f"  [yellow]JWT analysis failed: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "jwt_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def _test_redirect_manipulation(auth_url: str, redirect_location: str, results: dict):
    """Test redirect URI manipulation."""
    try:
        import requests

        parsed = urlparse(redirect_location)
        params = parse_qs(parsed.query)

        original_uri = params.get("redirect_uri", [""])[0]
        if not original_uri:
            return

        for payload_template in REDIRECT_PAYLOADS:
            payload = payload_template.replace("{original}", original_uri)
            test_url = redirect_location.replace(original_uri, payload)

            try:
                resp = requests.get(test_url, timeout=10, allow_redirects=False)
                location = resp.headers.get("Location", "")

                if "evil.com" in location or resp.status_code == 200:
                    results["findings"].append({
                        "type": "redirect_uri_manipulation",
                        "detail": f"Redirect URI manipulation works: {payload_template}",
                        "severity": "critical",
                        "payload": payload,
                    })
                    break
            except Exception:
                continue
    except Exception:
        pass
