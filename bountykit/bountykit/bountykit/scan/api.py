"""API security testing module."""

import json
import os
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

# Common API security issues to test
API_TESTS = [
    {"name": "Broken Object Level Authorization (BOLA)", "path": "/1", "expected": "200"},
    {"name": "Broken Authentication", "path": "/admin", "expected": "401"},
    {"name": "Excessive Data Exposure", "path": "/users", "expected": "check_schema"},
    {"name": "Lack of Resources & Rate Limiting", "type": "rate_limit"},
    {"name": "Mass Assignment", "path": "/register", "method": "POST"},
    {"name": "Security Misconfiguration", "path": "/config", "expected": "403"},
    {"name": "Injection (NoSQL/SQL)", "path": "/search?q[$ne]="},
]


def test_api(
    target: str,
    method: str = "GET",
    output_dir: str = "./results",
) -> dict:
    """Test API security.

    Checks for OWASP API Security Top 10 issues.

    Args:
        target: Target API URL
        method: HTTP method
        output_dir: Output directory
    """
    results = {
        "target": target,
        "tool": "api_tester",
        "method": method,
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Testing API security on {target}...[/dim]")

    try:
        import requests

        # Test common endpoints
        base_url = target.rstrip("/")

        for test in API_TESTS:
            if test.get("type") == "rate_limit":
                _test_rate_limit(base_url, results)
                continue

            path = test.get("path", "")
            test_url = f"{base_url}{path}"
            test_method = test.get("method", method)

            try:
                resp = requests.request(
                    test_method,
                    test_url,
                    timeout=10,
                    headers={"User-Agent": "bountykit/0.1 (authorized research)"},
                )

                finding = {
                    "test": test["name"],
                    "url": test_url,
                    "status": resp.status_code,
                    "method": test_method,
                }

                # Check for issues
                if _check_security_issue(test, resp):
                    results["findings"].append(finding)
                    console.print(f"  [yellow]⚠ {test['name']}: {resp.status_code}[/yellow]")

            except requests.RequestException:
                continue

        if results["findings"]:
            console.print(f"  [red]Found {len(results['findings'])} API issues[/red]")
        else:
            console.print("  [green]✓ No obvious API issues found[/green]")

    except ImportError:
        console.print("  [yellow]requests not installed — skipping API test[/yellow]")

    # Save results
    output_file = Path(output_dir) / "api_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def _check_security_issue(test: dict, response) -> bool:
    """Check if response indicates a security issue."""
    expected = test.get("expected", "")

    if expected == "check_schema":
        # Check if response exposes too much data
        try:
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                # Check for sensitive fields
                sensitive_fields = ["password", "token", "secret", "key", "ssn", "credit_card"]
                for item in data[:3]:
                    if isinstance(item, dict):
                        for field in sensitive_fields:
                            if field in str(item).lower():
                                return True
        except (ValueError, AttributeError):
            pass

    elif expected and response.status_code != int(expected):
        # Wrong status code might indicate misconfiguration
        if response.status_code == 200 and expected in ("401", "403"):
            return True

    # Check for exposed headers
    dangerous_headers = ["x-powered-by", "server", "x-aspnet-version", "x-debug"]
    for header in dangerous_headers:
        if header in response.headers:
            return True

    return False


def _test_rate_limit(base_url: str, results: dict):
    """Test for rate limiting."""
    try:
        import requests

        console.print("  [dim]Testing rate limiting (sending 20 rapid requests)...[/dim]")

        statuses = []
        for i in range(20):
            try:
                resp = requests.get(
                    base_url,
                    timeout=5,
                    headers={"User-Agent": "bountykit/0.1 (authorized research)"},
                )
                statuses.append(resp.status_code)
            except requests.RequestException:
                break

        # Check if we got rate limited
        if 429 not in statuses and len(statuses) >= 20:
            results["findings"].append({
                "test": "Lack of Rate Limiting",
                "url": base_url,
                "status": "no_rate_limit",
                "method": "GET",
                "detail": f"All {len(statuses)} requests succeeded without rate limiting",
            })
            console.print("  [yellow]⚠ No rate limiting detected[/yellow]")

    except ImportError:
        pass
