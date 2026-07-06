"""AWS cloud security testing module."""

import json
import os
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

METADATA_URL = "http://169.254.169.254"
METADATA_URLS = {
    "imds": f"{METADATA_URL}/latest/meta-data/",
    "iam": f"{METADATA_URL}/latest/meta-data/iam/security-credentials/",
    "user-data": f"{METADATA_URL}/latest/user-data",
    "dynanmo": f"{METADATA_URL}/latest/dynamic/instance-identity/document",
}


def test_aws(
    bucket: Optional[str] = None,
    test_metadata: bool = True,
    output_dir: str = "./results",
) -> dict:
    """Test AWS misconfigurations.

    Tests for:
    - Cloud metadata endpoint exposure (SSRF)
    - S3 bucket misconfigurations
    - IAM credential exposure

    Args:
        bucket: S3 bucket name to test
        test_metadata: Test cloud metadata endpoint
        output_dir: Output directory
    """
    results = {
        "tool": "aws_tester",
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print("\n[bold cyan]AWS Security Testing[/bold cyan]\n")

    # Test metadata endpoint
    if test_metadata:
        console.print("[bold]Testing Cloud Metadata Endpoint...[/bold]")
        metadata_results = _test_metadata_endpoint()
        results["findings"].extend(metadata_results)

    # Test S3 bucket
    if bucket:
        console.print(f"\n[bold]Testing S3 Bucket: {bucket}[/bold]")
        s3_results = _test_s3_bucket(bucket)
        results["findings"].extend(s3_results)

    # Save results
    output_file = Path(output_dir) / "aws_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"\n[dim]Results saved to {output_file}[/dim]")
    return results


def _test_metadata_endpoint() -> list:
    """Test cloud metadata endpoint for exposure."""
    findings = []

    try:
        import requests

        for name, url in METADATA_URLS.items():
            try:
                resp = requests.get(url, timeout=5)

                if resp.status_code == 200:
                    findings.append({
                        "type": "Cloud Metadata Exposure",
                        "detail": f"Metadata endpoint accessible: {name}",
                        "url": url,
                        "severity": "CRITICAL",
                        "evidence": resp.text[:100],
                    })
                    console.print(f"  [bold red]⚠ CRITICAL: {name} metadata exposed![/bold red]")
                    console.print(f"    [dim]{resp.text[:80]}...[/dim]")

            except requests.RequestException:
                continue

    except ImportError:
        console.print("  [yellow]requests not installed[/yellow]")

    if not findings:
        console.print("  [green]✓ Metadata endpoint not accessible (not on cloud)[/green]")

    return findings


def _test_s3_bucket(bucket: str) -> list:
    """Test S3 bucket for misconfigurations."""
    findings = []

    try:
        import requests

        # Test listing
        list_url = f"https://{bucket}.s3.amazonaws.com/"
        resp = requests.get(list_url, timeout=10)

        if resp.status_code == 200:
            findings.append({
                "type": "S3 Bucket Listing",
                "detail": f"Bucket listing enabled: {bucket}",
                "url": list_url,
                "severity": "HIGH",
            })
            console.print(f"  [red]⚠ HIGH: Bucket listing enabled for {bucket}[/red]")

        # Test public access
        public_url = f"https://{bucket}.s3.amazonaws.com/?list-type=2"
        resp = requests.get(public_url, timeout=10)

        if resp.status_code == 200:
            findings.append({
                "type": "S3 Public Access",
                "detail": f"Bucket publicly accessible: {bucket}",
                "url": public_url,
                "severity": "CRITICAL",
            })
            console.print(f"  [bold red]⚠ CRITICAL: Bucket {bucket} is publicly accessible![/bold red]")

    except ImportError:
        console.print("  [yellow]requests not installed[/yellow]")
    except Exception as e:
        console.print(f"  [dim]S3 test error: {e}[/dim]")

    if not findings:
        console.print(f"  [green]✓ Bucket {bucket} appears secure[/green]")

    return findings
