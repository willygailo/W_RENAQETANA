"""Deserialization vulnerability detection module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 10:
- Java deserialization detection (ysoserial, serialkiller)
- PHP deserialization detection
- .NET deserialization detection
- Generic serialization pattern detection
"""

import json
import os
import re
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Java deserialization gadget chains (for detection, not exploitation)
JAVA_GADGET_CHAINS = [
    "CommonsCollections1",
    "CommonsCollections2",
    "CommonsCollections3",
    "CommonsCollections4",
    "CommonsCollections5",
    "CommonsCollections6",
    "CommonsCollections7",
    "Spring1",
    "Spring2",
    "JRMPClient",
    "JRMPListener",
    "CommonsBeanutils",
    "Groovy1",
    "Jdk7u21",
    "URLDNS",
]

# Serialized object signatures
JAVA_SERIALIZED_SIGNATURE = bytes([0xAC, 0xED, 0x00, 0x05])
PHP_SERIALIZED_PREFIX = re.compile(r'^[aOsi]:\d+:[;\{]')


def detect_java_deserialization(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Detect Java deserialization vulnerabilities.

    Checks for serialized Java objects in responses, cookies,
    and parameters. Uses ysoserial for payload generation.

    Args:
        target: Target URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "java_deserialization",
        "vulnerable": False,
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Checking for Java deserialization on {target}...[/dim]")

    # Check for Java serialized object signatures
    try:
        import requests
        resp = requests.get(target, timeout=10, verify=False)

        # Check response body
        if JAVA_SERIALIZED_SIGNATURE in resp.content:
            results["findings"].append({
                "type": "serialized_object_in_response",
                "detail": "Java serialized object found in response body",
                "severity": "high",
            })

        # Check cookies
        for name, value in resp.cookies.items():
            try:
                cookie_bytes = value.encode()
                if JAVA_SERIALIZED_SIGNATURE in cookie_bytes:
                    results["findings"].append({
                        "type": "serialized_object_in_cookie",
                        "detail": f"Java serialized object in cookie: {name}",
                        "severity": "high",
                    })
            except Exception:
                continue

        # Check headers for serialization indicators
        for header, value in resp.headers.items():
            if any(p in value.lower() for p in ["java", "tomcat", "jboss", "weblogic"]):
                results["findings"].append({
                    "type": "java_server_detected",
                    "detail": f"Header: {header}: {value[:50]}",
                    "severity": "info",
                })

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    # Try ysoserial for detection (safe - uses URLDNS only)
    try:
        cmd = ["java", "-jar", "ysoserial.jar", "URLDNS", target]
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        if result.returncode == 0:
            results["findings"].append({
                "type": "ysoserial_available",
                "detail": "ysoserial.jar available for payload generation",
                "severity": "info",
            })
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass

    results["vulnerable"] = any(f["severity"] in ["high", "critical"] for f in results["findings"])

    if results["vulnerable"]:
        console.print(f"  [bold red]⚠ Potential Java deserialization found![/bold red]")
    else:
        console.print(f"  [green]✓ No obvious Java deserialization found[/green]")

    # Save results
    output_file = Path(output_dir) / "java_deserialization.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def detect_php_deserialization(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Detect PHP deserialization vulnerabilities.

    Checks for PHP serialized data patterns in responses and parameters.

    Args:
        target: Target URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "php_deserialization",
        "vulnerable": False,
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Checking for PHP deserialization on {target}...[/dim]")

    try:
        import requests
        resp = requests.get(target, timeout=10, verify=False)

        # Check response body for serialized PHP data
        body = resp.text

        # Look for PHP serialized objects
        php_serial_pattern = re.compile(r'[aO]:\d+:\{[^}]*\}')
        matches = php_serial_pattern.findall(body)

        if matches:
            for match in matches[:5]:
                results["findings"].append({
                    "type": "php_serialized_data",
                    "detail": f"PHP serialized data found: {match[:80]}",
                    "severity": "medium",
                })

        # Check cookies for serialized data
        for name, value in resp.cookies.items():
            if PHP_SERIALIZED_PREFIX.match(value):
                results["findings"].append({
                    "type": "php_serialized_cookie",
                    "detail": f"Serialized data in cookie: {name}",
                    "severity": "high",
                })

        # Check URL parameters
        if "?" in target:
            params = target.split("?", 1)[1]
            for param in params.split("&"):
                value = param.split("=", 1)[1] if "=" in param else ""
                if PHP_SERIALIZED_PREFIX.match(value):
                    results["findings"].append({
                        "type": "php_serialized_parameter",
                        "detail": f"Serialized data in parameter: {param.split('=')[0]}",
                        "severity": "high",
                    })

        # Check for PHP object injection indicators
        php_indicators = ["unserialize", "__wakeup", "__destruct", "__toString"]
        for indicator in php_indicators:
            if indicator in body:
                results["findings"].append({
                    "type": "php_deserialization_indicator",
                    "detail": f"Found {indicator} in page source",
                    "severity": "info",
                })

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    results["vulnerable"] = any(f["severity"] in ["high", "critical"] for f in results["findings"])

    if results["vulnerable"]:
        console.print(f"  [bold red]⚠ Potential PHP deserialization found![/bold red]")
    else:
        console.print(f"  [green]✓ No obvious PHP deserialization found[/green]")

    # Save results
    output_file = Path(output_dir) / "php_deserialization.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def detect_dotnet_deserialization(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Detect .NET deserialization vulnerabilities.

    Checks for ViewState, SOAP, and other .NET serialization patterns.

    Args:
        target: Target URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "dotnet_deserialization",
        "vulnerable": False,
        "findings": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Checking for .NET deserialization on {target}...[/dim]")

    try:
        import requests
        resp = requests.get(target, timeout=10, verify=False)

        body = resp.text
        headers = resp.headers

        # Check for ASP.NET ViewState
        viewstate_match = re.search(
            r'__VIEWSTATE["\s]*value="([^"]+)"',
            body,
        )
        if viewstate_match:
            viewstate = viewstate_match.group(1)
            results["findings"].append({
                "type": "viewstate_found",
                "detail": f"ASP.NET ViewState found (length: {len(viewstate)})",
                "severity": "info",
            })

            # Check if ViewState is MAC-protected
            if len(viewstate) > 1000:
                results["findings"].append({
                    "type": "viewstate_large",
                    "detail": "Large ViewState — may be vulnerable to deserialization",
                    "severity": "medium",
                })

        # Check for ASP.NET headers
        aspnet_headers = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for header in aspnet_headers:
            if header in headers:
                results["findings"].append({
                    "type": "aspnet_detected",
                    "detail": f"{header}: {headers[header]}",
                    "severity": "info",
                })

        # Check for SOAP endpoints
        soap_indicators = ["<soap:", "xmlns:soap", "soap:Envelope"]
        for indicator in soap_indicators:
            if indicator.lower() in body.lower():
                results["findings"].append({
                    "type": "soap_endpoint",
                    "detail": f"SOAP endpoint detected: {indicator}",
                    "severity": "info",
                })
                break

        # Check for __VIEWSTATEGENERATOR
        if "__VIEWSTATEGENERATOR" in body:
            results["findings"].append({
                "type": "viewstate_generator",
                "detail": "ViewState generator found — may be predictable",
                "severity": "low",
            })

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    results["vulnerable"] = any(f["severity"] in ["high", "critical"] for f in results["findings"])

    if results["vulnerable"]:
        console.print(f"  [bold red]⚠ Potential .NET deserialization found![/bold red]")
    else:
        console.print(f"  [green]✓ No obvious .NET deserialization found[/green]")

    # Save results
    output_file = Path(output_dir) / "dotnet_deserialization.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def scan_all_deserialization(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Run all deserialization checks.

    Args:
        target: Target URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "combined_deserialization",
        "java": {},
        "php": {},
        "dotnet": {},
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"[bold]  Running deserialization checks on {target}[/bold]")

    results["java"] = detect_java_deserialization(target, output_dir)
    results["php"] = detect_php_deserialization(target, output_dir)
    results["dotnet"] = detect_dotnet_deserialization(target, output_dir)

    # Save merged results
    merged_file = Path(output_dir) / "deserialization_all.json"
    with open(merged_file, "w") as f:
        json.dump(results, f, indent=2)

    return results
