"""Active reconnaissance — host probing and port scanning."""

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


def probe_hosts(target: str, output_dir: str = "./results") -> dict:
    """Probe live hosts using httpx or curl.

    Returns dict with live host information.
    """
    results = {
        "target": target,
        "method": "host_probe",
        "live_hosts": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    # Try httpx first
    console.print("  [dim]Probing live hosts with httpx...[/dim]")
    hosts = _run_httpx(target)
    if hosts:
        results["live_hosts"] = hosts
        console.print(f"  [green]✓ Found {len(hosts)} live hosts[/green]")
    else:
        # Fallback to curl
        console.print("  [dim]httpx not available, falling back to curl...[/dim]")
        hosts = _probe_with_curl(target)
        results["live_hosts"] = hosts
        console.print(f"  [green]✓ Found {len(hosts)} live hosts[/green]")

    output_file = Path(output_dir) / f"{target}_hosts.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def scan_ports(
    target: str,
    output_dir: str = "./results",
    full: bool = False,
) -> dict:
    """Scan ports using naabu or nmap.

    Args:
        target: Target domain
        output_dir: Output directory
        full: If True, scan all 65535 ports
    """
    results = {
        "target": target,
        "method": "port_scan",
        "open_ports": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    # Try naabu first
    console.print("  [dim]Scanning ports with naabu...[/dim]")
    ports = _run_naabu(target, full=full)
    if ports:
        results["open_ports"] = ports
        console.print(f"  [green]✓ Found {len(ports)} open ports[/green]")
    else:
        # Fallback to nmap
        console.print("  [dim]naabu not available, falling back to nmap...[/dim]")
        ports = _run_nmap(target, full=full)
        results["open_ports"] = ports
        console.print(f"  [green]✓ Found {len(ports)} open ports[/green]")

    output_file = Path(output_dir) / f"{target}_ports.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def _run_httpx(target: str) -> list:
    """Run httpx to probe live hosts."""
    try:
        result = subprocess.run(
            ["httpx", "-u", target, "-silent", "-json", "-title", "-tech-detect", "-status-code"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            hosts = []
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    hosts.append({
                        "url": data.get("url", ""),
                        "status": data.get("status_code"),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                    })
                except json.JSONDecodeError:
                    continue
            return hosts
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        console.print("  [yellow]httpx timed out[/yellow]")
    return []


def _probe_with_curl(target: str) -> list:
    """Probe hosts using curl as fallback."""
    schemes = ["https", "http"]
    hosts = []

    for scheme in schemes:
        url = f"{scheme}://{target}"
        try:
            result = subprocess.run(
                ["curl", "-sIL", "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True,
                text=True,
                timeout=15,
            )
            status = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            if status > 0:
                hosts.append({"url": url, "status": status})
        except (subprocess.TimeoutExpired, ValueError):
            pass

    return hosts


def _run_naabu(target: str, full: bool = False) -> list:
    """Run naabu for port scanning."""
    try:
        cmd = ["naabu", "-host", target, "-silent", "-json"]
        if not full:
            cmd.extend(["-top-ports", "1000"])
        else:
            cmd.extend(["-p", "-"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0 and result.stdout.strip():
            ports = []
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    ports.append({
                        "host": data.get("host", target),
                        "port": data.get("port"),
                        "protocol": data.get("protocol", "tcp"),
                    })
                except json.JSONDecodeError:
                    continue
            return ports
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        console.print("  [yellow]naabu timed out[/yellow]")
    return []


def _run_nmap(target: str, full: bool = False) -> list:
    """Run nmap for port scanning."""
    try:
        cmd = ["nmap", "-Pn", "-T4", "--open", "-oX", "-"]
        if not full:
            cmd.extend(["--top-ports", "1000"])
        else:
            cmd.extend(["-p-"])
        cmd.append(target)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            return _parse_nmap_xml(result.stdout)
    except FileNotFoundError:
        console.print("  [yellow]nmap not installed[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]nmap timed out[/yellow]")
    return []


def _parse_nmap_xml(xml_output: str) -> list:
    """Parse nmap XML output for open ports."""
    import xml.etree.ElementTree as ET

    ports = []
    try:
        root = ET.fromstring(xml_output)
        for port_elem in root.findall(".//port"):
            state = port_elem.find("state")
            if state is not None and state.get("state") == "open":
                ports.append({
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "service": port_elem.find("service").get("name", "") if port_elem.find("service") is not None else "",
                })
    except ET.ParseError:
        pass

    return ports
