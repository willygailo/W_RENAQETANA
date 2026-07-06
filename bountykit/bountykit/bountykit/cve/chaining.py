"""CVE chaining and combination attack module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 11:
- CVE combination patterns
- Attack chain building
- Multi-step exploitation paths
"""

import json
import os
from pathlib import Path

from rich.console import Console

console = Console()

# Common CVE chain patterns
CVE_CHAIN_PATTERNS = {
    "rce_chain": {
        "name": "Remote Code Execution Chain",
        "description": "Chain CVEs to achieve RCE",
        "steps": [
            {"type": "recon", "description": "Discover vulnerable services"},
            {"type": "info_disclosure", "description": "Gather information for exploitation"},
            {"type": "initial_access", "description": "Gain initial access"},
            {"type": "privilege_escalation", "description": "Escalate to root/admin"},
        ],
    },
    "data_exfil": {
        "name": "Data Exfiltration Chain",
        "description": "Chain CVEs to exfiltrate data",
        "steps": [
            {"type": "recon", "description": "Identify data storage"},
            {"type": "auth_bypass", "description": "Bypass authentication"},
            {"type": "data_access", "description": "Access sensitive data"},
            {"type": "exfil", "description": "Exfiltrate data"},
        ],
    },
    "lateral_movement": {
        "name": "Lateral Movement Chain",
        "description": "Chain CVEs for lateral movement",
        "steps": [
            {"type": "initial_access", "description": "Gain initial foothold"},
            {"type": "credential_harvest", "description": "Harvest credentials"},
            {"type": "pivoting", "description": "Move to other systems"},
            {"type": "domain_dominance", "description": "Achieve domain dominance"},
        ],
    },
}

# Known CVE chain combinations
KNOWN_CHAINS = [
    {
        "name": "Log4Shell + ProxyLogon",
        "cves": ["CVE-2021-44228", "CVE-2021-26855"],
        "description": "Log4Shell RCE combined with Exchange SSRF",
        "severity": "critical",
    },
    {
        "name": "Spring4Shell + SpringShell",
        "cves": ["CVE-2022-22965", "CVE-2022-22963"],
        "description": "Spring Framework RCE chain",
        "severity": "critical",
    },
    {
        "name": "ProxyShell + ProxyLogon",
        "cves": ["CVE-2021-34473", "CVE-2021-31207", "CVE-2021-26855"],
        "description": "Exchange Server chain attack",
        "severity": "critical",
    },
    {
        "name": "BlueKeep + EternalBlue",
        "cves": ["CVE-2019-0708", "CVE-2017-0144"],
        "description": "RDP + SMB RCE chain",
        "severity": "critical",
    },
]


def analyze_chains(
    cve_list: list,
    output_dir: str = "./results",
) -> dict:
    """Analyze potential attack chains from a list of CVEs.

    Args:
        cve_list: List of CVE IDs to analyze
        output_dir: Output directory
    """
    results = {
        "method": "cve_chain_analysis",
        "cves_analyzed": cve_list,
        "possible_chains": [],
        "attack_paths": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Analyzing {len(cve_list)} CVEs for chain potential...[/dim]")

    # Check for known chains
    for chain in KNOWN_CHAINS:
        chain_cves = set(chain["cves"])
        analyzed_cves = set(cve_list)

        if chain_cves.issubset(analyzed_cves):
            results["possible_chains"].append(chain)
            console.print(f"  [bold red]⚠ Known chain found: {chain['name']}[/bold red]")

    # Generate attack paths
    for cve in cve_list:
        # Determine CVE type based on ID pattern
        attack_path = {
            "cve": cve,
            "potential_chains": [],
        }

        # Check if CVE can be part of a chain
        for chain in KNOWN_CHAINS:
            if cve in chain["cves"]:
                attack_path["potential_chains"].append(chain["name"])

        results["attack_paths"].append(attack_path)

    if results["possible_chains"]:
        console.print(
            f"  [bold red]⚠ Found {len(results['possible_chains'])} known attack chains[/bold red]"
        )
    else:
        console.print(f"  [green]✓ No known chains found for these CVEs[/green]")

    # Save results
    output_file = Path(output_dir) / "cve_chains.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def build_attack_path(
    target: str,
    cves: list,
    output_dir: str = "./results",
) -> dict:
    """Build a structured attack path for target.

    Args:
        target: Target system
        cves: List of applicable CVEs
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "attack_path",
        "phases": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Building attack path for {target}...[/dim]")

    # Phase 1: Reconnaissance
    results["phases"].append({
        "phase": 1,
        "name": "Reconnaissance",
        "description": "Gather information about target",
        "tools": ["nmap", "httpx", "nuclei"],
        "cves_applicable": [],
    })

    # Phase 2: Vulnerability Scanning
    results["phases"].append({
        "phase": 2,
        "name": "Vulnerability Scanning",
        "description": "Identify vulnerable services",
        "tools": ["nuclei", "nmap"],
        "cves_applicable": cves,
    })

    # Phase 3: Exploitation
    results["phases"].append({
        "phase": 3,
        "name": "Exploitation",
        "description": "Attempt to exploit vulnerabilities",
        "tools": ["metasploit", "custom_exploits"],
        "cves_applicable": cves,
    })

    # Phase 4: Post-Exploitation
    results["phases"].append({
        "phase": 4,
        "name": "Post-Exploitation",
        "description": "Escalate privileges and move laterally",
        "tools": ["mimikatz", "bloodhound"],
        "cves_applicable": [],
    })

    # Phase 5: Reporting
    results["phases"].append({
        "phase": 5,
        "name": "Reporting",
        "description": "Document findings and create report",
        "tools": ["bountykit report"],
        "cves_applicable": [],
    })

    console.print(f"  [green]✓ Attack path built with {len(results['phases'])} phases[/green]")

    # Save results
    output_file = Path(output_dir) / "attack_path.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def get_chain_patterns() -> dict:
    """Get all available CVE chain patterns.

    Returns:
        Dictionary of chain patterns
    """
    return CVE_CHAIN_PATTERNS


def get_known_chains() -> list:
    """Get all known CVE chain combinations.

    Returns:
        List of known chains
    """
    return KNOWN_CHAINS
