"""CVE chaining and combination attack module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 11:
- CVE combination patterns
- Attack chain building
- Multi-step exploitation paths
- MITRE ATT&CK mapping
- Automated chain detection
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field
import time

from rich.console import Console

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()

# MITRE ATT&CK techniques commonly used in CVE chains
ATTACK_TECHNIQUES = {
    "initial_access": {
        "T1190": "Exploit Public-Facing Application",
        "T1133": "External Remote Services",
        "T1078": "Valid Accounts",
        "T1566": "Phishing",
    },
    "execution": {
        "T1059": "Command and Scripting Interpreter",
        "T1203": "Exploitation for Client Execution",
        "T1047": "Windows Management Instrumentation",
    },
    "persistence": {
        "T1053": "Scheduled Task/Job",
        "T1543": "Create or Modify System Process",
        "T1136": "Create Account",
    },
    "privilege_escalation": {
        "T1068": "Exploitation for Privilege Escalation",
        "T1055": "Process Injection",
        "T1134": "Access Token Manipulation",
    },
    "defense_evasion": {
        "T1027": "Obfuscated Files or Information",
        "T1070": "Indicator Removal",
        "T1562": "Impair Defenses",
    },
    "credential_access": {
        "T1003": "OS Credential Dumping",
        "T1110": "Brute Force",
        "T1552": "Unsecured Credentials",
    },
    "lateral_movement": {
        "T1021": "Remote Services",
        "T1570": "Lateral Tool Transfer",
    },
    "exfiltration": {
        "T1041": "Exfiltration Over C2 Channel",
        "T1567": "Exfiltration Over Web Service",
    },
}

# Common CVE chain patterns with ATT&CK mapping
CVE_CHAIN_PATTERNS = {
    "rce_chain": {
        "name": "Remote Code Execution Chain",
        "description": "Chain CVEs to achieve RCE",
        "steps": [
            {"type": "recon", "description": "Discover vulnerable services", "attack_id": "T1592"},
            {"type": "initial_access", "description": "Exploit public-facing app", "attack_id": "T1190"},
            {"type": "execution", "description": "Execute commands on target", "attack_id": "T1059"},
            {"type": "privilege_escalation", "description": "Escalate to root/admin", "attack_id": "T1068"},
        ],
    },
    "data_exfil": {
        "name": "Data Exfiltration Chain",
        "description": "Chain CVEs to exfiltrate data",
        "steps": [
            {"type": "recon", "description": "Identify data storage", "attack_id": "T1083"},
            {"type": "auth_bypass", "description": "Bypass authentication", "attack_id": "T1078"},
            {"type": "data_access", "description": "Access sensitive data", "attack_id": "T1005"},
            {"type": "exfil", "description": "Exfiltrate data", "attack_id": "T1041"},
        ],
    },
    "lateral_movement": {
        "name": "Lateral Movement Chain",
        "description": "Chain CVEs for lateral movement",
        "steps": [
            {"type": "initial_access", "description": "Gain initial foothold", "attack_id": "T1190"},
            {"type": "credential_harvest", "description": "Harvest credentials", "attack_id": "T1003"},
            {"type": "pivoting", "description": "Move to other systems", "attack_id": "T1021"},
            {"type": "domain_dominance", "description": "Achieve domain dominance", "attack_id": "T1078"},
        ],
    },
    "supply_chain": {
        "name": "Supply Chain Attack Chain",
        "description": "Compromise software supply chain",
        "steps": [
            {"type": "recon", "description": "Identify dependencies", "attack_id": "T1195"},
            {"type": "compromise", "description": "Inject malicious code", "attack_id": "T1195.002"},
            {"type": "distribution", "description": "Distribute poisoned package", "attack_id": "T1195.002"},
            {"type": "execution", "description": "Trigger in target builds", "attack_id": "T1059"},
        ],
    },
    "container_escape": {
        "name": "Container Escape Chain",
        "description": "Escape container to host",
        "steps": [
            {"type": "recon", "description": "Enumerate container env", "attack_id": "T1610"},
            {"type": "container_escape", "description": "Escape to host", "attack_id": "T1611"},
            {"type": "privilege_escalation", "description": "Root on host", "attack_id": "T1068"},
        ],
    },
}

# Known CVE chain combinations (expanded)
KNOWN_CHAINS = [
    {
        "name": "Log4Shell + ProxyLogon",
        "cves": ["CVE-2021-44228", "CVE-2021-26855"],
        "description": "Log4Shell RCE combined with Exchange SSRF for full compromise",
        "severity": "critical",
        "attack_path": ["T1190", "T1059", "T1078"],
        "products": ["Apache Log4j", "Microsoft Exchange"],
    },
    {
        "name": "Spring4Shell + SpringShell",
        "cves": ["CVE-2022-22965", "CVE-2022-22963"],
        "description": "Spring Framework RCE chain via class loader manipulation",
        "severity": "critical",
        "attack_path": ["T1190", "T1059"],
        "products": ["Spring Framework", "Spring Cloud Function"],
    },
    {
        "name": "ProxyShell + ProxyLogon",
        "cves": ["CVE-2021-34473", "CVE-2021-31207", "CVE-2021-26855"],
        "description": "Exchange Server chain: pre-auth SSRF + auth bypass + RCE",
        "severity": "critical",
        "attack_path": ["T1190", "T1078", "T1059"],
        "products": ["Microsoft Exchange Server"],
    },
    {
        "name": "BlueKeep + EternalBlue",
        "cves": ["CVE-2019-0708", "CVE-2017-0144"],
        "description": "RDP + SMB RCE chain for network worm capability",
        "severity": "critical",
        "attack_path": ["T1210", "T1021.002"],
        "products": ["Windows RDP", "Windows SMB"],
    },
    {
        "name": "PrintNightmare + Print Spooler",
        "cves": ["CVE-2021-34527", "CVE-2021-1675"],
        "description": "Windows Print Spooler RCE for domain escalation",
        "severity": "critical",
        "attack_path": ["T1190", "T1068"],
        "products": ["Windows Print Spooler"],
    },
    {
        "name": "Dirty Pipe + Dirty COW",
        "cves": ["CVE-2022-0847", "CVE-2016-5195"],
        "description": "Linux kernel privilege escalation chain",
        "severity": "high",
        "attack_path": ["T1068"],
        "products": ["Linux Kernel"],
    },
    {
        "name": "Heartbleed + Shellshock",
        "cves": ["CVE-2014-0160", "CVE-2014-6271"],
        "description": "TLS memory disclosure + bash RCE",
        "severity": "critical",
        "attack_path": ["T1040", "T1059.004"],
        "products": ["OpenSSL", "GNU Bash"],
    },
    {
        "name": "Confluence + OGNL Injection",
        "cves": ["CVE-2022-26134", "CVE-2021-26084"],
        "description": "Atlassian Confluence OGNL injection RCE chain",
        "severity": "critical",
        "attack_path": ["T1190", "T1059"],
        "products": ["Atlassian Confluence"],
    },
]

# CVE type classification for automated chain detection
CVE_TYPE_PATTERNS = {
    "ssrf": {
        "keywords": ["ssrf", "server-side request forgery", "url validation"],
        "chains_with": ["rce", "file_read", "credential_theft"],
        "attack_id": "T1190",
    },
    "rce": {
        "keywords": ["remote code execution", "command injection", "code injection"],
        "chains_with": ["privilege_escalation", "lateral_movement"],
        "attack_id": "T1059",
    },
    "sql_injection": {
        "keywords": ["sql injection", "sqli", "database injection"],
        "chains_with": ["data_exfil", "auth_bypass"],
        "attack_id": "T1190",
    },
    "auth_bypass": {
        "keywords": ["authentication bypass", "auth bypass", "login bypass"],
        "chains_with": ["rce", "data_access", "privilege_escalation"],
        "attack_id": "T1078",
    },
    "file_read": {
        "keywords": ["file read", "path traversal", "directory traversal", "lfi"],
        "chains_with": ["rce", "credential_theft", "ssrf"],
        "attack_id": "T1083",
    },
    "deserialization": {
        "keywords": ["deserialization", "unserialize", "pickle", "yaml.load"],
        "chains_with": ["rce", "auth_bypass"],
        "attack_id": "T1059",
    },
    "privilege_escalation": {
        "keywords": ["privilege escalation", "elevation", "sudo", "suid"],
        "chains_with": ["lateral_movement", "persistence"],
        "attack_id": "T1068",
    },
    "xss": {
        "keywords": ["cross-site scripting", "xss", "reflected xss", "stored xss"],
        "chains_with": ["csrf", "session_hijack", "credential_theft"],
        "attack_id": "T1189",
    },
    "lfi": {
        "keywords": ["local file inclusion", "lfi", "path traversal", "file inclusion"],
        "chains_with": ["rce", "ssrf", "credential_theft"],
        "attack_id": "T1083",
    },
    "open_redirect": {
        "keywords": ["open redirect", "url redirect", "redirect injection"],
        "chains_with": ["phishing", "oauth_bypass", "xss"],
        "attack_id": "T1189",
    },
}


def classify_cve_type(cve_id: str, description: str = "") -> str:
    """Classify a CVE's vulnerability type from its description.

    Args:
        cve_id: CVE identifier
        description: Optional CVE description for keyword matching

    Returns:
        Vulnerability type string (e.g., 'rce', 'ssrf', 'xss')
    """
    desc_lower = description.lower()

    for vtype, info in CVE_TYPE_PATTERNS.items():
        for keyword in info["keywords"]:
            if keyword in desc_lower:
                return vtype

    return "unknown"


def analyze_chains(
    cve_list: list,
    output_dir: str = "./results",
) -> dict:
    """Analyze potential attack chains from a list of CVEs.

    Checks known chains, classifies types, suggests chain partners,
    and maps to MITRE ATT&CK techniques.

    Args:
        cve_list: List of CVE IDs to analyze
        output_dir: Output directory
    """
    results = {
        "method": "cve_chain_analysis",
        "cves_analyzed": cve_list,
        "possible_chains": [],
        "attack_paths": [],
        "attack_techniques": [],
        "chain_suggestions": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Analyzing {len(cve_list)} CVEs for chain potential...[/dim]")

    # Check for known chains
    for chain in KNOWN_CHAINS:
        chain_cves = set(chain["cves"])
        analyzed_cves = set(cve_list)

        if chain_cves.issubset(analyzed_cves):
            results["possible_chains"].append(chain)
            console.print(f"  [bold red]Known chain found: {chain['name']}[/bold red]")

    # Generate attack paths with ATT&CK mapping
    for cve in cve_list:
        attack_path = {
            "cve": cve,
            "potential_chains": [],
            "type": classify_cve_type(cve),
            "attack_id": "",
        }

        # Check if CVE can be part of a chain
        for chain in KNOWN_CHAINS:
            if cve in chain["cves"]:
                attack_path["potential_chains"].append(chain["name"])
                if chain.get("attack_path"):
                    attack_path["attack_id"] = chain["attack_path"][0]

        results["attack_paths"].append(attack_path)

    # Collect unique ATT&CK technique IDs
    all_attack_ids = set()
    for path in results["attack_paths"]:
        if path["attack_id"]:
            all_attack_ids.add(path["attack_id"])
    for chain in results["possible_chains"]:
        for tid in chain.get("attack_path", []):
            all_attack_ids.add(tid)

    # Map ATT&CK IDs to descriptions
    for tactic, techniques in ATTACK_TECHNIQUES.items():
        for tid, desc in techniques.items():
            if tid in all_attack_ids:
                results["attack_techniques"].append({
                    "id": tid,
                    "tactic": tactic,
                    "description": desc,
                })

    # Suggest chain partners based on CVE types
    cve_types = set(p["type"] for p in results["attack_paths"] if p["type"] != "unknown")
    for vtype in cve_types:
        if vtype in CVE_TYPE_PATTERNS:
            chains_with = CVE_TYPE_PATTERNS[vtype].get("chains_with", [])
            for partner_type in chains_with:
                if partner_type not in cve_types:
                    results["chain_suggestions"].append({
                        "current_type": vtype,
                        "suggested_type": partner_type,
                        "reason": f"{vtype} chains with {partner_type} for higher impact",
                    })

    if results["possible_chains"]:
        console.print(
            f"  [bold red]Found {len(results['possible_chains'])} known attack chains[/bold red]"
        )
    if results["chain_suggestions"]:
        console.print(
            f"  [cyan]Suggested chain partners: {len(results['chain_suggestions'])}[/cyan]"
        )

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
    """Build a structured attack path with ATT&CK mapping.

    Args:
        target: Target system
        cves: List of applicable CVEs
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "attack_path",
        "phases": [],
        "attack_timeline": [],
        "chain_patterns_used": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Building attack path for {target}...[/dim]")

    # Classify all CVEs
    cve_types = {}
    for cve in cves:
        vtype = classify_cve_type(cve)
        cve_types[cve] = vtype

    # Determine which chain patterns apply
    applicable_patterns = []
    for pattern_name, pattern in CVE_CHAIN_PATTERNS.items():
        pattern_types = set(s["type"] for s in pattern["steps"])
        cve_type_set = set(cve_types.values())
        if pattern_types & cve_type_set:
            applicable_patterns.append(pattern_name)

    results["chain_patterns_used"] = applicable_patterns

    # Phase 1: Reconnaissance
    recon_step = CVE_CHAIN_PATTERNS.get("rce_chain", {}).get("steps", [{}])[0]
    results["phases"].append({
        "phase": 1,
        "name": "Reconnaissance",
        "description": "Gather information about target",
        "tools": ["nmap", "httpx", "nuclei", "subfinder"],
        "cves_applicable": [],
        "attack_id": recon_step.get("attack_id", ""),
    })

    # Phase 2: Vulnerability Scanning
    results["phases"].append({
        "phase": 2,
        "name": "Vulnerability Scanning",
        "description": "Identify vulnerable services",
        "tools": ["nuclei", "nmap", "nikto"],
        "cves_applicable": cves,
        "attack_id": "T1592",
    })

    # Phase 3: Exploitation
    results["phases"].append({
        "phase": 3,
        "name": "Exploitation",
        "description": "Attempt to exploit vulnerabilities",
        "tools": _get_exploit_tools(cve_types),
        "cves_applicable": cves,
        "attack_id": "T1190",
    })

    # Phase 4: Post-Exploitation
    results["phases"].append({
        "phase": 4,
        "name": "Post-Exploitation",
        "description": "Escalate privileges and move laterally",
        "tools": ["mimikatz", "bloodhound", "linpeas"],
        "cves_applicable": [],
        "attack_id": "T1068",
    })

    # Phase 5: Reporting
    results["phases"].append({
        "phase": 5,
        "name": "Reporting",
        "description": "Document findings and create report",
        "tools": ["bountykit report"],
        "cves_applicable": [],
    })

    # Build attack timeline
    for phase in results["phases"]:
        attack_id = phase.get("attack_id", "")
        if attack_id:
            results["attack_timeline"].append({
                "phase": phase["phase"],
                "name": phase["name"],
                "attack_id": attack_id,
            })

    console.print(
        f"  [green]Attack path built: {len(results['phases'])} phases, "
        f"{len(results['chain_patterns_used'])} chain patterns[/green]"
    )

    # Save results
    output_file = Path(output_dir) / "attack_path.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def suggest_chain_partners(cve_types: list) -> list:
    """Suggest chain partner types based on current CVE types.

    Args:
        cve_types: List of CVE vulnerability types

    Returns:
        List of suggested chain partners
    """
    suggestions = []
    seen = set()

    for vtype in cve_types:
        if vtype in CVE_TYPE_PATTERNS:
            for partner in CVE_TYPE_PATTERNS[vtype].get("chains_with", []):
                key = f"{vtype}->{partner}"
                if key not in seen and partner not in cve_types:
                    seen.add(key)
                    suggestions.append({
                        "current": vtype,
                        "suggested": partner,
                        "reason": f"{vtype} + {partner} creates high-impact chain",
                    })

    return suggestions


def get_chain_patterns() -> dict:
    """Get all available CVE chain patterns."""
    return CVE_CHAIN_PATTERNS


def get_known_chains() -> list:
    """Get all known CVE chain combinations."""
    return KNOWN_CHAINS


def get_attack_techniques() -> dict:
    """Get all MITRE ATT&CK technique mappings."""
    return ATTACK_TECHNIQUES


def _get_exploit_tools(cve_types: dict) -> list:
    """Determine exploitation tools based on CVE types."""
    tools = ["metasploit"]

    type_to_tool = {
        "rce": ["metasploit", "custom_exploits"],
        "ssrf": ["curl", "ssrfmap"],
        "sql_injection": ["sqlmap", "havij"],
        "xss": ["dalfox", "xsser"],
        "deserialization": ["ysoserial", "jexboss"],
        "lfi": ["liffy", "dotdotpwn"],
        "auth_bypass": ["hydra", "custom_scripts"],
        "file_read": ["dotdotpwn", "custom_scripts"],
        "privilege_escalation": ["linpeas", "winpeas", "linenum"],
        "open_redirect": ["redirect_mapper", "custom_scripts"],
    }

    for cve, vtype in cve_types.items():
        if vtype in type_to_tool:
            for tool in type_to_tool[vtype]:
                if tool not in tools:
                    tools.append(tool)

    return tools
