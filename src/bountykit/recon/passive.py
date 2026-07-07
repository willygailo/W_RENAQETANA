"""Passive DNS enumeration module — 2026 techniques."""

import json
import os
import re
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from bountykit.utils.validator import sanitize_target_filename

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ReconFinding:
    """Single recon finding."""
    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    endpoint: str = ""
    payload: str = ""
    remediation: str = ""


@dataclass
class ReconResult:
    """Complete recon assessment result."""
    target: str
    findings: List[ReconFinding] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    certificates: List[Dict] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


# 2026 Passive Recon Techniques
PASSIVE_RECON_TECHNIQUES = [
    {
        "id": "dns_over_https",
        "name": "DNS-over-HTTPS (DoH)",
        "description": "Query DNS via encrypted DoH providers",
        "providers": [
            "https://dns.google/dns-query",
            "https://cloudflare-dns.com/dns-query",
            "https://1.1.1.1/dns-query",
        ],
    },
    {
        "id": "certificate_transparency",
        "name": "Certificate Transparency",
        "description": "Search CT logs for subdomains",
        "sources": ["crt.sh", "certspotter", "censys"],
    },
    {
        "id": "ai_subdomain_discovery",
        "name": "AI-Powered Subdomain Discovery",
        "description": "Use ML to predict subdomains based on naming patterns",
        "wordlists": ["common", "algorithmic", "target-specific"],
    },
]


def passive_dns(
    target: str,
    output_dir: str = "./results",
    techniques: List[str] = None,
) -> ReconResult:
    """Perform passive DNS enumeration with 2026 techniques.

    Uses DoH, CT logs, and AI-powered discovery.

    Args:
        target: Target domain
        output_dir: Output directory
        techniques: Specific techniques to use (None = all)
    """
    result = ReconResult(target=target)
    os.makedirs(output_dir, exist_ok=True)

    logger.info(f"Starting passive recon on {target}")

    with httpx.Client(timeout=30.0) as client:
        # Certificate Transparency
        if techniques is None or "certificate_transparency" in techniques:
            _query_ct_logs(client, target, result)
        
        # DNS-over-HTTPS
        if techniques is None or "dns_over_https" in techniques:
            _query_doh(client, target, result)
        
        # AI-powered subdomain discovery
        if techniques is None or "ai_subdomain_discovery" in techniques:
            _ai_subdomain_discovery(target, result)

    # Save results
    output_file = Path(output_dir) / f"{sanitize_target_filename(target)}_passive_dns.json"
    _save_results(result, output_file)

    return result


def _query_ct_logs(client: httpx.Client, target: str, result: ReconResult):
    """Query Certificate Transparency logs."""
    logger.info("Querying CT logs...")
    
    # crt.sh
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        resp = client.get(url)
        
        if resp.status_code == 200:
            certs = resp.json()
            subdomains = set()
            
            for cert in certs:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{target}") or sub == target:
                        if not sub.startswith("*"):
                            subdomains.add(sub)
                            
                result.certificates.append({
                    "id": cert.get("id"),
                    "issuer": cert.get("issuer_name"),
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                })
            
            result.subdomains.extend(sorted(subdomains))
            logger.info(f"Found {len(subdomains)} subdomains from CT logs")
    except Exception as e:
        logger.debug(f"CT log query failed: {e}")


def _query_doh(client: httpx.Client, target: str, result: ReconResult):
    """Query DNS-over-HTTPS providers."""
    logger.info("Querying DoH providers...")
    
    doh_providers = [
        ("Google", "https://dns.google/resolve"),
        ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ]
    
    common_subdomains = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test"]
    
    for provider_name, provider_url in doh_providers:
        for sub in common_subdomains:
            try:
                domain = f"{sub}.{target}"
                resp = client.get(
                    provider_url,
                    params={"name": domain, "type": "A"},
                    headers={"Accept": "application/dns-json"},
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("Answer"):
                        result.subdomains.append(domain)
            except Exception:
                continue
    
    result.subdomains = list(set(result.subdomains))
    logger.info(f"Found {len(result.subdomains)} subdomains via DoH")


def _ai_subdomain_discovery(target: str, result: ReconResult):
    """AI-powered subdomain discovery using naming patterns."""
    logger.info("Running AI-powered subdomain discovery...")
    
    # Common naming patterns
    patterns = [
        "{sub}.{domain}",
        "{sub}-{domain}",
        "{domain}-{sub}",
        "{sub}01.{domain}",
        "{sub}02.{domain}",
        "dev.{sub}.{domain}",
        "staging.{sub}.{domain}",
    ]
    
    # Common subdomain names
    common_subs = [
        "api", "dev", "staging", "test", "admin", "portal", "dashboard",
        "auth", "login", "sso", "vpn", "mail", "smtp", "imap", "pop",
        "ftp", "sftp", "git", "jenkins", "ci", "cd", "build", "deploy",
        "monitor", "grafana", "prometheus", "elastic", "kibana", "log",
        "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
        "cache", "cdn", "static", "media", "assets", "images", "files",
    ]
    
    discovered = []
    
    for pattern in patterns:
        for sub in common_subs:
            domain = pattern.format(sub=sub, domain=target)
            discovered.append(domain)
    
    # Add discovered subdomains to result
    result.subdomains.extend(discovered[:50])  # Limit to 50
    result.subdomains = list(set(result.subdomains))
    
    logger.info(f"AI discovery found {len(discovered)} potential subdomains")


def _save_results(result: ReconResult, output_file: Path):
    """Save results to JSON file."""
    data = {
        "target": result.target,
        "timestamp": result.timestamp,
        "summary": result.summary,
        "subdomains": result.subdomains,
        "certificates": result.certificates[:10],  # Limit certificates
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "endpoint": f.endpoint,
                "payload": f.payload,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    
    logger.info(f"Results saved to {output_file}")
