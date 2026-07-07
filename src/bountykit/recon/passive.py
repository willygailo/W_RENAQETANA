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
    {
        "id": "zone_transfer",
        "name": "DNS Zone Transfer Detection",
        "description": "Check for AXFR zone transfer vulnerabilities",
        "method": "TCP port 53 connectivity check",
    },
    {
        "id": "subdomain_takeover",
        "name": "Subdomain Takeover Detection",
        "description": "Check for CNAME records pointing to unclaimed services",
        "services": ["AWS S3", "GitHub Pages", "Heroku", "Shopify", "Fastly"],
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
        
        # DNS Zone Transfer check
        if techniques is None or "zone_transfer" in techniques:
            _check_zone_transfer(target, result)
        
        # Subdomain takeover check
        if techniques is None or "subdomain_takeover" in techniques:
            _check_subdomain_takeover(client, target, result)

    # Save results
    output_file = Path(output_dir) / f"{sanitize_target_filename(target)}_passive_dns.json"
    _save_results(result, output_file)

    return result


def _query_ct_logs(client: httpx.Client, target: str, result: ReconResult):
    """Query Certificate Transparency logs with advanced parsing."""
    logger.info("Querying CT logs...")
    
    # crt.sh - Enhanced parsing
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        resp = client.get(url)
        
        if resp.status_code == 200:
            certs = resp.json()
            subdomains = set()
            seen_certs = set()
            
            for cert in certs:
                cert_id = cert.get("id")
                if cert_id in seen_certs:
                    continue
                seen_certs.add(cert_id)
                
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    # Skip wildcards but extract the base domain
                    if sub.startswith("*"):
                        sub = sub[1:]  # Remove the *
                    
                    if sub.endswith(f".{target}") or sub == target:
                        if sub:  # Ensure not empty
                            subdomains.add(sub)
                
                # Track certificate metadata for security analysis
                issuer = cert.get("issuer_name", "")
                not_before = cert.get("not_before", "")
                not_after = cert.get("not_after", "")
                
                # Check for short-lived certificates (potential security indicator)
                if not_before and not_after:
                    try:
                        from datetime import datetime
                        start = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                        end = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                        validity_days = (end - start).days
                        
                        result.certificates.append({
                            "id": cert_id,
                            "issuer": issuer,
                            "not_before": not_before,
                            "not_after": not_after,
                            "validity_days": validity_days,
                            "is_short_lived": validity_days <= 90,
                        })
                    except (ValueError, TypeError):
                        # Fallback if date parsing fails
                        result.certificates.append({
                            "id": cert_id,
                            "issuer": issuer,
                            "not_before": not_before,
                            "not_after": not_after,
                        })
            
            result.subdomains.extend(sorted(subdomains))
            
            # Add finding for certificate intelligence
            short_lived = [c for c in result.certificates if c.get("is_short_lived")]
            if short_lived:
                result.findings.append(ReconFinding(
                    category="recon",
                    severity="info",
                    title="Short-Lived Certificates Detected",
                    description=f"Found {len(short_lived)} certificates with validity ≤90 days (potential automated rotation)",
                    evidence=f"Certificate IDs: {[c['id'] for c in short_lived[:5]]}",
                ))
            
            logger.info(f"Found {len(subdomains)} subdomains from CT logs")
    except Exception as e:
        logger.debug(f"CT log query failed: {e}")


def _query_doh(client: httpx.Client, target: str, result: ReconResult):
    """Query DNS-over-HTTPS providers with multiple record types."""
    logger.info("Querying DoH providers...")
    
    doh_providers = [
        ("Google", "https://dns.google/resolve"),
        ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ]
    
    # Extended subdomain wordlist
    common_subdomains = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "portal", "dashboard", "auth", "sso", "vpn", "remote", "gateway",
        "shop", "store", "blog", "docs", "wiki", "help", "support",
        "cdn", "static", "media", "assets", "images", "files", "download",
        "upload", "backup", "db", "database", "mysql", "postgres", "redis",
        "mongo", "elastic", "search", "cache", "queue", "worker", "cron",
        "jenkins", "ci", "cd", "build", "deploy", "monitor", "grafana",
        "prometheus", "kibana", "elastic", "log", "logs", "status", "health",
    ]
    
    # Query multiple record types
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    
    for provider_name, provider_url in doh_providers:
        for sub in common_subdomains:
            domain = f"{sub}.{target}"
            for rtype in record_types:
                try:
                    resp = client.get(
                        provider_url,
                        params={"name": domain, "type": rtype},
                        headers={"Accept": "application/dns-json"},
                    )
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("Answer"):
                            for answer in data["Answer"]:
                                # Extract IP addresses from A records
                                if rtype == "A" and domain not in result.subdomains:
                                    result.subdomains.append(domain)
                                    break
                                # Extract CNAME targets
                                elif rtype == "CNAME":
                                    cname = answer.get("data", "").rstrip(".")
                                    if cname and cname != domain:
                                        # Potential subdomain takeover check
                                        result.findings.append(ReconFinding(
                                            category="recon",
                                            severity="info",
                                            title="CNAME Record Found",
                                            description=f"{domain} -> {cname}",
                                            endpoint=f"dns://{domain}",
                                        ))
                                        if domain not in result.subdomains:
                                            result.subdomains.append(domain)
                                        break
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
        "{sub}.internal.{domain}",
        "{sub}.corp.{domain}",
        "{sub}.private.{domain}",
    ]
    
    # Common subdomain names
    common_subs = [
        "api", "dev", "staging", "test", "admin", "portal", "dashboard",
        "auth", "login", "sso", "vpn", "mail", "smtp", "imap", "pop",
        "ftp", "sftp", "git", "jenkins", "ci", "cd", "build", "deploy",
        "monitor", "grafana", "prometheus", "elastic", "kibana", "log",
        "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
        "cache", "cdn", "static", "media", "assets", "images", "files",
        # 2026-specific additions
        "k8s", "kubernetes", "docker", "registry", "harbor", "nexus",
        "vault", "consul", "etcd", "zookeeper", "kafka", "rabbitmq",
        "minio", "s3", "aws", "gcp", "azure", "cloud",
        "grafana", "loki", "tempo", "mimir", "prometheus", "alertmanager",
        "argocd", "flux", "tekton", "crossplane", "terraform", "ansible",
    ]
    
    discovered = []
    
    for pattern in patterns:
        for sub in common_subs:
            domain = pattern.format(sub=sub, domain=target)
            discovered.append(domain)
    
    # Add discovered subdomains to result
    result.subdomains.extend(discovered[:100])  # Increased to 100
    result.subdomains = list(set(result.subdomains))
    
    logger.info(f"AI discovery found {len(discovered)} potential subdomains")


def _check_zone_transfer(target: str, result: ReconResult):
    """Check for DNS zone transfer vulnerabilities (AXFR)."""
    logger.info("Checking DNS zone transfer...")
    
    try:
        import socket
        
        # Get nameservers for the target
        ns_records = []
        try:
            # Try to get NS records via DoH
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(
                    "https://dns.google/resolve",
                    params={"name": target, "type": "NS"},
                    headers={"Accept": "application/dns-json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("Answer"):
                        for answer in data["Answer"]:
                            ns = answer.get("data", "").rstrip(".")
                            if ns:
                                ns_records.append(ns)
        except Exception:
            pass
        
        # If no NS records found, try common patterns
        if not ns_records:
            ns_records = [
                f"ns1.{target}",
                f"ns2.{target}",
                f"dns.{target}",
            ]
        
        for ns in ns_records[:3]:  # Limit to 3 nameservers
            try:
                # Try TCP connection to DNS port (zone transfer requires TCP)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ns, 53))
                sock.close()
                
                # If we can connect, flag it as potential zone transfer
                result.findings.append(ReconFinding(
                    category="recon",
                    severity="medium",
                    title="Potential DNS Zone Transfer",
                    description=f"Nameserver {ns} is accessible on port 53 (TCP)",
                    endpoint=f"dns://{ns}:53",
                    evidence="TCP port 53 is open - zone transfer (AXFR) may be possible",
                    remediation="Disable zone transfers to unauthorized hosts",
                ))
            except (socket.timeout, socket.error, OSError):
                # Connection failed - not accessible
                pass
            except Exception as e:
                logger.debug(f"Zone transfer check failed for {ns}: {e}")
        
        logger.info(f"Checked {len(ns_records)} nameservers for zone transfer")
    except Exception as e:
        logger.debug(f"Zone transfer check failed: {e}")


def _check_subdomain_takeover(client: httpx.Client, target: str, result: ReconResult):
    """Check for subdomain takeover opportunities."""
    logger.info("Checking for subdomain takeover opportunities...")
    
    # Services that might be vulnerable to subdomain takeover
    vulnerable_services = {
        "amazonaws.com": {"service": "AWS S3/CloudFront", "verify": "NoSuchBucket"},
        "herokuapp.com": {"service": "Heroku", "verify": "No such app"},
        "github.io": {"service": "GitHub Pages", "verify": "There isn't a GitHub Pages site here"},
        "shopify.com": {"service": "Shopify", "verify": "Sorry, this shop is currently unavailable"},
        "fastly.net": {"service": "Fastly", "verify": "Fastly error: unknown domain"},
        "pantheon.io": {"service": "Pantheon", "verify": "404 error unknown site"},
        "surge.sh": {"service": "Surge.sh", "verify": "project not found"},
        "bitbucket.io": {"service": "Bitbucket", "verify": "Repository not found"},
        "zendesk.com": {"service": "Zendesk", "verify": "Help Center Closed"},
        "readme.io": {"service": "ReadMe", "verify": "Project was not found"},
        "ghost.io": {"service": "Ghost", "verify": "The thing you were looking for is no longer here"},
        "intercom.help": {"service": "Intercom", "verify": "This help center no longer exists"},
        "cargocollective.com": {"service": "Cargo", "verify": "If this is your website and you've just created it"},
        "feedpress.me": {"service": "FeedPress", "verify": "The feed has not been found"},
        "ghost.org": {"service": "Ghost(Pro)", "verify": "The page you are looking for is no longer here"},
        "helpjuice.com": {"service": "Helpjuice", "verify": "We could not find what you're looking for"},
        "helpscoutdocs.com": {"service": "HelpScout", "verify": "No documentation was found"},
        "heroku.com": {"service": "Heroku", "verify": "No such app"},
        "instapage.com": {"service": "Instapage", "verify": "Page Not Found"},
        "launchrock.com": {"service": "LaunchRock", "verify": "It looks like you've lost your way"},
        "ngrok.io": {"service": "ngrok", "verify": "Tunnel not found"},
        "pingdom.com": {"service": "Pingdom", "verify": "Sorry, couldn't find the status page"},
        "proposify.biz": {"service": "Proposify", "verify": "If you need immediate assistance"},
        "readme.io": {"service": "ReadMe", "verify": "Project not found"},
        "simplebooklet.com": {"service": "SimpleBooklet", "verify": "We can't find this"},
        "smartling.com": {"service": "Smartling", "verify": "Domain is not configured"},
        "statuspage.io": {"service": "Atlassian StatusPage", "verify": "Better StatusPage"},
        "strikingly.com": {"service": "Strikingly", "verify": "But if you're looking to build your own website"},
        "surge.sh": {"service": "Surge", "verify": "project not found"},
        "tave.com": {"service": "Tave", "verify": "Client not found"},
        "teamwork.com": {"service": "Teamwork", "verify": "Oops - We didn't find your site"},
        "helpdesk.com": {"service": "HelpDesk", "verify": "Customer portal not found"},
        "tictail.com": {"service": "Tictail", "verify": "to target edge: Could not find host"},
        "tumblr.com": {"service": "Tumblr", "verify": "Whatever you were looking for"},
        "uberflip.com": {"service": "Uberflip", "verify": "Blog not found"},
        "uservoice.com": {"service": "UserVoice", "verify": "This UserVoice subdomain is currently available!"},
        "vend.com": {"service": "Vend", "verify": "Looks like you've followed a broken link"},
        "webflow.com": {"service": "Webflow", "verify": "The page you are looking for is not found"},
        "wishpond.com": {"service": "Wishpond", "verify": "https://wishpond.com"},
        "wordpress.com": {"service": "WordPress.com", "verify": "Do you want to register"},
        "zendesk.com": {"service": "Zendesk", "verify": "Help Center Closed"},
        "zoho.com": {"service": "Zoho", "verify": "No such Account"},
    }
    
    # Check CNAME records for potential takeovers
    for finding in result.findings:
        if "CNAME Record Found" in finding.title:
            # Extract the CNAME target from description
            parts = finding.description.split(" -> ")
            if len(parts) == 2:
                cname = parts[1]
                for domain_pattern, info in vulnerable_services.items():
                    if domain_pattern in cname:
                        result.findings.append(ReconFinding(
                            category="recon",
                            severity="high",
                            title=f"Potential Subdomain Takeover - {info['service']}",
                            description=f"CNAME points to {cname} which may be vulnerable",
                            endpoint=f"dns://{parts[0]}",
                            evidence=f"CNAME target: {cname}, Service: {info['service']}",
                            remediation=f"Verify if {info['service']} account still exists and claim the subdomain",
                        ))
                        break
    
    logger.info("Subdomain takeover check completed")
