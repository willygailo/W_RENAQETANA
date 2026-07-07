"""Active reconnaissance — 2026 techniques."""

import json
import os
import subprocess
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
    live_hosts: List[Dict] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


# 2026 Active Recon Techniques
ACTIVE_RECON_TECHNIQUES = [
    {
        "id": "http2_fingerprint",
        "name": "HTTP/2 Fingerprinting",
        "description": "Detect HTTP/2 support and fingerprint ALPN negotiation",
    },
    {
        "id": "certificate_transparency",
        "name": "Certificate Transparency",
        "description": "Search CT logs for subdomains",
    },
    {
        "id": "advanced_http_fingerprint",
        "name": "Advanced HTTP Fingerprinting",
        "description": "Detect server software, WAF, CDN with 2026 techniques",
    },
    {
        "id": "web_technology_detection",
        "name": "Web Technology Detection",
        "description": "Identify frameworks, libraries, and versions",
    },
]


def probe_hosts(
    target: str,
    output_dir: str = "./results",
    techniques: List[str] = None,
) -> ReconResult:
    """Probe live hosts with 2026 techniques.

    Uses HTTP/2 fingerprinting, CT logs, and advanced detection.

    Args:
        target: Target domain
        output_dir: Output directory
        techniques: Specific techniques to use (None = all)
    """
    result = ReconResult(target=target)
    os.makedirs(output_dir, exist_ok=True)

    logger.info(f"Starting active recon on {target}")

    with httpx.Client(
        timeout=30.0,
        follow_redirects=True,
        headers={"User-Agent": "bountykit/0.1 (authorized research)"},
    ) as client:
        # HTTP/2 fingerprinting
        if techniques is None or "http2_fingerprint" in techniques:
            _http2_fingerprint(client, target, result)
        
        # Certificate Transparency
        if techniques is None or "certificate_transparency" in techniques:
            _query_ct_logs(client, target, result)
        
        # Advanced HTTP fingerprinting
        if techniques is None or "advanced_http_fingerprint" in techniques:
            _advanced_http_fingerprint(client, target, result)
        
        # Web technology detection
        if techniques is None or "web_technology_detection" in techniques:
            _web_technology_detection(client, target, result)

    # Save results
    output_file = Path(output_dir) / f"{sanitize_target_filename(target)}_active_recon.json"
    _save_results(result, output_file)

    return result


def _http2_fingerprint(client: httpx.Client, target: str, result: ReconResult):
    """Detect HTTP/2 support and fingerprint ALPN."""
    logger.info("Checking HTTP/2 support...")
    
    try:
        # Try HTTP/2
        url = f"https://{target}"
        resp = client.get(url, extensions={"http2": True})
        
        http_version = resp.http_version
        if http_version == "HTTP/2":
            result.findings.append(ReconFinding(
                category="recon",
                severity="info",
                title="HTTP/2 Supported",
                description=f"Target supports {http_version}",
                endpoint=url,
            ))
            
            # Check for HTTP/2 specific issues
            if "server" in resp.headers:
                server = resp.headers["server"]
                if "nginx" in server.lower() and "1.25" in server:
                    result.findings.append(ReconFinding(
                        category="recon",
                        severity="low",
                        title="Nginx HTTP/2 Potential Issue",
                        description="Nginx 1.25.x had HTTP/2 rapid reset vulnerability",
                        endpoint=url,
                        remediation="Update nginx to latest stable version",
                    ))
    except Exception as e:
        logger.debug(f"HTTP/2 check failed: {e}")


def _query_ct_logs(client: httpx.Client, target: str, result: ReconResult):
    """Query Certificate Transparency logs."""
    logger.info("Querying CT logs...")
    
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
            
            result.live_hosts.extend([{"url": f"https://{sub}"} for sub in subdomains])
            logger.info(f"Found {len(subdomains)} subdomains from CT logs")
    except Exception as e:
        logger.debug(f"CT log query failed: {e}")


def _advanced_http_fingerprint(client: httpx.Client, target: str, result: ReconResult):
    """Advanced HTTP fingerprinting with 2026 techniques."""
    logger.info("Running advanced HTTP fingerprinting...")
    
    url = f"https://{target}"
    
    try:
        resp = client.get(url)
        
        # Check server header
        server = resp.headers.get("server", "").lower()
        
        # Detect WAF/CDN
        waf_indicators = {
            "cloudflare": "Cloudflare CDN",
            "akamai": "Akamai CDN",
            "incapsula": "Incapsula WAF",
            "sucuri": "Sucuri WAF",
            "wordfence": "Wordfence WAF",
            "modsecurity": "ModSecurity WAF",
            "cloudfront": "AWS CloudFront",
        }
        
        for indicator, name in waf_indicators.items():
            if indicator in server or any(indicator in v.lower() for v in resp.headers.values()):
                result.findings.append(ReconFinding(
                    category="recon",
                    severity="info",
                    title=f"Detected {name}",
                    description=f"Target uses {name}",
                    endpoint=url,
                ))
        
        # Check for security headers
        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "x-xss-protection",
        ]
        
        missing_headers = [h for h in security_headers if h not in resp.headers]
        
        if missing_headers:
            result.findings.append(ReconFinding(
                category="recon",
                severity="low",
                title="Missing Security Headers",
                description=f"Missing headers: {', '.join(missing_headers)}",
                endpoint=url,
                remediation="Add missing security headers",
            ))
        
        # Check for server version disclosure
        if server:
            result.findings.append(ReconFinding(
                category="recon",
                severity="info",
                title="Server Version Disclosed",
                description=f"Server header reveals: {server}",
                endpoint=url,
                remediation="Remove or obfuscate server header",
            ))
            
    except Exception as e:
        logger.debug(f"HTTP fingerprint failed: {e}")


def _web_technology_detection(client: httpx.Client, target: str, result: ReconResult):
    """Detect web technologies, frameworks, and libraries."""
    logger.info("Detecting web technologies...")
    
    url = f"https://{target}"
    
    try:
        resp = client.get(url)
        headers = resp.headers
        body = resp.text.lower()
        
        # Technology detection patterns
        tech_patterns = {
            "x-powered-by": {"PHP": "php", "Express": "nodejs", "ASP.NET": "dotnet"},
            "x-generator": {"WordPress": "wordpress", "Drupal": "drupal", "Joomla": "joomla"},
            "set-cookie": {"PHPSESSID": "php", "JSESSIONID": "java", "connect.sid": "nodejs"},
        }
        
        detected_techs = []
        
        # Check headers
        for header, patterns in tech_patterns.items():
            header_value = headers.get(header, "").lower()
            for tech_name, tech_id in patterns.items():
                if tech_name.lower() in header_value:
                    detected_techs.append(tech_name)
        
        # Check body patterns
        body_patterns = {
            "wp-content": "WordPress",
            "drupal.js": "Drupal",
            "joomla": "Joomla",
            "react": "React",
            "vue": "Vue.js",
            "angular": "Angular",
            "next.js": "Next.js",
            "nuxt": "Nuxt.js",
        }
        
        for pattern, tech_name in body_patterns.items():
            if pattern in body:
                detected_techs.append(tech_name)
        
        if detected_techs:
            result.findings.append(ReconFinding(
                category="recon",
                severity="info",
                title="Web Technologies Detected",
                description=f"Detected technologies: {', '.join(set(detected_techs))}",
                endpoint=url,
            ))
            
    except Exception as e:
        logger.debug(f"Technology detection failed: {e}")


def _save_results(result: ReconResult, output_file: Path):
    """Save results to JSON file."""
    data = {
        "target": result.target,
        "timestamp": result.timestamp,
        "summary": result.summary,
        "live_hosts": result.live_hosts[:10],
        "open_ports": result.open_ports,
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
    logger.info("Scanning ports with naabu...")
    ports = _run_naabu(target, full=full)
    if ports:
        results["open_ports"] = ports
        logger.info(f"Found {len(ports)} open ports")
    else:
        # Fallback to nmap
        logger.info("naabu not available, falling back to nmap...")
        ports = _run_nmap(target, full=full)
        results["open_ports"] = ports
        logger.info(f"Found {len(ports)} open ports")

    output_file = Path(output_dir) / f"{sanitize_target_filename(target)}_ports.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Results saved to {output_file}")
    return results


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
        logger.warning("naabu timed out")
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
        logger.warning("nmap not installed")
    except subprocess.TimeoutExpired:
        logger.warning("nmap timed out")
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
