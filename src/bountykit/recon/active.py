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
    {
        "id": "http_methods",
        "name": "HTTP Methods Enumeration",
        "description": "Test for allowed HTTP methods and misconfigurations",
    },
    {
        "id": "common_misconfigs",
        "name": "Common Misconfigurations",
        "description": "Check for exposed files, directories, and debug endpoints",
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
        
        # HTTP methods enumeration
        if techniques is None or "http_methods" in techniques:
            _http_methods_enumeration(client, target, result)
        
        # Common misconfigurations
        if techniques is None or "common_misconfigs" in techniques:
            _check_common_misconfigs(client, target, result)

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
        
        # Comprehensive WAF/CDN detection - 2026 patterns
        waf_indicators = {
            # CDN providers
            "cloudflare": {"name": "Cloudflare CDN", "headers": ["cf-ray", "cf-cache-status"]},
            "akamai": {"name": "Akamai CDN", "headers": ["x-akamai-transformed"]},
            "cloudfront": {"name": "AWS CloudFront", "headers": ["x-amz-cf-id", "x-amz-cf-pop"]},
            "fastly": {"name": "Fastly CDN", "headers": ["x-fastly-request-id"]},
            "edgecast": {"name": "EdgeCast CDN", "headers": ["x-ec-request-id"]},
            "limelight": {"name": "Limelight CDN", "headers": ["llid"]},
            
            # WAF providers
            "incapsula": {"name": "Incapsula/Imperva WAF", "headers": ["x-iinfo"]},
            "sucuri": {"name": "Sucuri WAF", "headers": ["x-sucuri-id"]},
            "wordfence": {"name": "Wordfence WAF", "headers": ["wordfence-verifiedhuman"]},
            "modsecurity": {"name": "ModSecurity WAF", "headers": []},
            "barracuda": {"name": "Barracuda WAF", "headers": ["barra_counter_session"]},
            "f5_bigip": {"name": "F5 BIG-IP ASM", "headers": ["bigip"]},
            "citrix_netscaler": {"name": "Citrix NetScaler", "headers": ["ns_af"]},
            "denyall": {"name": "DenyAll WAF", "headers": ["x-denied-all"]},
            "fortiweb": {"name": "Fortinet FortiWeb", "headers": []},
            "radware": {"name": "Radware AppWall", "headers": []},
            "reblaze": {"name": "Reblaze WAF", "headers": ["x-reblaze"]},
            "stackpath": {"name": "StackPath CDN", "headers": ["x-hw"]},
            
            # Bot protection
            "datadome": {"name": "DataDome Bot Protection", "headers": ["x-datadome"]},
            "kasada": {"name": "Kasada Bot Protection", "headers": ["x-kasada"]},
            "perimeterx": {"name": "PerimeterX", "headers": ["x-px"]},
            "cloudflare_bot": {"name": "Cloudflare Bot Management", "headers": ["cf-bot-management"]},
            
            # Server-side
            "varnish": {"name": "Varnish Cache", "headers": ["x-varnish"]},
            "squid": {"name": "Squid Proxy", "headers": ["x-squid-error"]},
            "ats": {"name": "Apache Traffic Server", "headers": ["x-ats"]},
            "gunicorn": {"name": "Gunicorn", "headers": ["server"]},
            "uvicorn": {"name": "Uvicorn", "headers": ["server"]},
        }
        
        detected_wafs = []
        
        for indicator, info in waf_indicators.items():
            # Check server header
            if indicator in server:
                detected_wafs.append(info["name"])
                continue
            
            # Check specific headers
            for header in info["headers"]:
                if header in resp.headers:
                    detected_wafs.append(info["name"])
                    break
            
            # Check all header values
            if info["name"] not in detected_wafs:
                for header_name, header_value in resp.headers.items():
                    if indicator in header_value.lower():
                        detected_wafs.append(info["name"])
                        break
        
        # Report detected WAFs
        if detected_wafs:
            result.findings.append(ReconFinding(
                category="recon",
                severity="info",
                title="WAF/CDN Detected",
                description=f"Detected protection: {', '.join(set(detected_wafs))}",
                endpoint=url,
                evidence=f"WAF signatures found in headers",
            ))
        
        # Enhanced security header analysis
        security_headers = {
            "strict-transport-security": {"severity": "high", "description": "HSTS not set"},
            "content-security-policy": {"severity": "high", "description": "CSP not set"},
            "x-frame-options": {"severity": "medium", "description": "Clickjacking protection missing"},
            "x-content-type-options": {"severity": "medium", "description": "MIME sniffing protection missing"},
            "x-xss-protection": {"severity": "low", "description": "Legacy XSS protection missing"},
            "referrer-policy": {"severity": "medium", "description": "Referrer policy not set"},
            "permissions-policy": {"severity": "medium", "description": "Permissions policy not set"},
            "cross-origin-opener-policy": {"severity": "low", "description": "COOP not set"},
            "cross-origin-resource-policy": {"severity": "low", "description": "CORP not set"},
            "cross-origin-embedder-policy": {"severity": "low", "description": "COEP not set"},
        }
        
        missing_headers = []
        weak_headers = []
        
        for header, info in security_headers.items():
            if header not in resp.headers:
                missing_headers.append((header, info))
            else:
                # Check for weak configurations
                value = resp.headers[header].lower()
                if header == "strict-transport-security":
                    if "max-age=0" in value or "max-age=300" in value:
                        weak_headers.append((header, "HSTS max-age too short"))
                elif header == "content-security-policy":
                    if "unsafe-inline" in value or "unsafe-eval" in value:
                        weak_headers.append((header, "CSP allows unsafe inline/eval"))
                    if "*" in value:
                        weak_headers.append((header, "CSP uses wildcard source"))
                elif header == "x-frame-options":
                    if value not in ["deny", "sameorigin"]:
                        weak_headers.append((header, f"Weak X-Frame-Options: {value}"))
        
        # Report missing headers
        if missing_headers:
            severity = "high" if any(h[1]["severity"] == "high" for h in missing_headers) else "medium"
            result.findings.append(ReconFinding(
                category="recon",
                severity=severity,
                title="Missing Security Headers",
                description=f"Missing: {', '.join(h[0] for h in missing_headers)}",
                endpoint=url,
                remediation="Implement recommended security headers",
            ))
        
        # Report weak headers
        for header, issue in weak_headers:
            result.findings.append(ReconFinding(
                category="recon",
                severity="low",
                title=f"Weak {header} Configuration",
                description=issue,
                endpoint=url,
                remediation=f"Strengthen {header} configuration",
            ))
        
        # Server version disclosure
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
        
        detected_techs = []
        
        # Header-based detection
        header_patterns = {
            "x-powered-by": {
                "PHP": "PHP",
                "Express": "Node.js/Express",
                "ASP.NET": "ASP.NET",
                "Django": "Django",
                "Flask": "Flask",
                "Ruby on Rails": "Ruby on Rails",
                "Laravel": "Laravel",
                "Fastify": "Node.js/Fastify",
                "Koa": "Node.js/Koa",
                "Hapi": "Node.js/Hapi",
            },
            "x-generator": {
                "WordPress": "WordPress",
                "Drupal": "Drupal",
                "Joomla": "Joomla",
                "Hugo": "Hugo",
                "Jekyll": "Jekyll",
                "Next.js": "Next.js",
                "Gatsby": "Gatsby",
            },
            "set-cookie": {
                "PHPSESSID": "PHP",
                "JSESSIONID": "Java",
                "connect.sid": "Node.js",
                "rack.session": "Ruby/Rack",
                "_session_id": "Python/Django",
                "csrftoken": "Python/Django",
                "laravel_session": "PHP/Laravel",
                "XSRF-TOKEN": "PHP/Laravel",
                "bf_sid": "PHP/Bitrix",
            },
            "x-aspnet-version": {"ASP.NET": "ASP.NET"},
            "x-aspnetmvc-version": {"MVC": "ASP.NET MVC"},
            "x-drupal-cache": {"Drupal": "Drupal"},
            "x-varnish": {"Varnish": "Varnish Cache"},
            "x-cache": {"HIT": "CDN/Cache", "MISS": "CDN/Cache"},
            "x-cdn": {"Incapsula": "Incapsula CDN"},
        }
        
        for header, patterns in header_patterns.items():
            header_value = headers.get(header, "").lower()
            for tech_name, tech_id in patterns.items():
                if tech_name.lower() in header_value:
                    detected_techs.append(tech_id)
        
        # Body-based detection - CMS
        cms_patterns = {
            "wp-content": "WordPress",
            "wp-includes": "WordPress",
            "wp-json": "WordPress REST API",
            "wp-login.php": "WordPress Login",
            "drupal.js": "Drupal",
            "drupal.min.js": "Drupal",
            "/sites/default/files": "Drupal",
            "joomla": "Joomla",
            "/media/jui": "Joomla",
            "magento": "Magento",
            "/static/frontend": "Magento 2",
            "prestashop": "PrestaShop",
            "shopify": "Shopify",
            "squarespace": "Squarespace",
            "wix.com": "Wix",
            "webflow": "Webflow",
            "ghost": "Ghost CMS",
            "contentful": "Contentful",
            "strapi": "Strapi",
        }
        
        # Body-based detection - Frameworks
        framework_patterns = {
            "react": "React",
            "reactdom": "React",
            "_next/static": "Next.js",
            "_next/data": "Next.js",
            "nuxt": "Nuxt.js",
            "__nuxt": "Nuxt.js",
            "angular": "Angular",
            "ng-version": "Angular",
            "vue.js": "Vue.js",
            "vue.min.js": "Vue.js",
            "ember": "Ember.js",
            "backbone": "Backbone.js",
            "jquery": "jQuery",
            "bootstrap": "Bootstrap",
            "tailwind": "Tailwind CSS",
            "bulma": "Bulma CSS",
            "materialize": "Materialize CSS",
            "svelte": "Svelte",
            "solid.js": "Solid.js",
            "preact": "Preact",
            "alpine.js": "Alpine.js",
            "htmx": "HTMX",
        }
        
        # Body-based detection - Server/Backend
        backend_patterns = {
            "laravel": "PHP/Laravel",
            "symfony": "PHP/Symfony",
            "codeigniter": "PHP/CodeIgniter",
            "cakephp": "PHP/CakePHP",
            "django": "Python/Django",
            "flask": "Python/Flask",
            "fastapi": "Python/FastAPI",
            "rails": "Ruby on Rails",
            "sinatra": "Ruby/Sinatra",
            "express": "Node.js/Express",
            "nestjs": "Node.js/NestJS",
            "spring": "Java/Spring",
            "struts": "Java/Struts",
            "grails": "Java/Grails",
            "dotnet": ".NET",
            "blazor": ".NET/Blazor",
        }
        
        # Body-based detection - Security/Analytics
        security_patterns = {
            "gtag": "Google Analytics",
            "google-analytics": "Google Analytics",
            "googletagmanager": "Google Tag Manager",
            "hotjar": "Hotjar",
            "mixpanel": "Mixpanel",
            "segment": "Segment",
            "amplitude": "Amplitude",
            "intercom": "Intercom",
            "crisp": "Crisp Chat",
            "drift": "Drift",
            "hubspot": "HubSpot",
            "marketo": "Marketo",
            "recaptcha": "reCAPTCHA",
            "hcaptcha": "hCaptcha",
            "turnstile": "Cloudflare Turnstile",
        }
        
        # Check all patterns
        all_patterns = {**cms_patterns, **framework_patterns, **backend_patterns, **security_patterns}
        
        for pattern, tech_name in all_patterns.items():
            if pattern.lower() in body:
                detected_techs.append(tech_name)
        
        # Check for version information
        version_patterns = {
            r'wp-content/themes/([a-zA-Z0-9_-]+)': "WordPress Theme",
            r'wp-content/plugins/([a-zA-Z0-9_-]+)': "WordPress Plugin",
            r'/wp-includes/js/jquery/jquery\.([0-9.]+)': "jQuery Version",
            r'ng-version="([0-9.]+)"': "Angular Version",
            r'react@([0-9.]+)': "React Version",
            r'vue@([0-9.]+)': "Vue Version",
        }
        
        import re
        for pattern, description in version_patterns.items():
            match = re.search(pattern, resp.text)
            if match:
                version = match.group(1)
                detected_techs.append(f"{description}: {version}")
        
        # Deduplicate and report
        unique_techs = list(set(detected_techs))
        if unique_techs:
            result.findings.append(ReconFinding(
                category="recon",
                severity="info",
                title="Web Technologies Detected",
                description=f"Detected {len(unique_techs)} technologies: {', '.join(unique_techs[:10])}",
                endpoint=url,
                evidence=f"Technologies: {unique_techs}",
            ))
            
    except Exception as e:
        logger.debug(f"Technology detection failed: {e}")


def _http_methods_enumeration(client: httpx.Client, target: str, result: ReconResult):
    """Enumerate HTTP methods and check for misconfigurations."""
    logger.info("Enumerating HTTP methods...")
    
    url = f"https://{target}"
    
    # Common HTTP methods to test
    methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"]
    
    # Dangerous methods that should be disabled
    dangerous_methods = {
        "TRACE": "XST (Cross-Site Tracing) vulnerability",
        "CONNECT": "Potential proxy abuse",
        "PUT": "Unauthorized file upload",
        "DELETE": "Unauthorized resource deletion",
        "PATCH": "Unauthorized resource modification",
    }
    
    try:
        # First check OPTIONS response
        options_resp = client.options(url)
        allowed_methods = options_resp.headers.get("allow", "").upper()
        
        for method in methods:
            try:
                # Skip GET (already tested) and OPTIONS (just checked)
                if method in ["GET", "OPTIONS"]:
                    continue
                
                # Send request with specific method
                resp = client.request(method, url)
                
                # Check if method is allowed (non-405 response)
                if resp.status_code != 405:  # 405 = Method Not Allowed
                    if method in dangerous_methods:
                        result.findings.append(ReconFinding(
                            category="recon",
                            severity="high",
                            title=f"Dangerous HTTP Method Allowed: {method}",
                            description=f"{dangerous_methods[method]}",
                            endpoint=url,
                            evidence=f"Method {method} returned status {resp.status_code}",
                            remediation=f"Disable {method} method if not required",
                        ))
                    elif method not in ["GET", "HEAD", "POST"]:
                        result.findings.append(ReconFinding(
                            category="recon",
                            severity="low",
                            title=f"Uncommon HTTP Method Allowed: {method}",
                            description=f"Method {method} is enabled",
                            endpoint=url,
                            evidence=f"Status: {resp.status_code}",
                            remediation="Disable unnecessary HTTP methods",
                        ))
                        
            except Exception:
                continue
        
        # Check for CORS misconfigurations
        cors_headers = {
            "access-control-allow-origin": "CORS",
            "access-control-allow-methods": "CORS Methods",
            "access-control-allow-headers": "CORS Headers",
            "access-control-allow-credentials": "CORS Credentials",
        }
        
        for header, name in cors_headers.items():
            if header in resp.headers:
                value = resp.headers[header]
                if header == "access-control-allow-origin" and value == "*":
                    result.findings.append(ReconFinding(
                        category="recon",
                        severity="medium",
                        title="CORS Wildcard Origin Allowed",
                        description="Access-Control-Allow-Origin is set to *",
                        endpoint=url,
                        evidence=f"Header: {header}={value}",
                        remediation="Restrict CORS origins to trusted domains",
                    ))
        
    except Exception as e:
        logger.debug(f"HTTP methods enumeration failed: {e}")


def _check_common_misconfigs(client: httpx.Client, target: str, result: ReconResult):
    """Check for common misconfigurations and exposed files."""
    logger.info("Checking for common misconfigurations...")
    
    # Common paths to check
    paths_to_check = {
        # Debug/Admin panels
        "/debug": "Debug endpoint exposed",
        "/admin": "Admin panel accessible",
        "/admin/login": "Admin login page accessible",
        "/phpmyadmin": "phpMyAdmin exposed",
        "/adminer": "Adminer exposed",
        "/_admin": "Admin panel exposed",
        
        # Configuration files
        "/.env": "Environment file exposed",
        "/config.json": "Config file exposed",
        "/config.php": "PHP config exposed",
        "/settings.py": "Django settings exposed",
        "/wp-config.php": "WordPress config exposed",
        "/.git/config": "Git config exposed",
        "/.git/HEAD": "Git repository exposed",
        
        # Backup files
        "/backup": "Backup directory accessible",
        "/backups": "Backups directory accessible",
        "/dump": "Database dump accessible",
        "/db.sql": "SQL dump exposed",
        "/database.sql": "Database dump exposed",
        
        # Documentation
        "/api-docs": "API documentation exposed",
        "/swagger": "Swagger UI exposed",
        "/swagger-ui.html": "Swagger UI exposed",
        "/redoc": "ReDoc exposed",
        "/graphql": "GraphQL endpoint exposed",
        
        # Monitoring
        "/metrics": "Metrics endpoint exposed",
        "/actuator": "Spring Actuator exposed",
        "/actuator/health": "Health endpoint exposed",
        "/actuator/env": "Environment endpoint exposed",
        "/debug/vars": "Debug variables exposed",
        
        # Server status
        "/server-status": "Apache status exposed",
        "/server-info": "Apache info exposed",
        "/nginx_status": "Nginx status exposed",
        
        # Source code
        "/.svn": "SVN directory exposed",
        "/.hg": "Mercurial directory exposed",
        "/CVS": "CVS directory exposed",
        "/WEB-INF": "Java WEB-INF exposed",
        
        # Logs
        "/logs": "Logs directory accessible",
        "/log": "Log file accessible",
        "/access.log": "Access log exposed",
        "/error.log": "Error log exposed",
    }
    
    found_misconfigs = []
    
    for path, description in paths_to_check.items():
        try:
            url = f"https://{target}{path}"
            resp = client.get(url, follow_redirects=False)
            
            # Check if resource exists (200 OK or redirect to content)
            if resp.status_code == 200:
                # Additional check to avoid false positives
                content_length = int(resp.headers.get("content-length", 0))
                content_type = resp.headers.get("content-type", "")
                
                # Skip if it's just a custom 404 page
                if "text/html" in content_type and content_length > 5000:
                    # Likely a custom 404 page
                    continue
                
                # Add to findings
                severity = "high" if any(s in path.lower() for s in [".env", ".git", "config", "dump", "log"]) else "medium"
                
                result.findings.append(ReconFinding(
                    category="recon",
                    severity=severity,
                    title=f"Misconfiguration Found: {description}",
                    description=f"Accessible at {path}",
                    endpoint=url,
                    evidence=f"Status: {resp.status_code}, Content-Type: {content_type}",
                    remediation=f"Restrict access to {path}",
                ))
                
                found_misconfigs.append(path)
                
        except Exception:
            continue
    
    if found_misconfigs:
        logger.info(f"Found {len(found_misconfigs)} misconfigurations")
    else:
        logger.info("No common misconfigurations found")


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
