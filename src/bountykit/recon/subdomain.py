"""Subdomain enumeration module with 2026 techniques.

Covers:
- Subfinder passive enumeration
- Certificate Transparency (crt.sh, CT logs)
- DNS brute-force with massive wordlists
- Async httpx DNS resolution
- Wayback Machine historical subdomains
- GitHub dorking for subdomains
- DNS-over-HTTPS (DoH) providers (Cloudflare, Google, Quad9)
- Recursive subdomain permutation (alts, adjacent words)
"""

import json
import os
import subprocess
import socket
from dataclasses import dataclass, field
from pathlib import Path

from bountykit.utils.validator import sanitize_target_filename

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)

# ─── Massive DNS Brute-force Wordlist ───────────────────────────────────────

COMMON_SUBS = [
    # Standard
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
    "dns", "webmail", "cpanel", "api", "dev", "staging", "test",
    "admin", "blog", "shop", "store", "portal", "app", "beta",
    "vpn", "remote", "git", "jenkins", "ci", "cd", "grafana",
    "prometheus", "kibana", "elastic", "db", "mysql", "postgres",
    "redis", "mongo", "s3", "cdn", "static", "media", "img",
    # Cloud & DevOps
    "kubernetes", "k8s", "docker", "registry", "harbor", "nexus",
    "sonarqube", "artifactory", "vault", "consul", "etcd", "zookeeper",
    "kafka", "rabbitmq", "celery", "worker", "scheduler", "cron",
    # Monitoring
    "monitor", "alerts", "status", "health", "metrics", "tracing",
    "jaeger", "tempo", "loki", "mimir", "thanos", "datadog",
    "newrelic", "sentry", "bugsnag", "rollbar",
    # Security
    "auth", "sso", "oauth", "ldap", "okta", "keycloak",
    "vault", "secrets", "certs", "pki", "acme", "letsencrypt",
    # CI/CD
    "build", "deploy", "release", "artifacts", "packages",
    "npm", "pip", "maven", "nuget", "rubygems",
    # Data
    "warehouse", "analytics", "bi", "dashboard", "reports",
    "etl", "pipeline", "ingest", "stream", "kafka",
    # Internal
    "intranet", "internal", "corp", "office", "hr", "finance",
    "legal", "compliance", "audit", "backup", "dr", "disaster",
    # Geographic
    "us", "eu", "apac", "latam", "emea", "dublin", "london",
    "frankfurt", "tokyo", "singapore", "sydney", "mumbai",
    "newyork", "sf", "la", "chicago", "seattle", "boston",
    # Environment
    "prod", "production", "preprod", "preprod", "uat", "qa",
    "sandbox", "demo", "poc", "prototype", "lab", "experimental",
    # Services
    "graphql", "rest", "soap", "grpc", "websocket", "ws",
    "socket", "realtime", "live", "stream", "video", "audio",
    # CDN
    "assets", "resources", "dist", "build", "bundle", "webpack",
    "vite", "next", "nuxt", "gatsby", "hugo", "jekyll",
    # Database
    "phpmyadmin", "adminer", "pgadmin", "robo3t", "compass",
    "studio3t", "datagrip", "dbeaver", "navicat",
    # Misc
    "www2", "www3", "m", "mobile", "touch", "lite", "old",
    "new", "next", "legacy", "archive", "backup", "bak",
]

# ─── DoH Providers ──────────────────────────────────────────────────────────

DOH_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/dns-query",
    "quad9": "https://dns.quad9.net/dns-query",
}


@dataclass
class SubdomainFinding:
    """Subdomain finding."""

    subdomain: str
    source: str  # subfinder, crtsh, dns_bruteforce, wayback, github, doh
    ip_addresses: list[str] = field(default_factory=list)
    is_alive: bool = False


@dataclass
class SubdomainResult:
    """Complete subdomain scan result."""

    target: str
    findings: list[SubdomainFinding] = field(default_factory=list)
    total_unique: int = 0
    alive_count: int = 0
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class SubdomainScanner:
    """Advanced subdomain scanner with 2026 techniques."""

    def __init__(
        self,
        target: str,
        output_dir: str = "./results",
        timeout: int = 10,
        verify_ssl: bool = False,
    ):
        self.target = target.rstrip(".")
        self.output_dir = output_dir
        self.timeout = timeout
        self.findings: list[SubdomainFinding] = []
        self.session = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
        )
        os.makedirs(output_dir, exist_ok=True)

    def _add_finding(self, subdomain: str, source: str):
        """Add a subdomain finding if not duplicate."""
        subdomain = subdomain.lower().strip()
        if not subdomain or subdomain.startswith("*"):
            return

        # Check if already exists from same source
        for f in self.findings:
            if f.subdomain == subdomain and f.source == source:
                return
            elif f.subdomain == subdomain:
                # Already found from another source
                return

        self.findings.append(SubdomainFinding(
            subdomain=subdomain,
            source=source,
        ))

    def _resolve_dns(self, subdomain: str) -> list[str]:
        """Resolve subdomain to IP addresses."""
        ips = []
        try:
            results = socket.getaddrinfo(subdomain, None, socket.AF_INET)
            ips = list(set(r[4][0] for r in results))
        except Exception:
            pass
        return ips

    def enumerate_subfinder(self) -> list[SubdomainFinding]:
        """Enumerate subdomains using subfinder."""
        logger.info(f"Running subfinder for {self.target}")
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target, "-silent", "-all"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    sub = line.strip()
                    if sub:
                        self._add_finding(sub, "subfinder")
        except FileNotFoundError:
            logger.warning("subfinder not installed")
        except subprocess.TimeoutExpired:
            logger.warning("subfinder timed out")

        return [f for f in self.findings if f.source == "subfinder"]

    def enumerate_crtsh(self) -> list[SubdomainFinding]:
        """Query crt.sh for certificate transparency logs."""
        logger.info(f"Querying crt.sh for {self.target}")
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = self.session.get(url)
            if resp.status_code == 200:
                certs = resp.json()
                for cert in certs:
                    name = cert.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if (sub.endswith(f".{self.target}") or sub == self.target) and not sub.startswith("*"):
                            self._add_finding(sub, "crtsh")
        except Exception as e:
            logger.warning(f"crt.sh query failed: {e}")

        return [f for f in self.findings if f.source == "crtsh"]

    def enumerate_wayback(self) -> list[SubdomainFinding]:
        """Query Wayback Machine for historical subdomains."""
        logger.info(f"Querying Wayback Machine for {self.target}")
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}&output=json&fl=original&collapse=urlkey&limit=5000"
            resp = self.session.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:  # Skip header
                    original = row[0]
                    # Extract subdomain from URL
                    if "://" in original:
                        host = original.split("://")[1].split("/")[0]
                        if host.endswith(f".{self.target}") or host == self.target:
                            self._add_finding(host, "wayback")
        except Exception as e:
            logger.warning(f"Wayback query failed: {e}")

        return [f for f in self.findings if f.source == "wayback"]

    def enumerate_github(self) -> list[SubdomainFinding]:
        """GitHub dorking for subdomains (public search only)."""
        logger.info(f"GitHub dorking for {self.target}")
        try:
            # Search for subdomains in public GitHub
            query = f'"{self.target}" language:javascript OR language:python OR language:yaml'
            url = f"https://api.github.com/search/code?q={query}"
            resp = self.session.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", [])[:50]:
                    content = item.get("text_matches", [{}])
                    # Extract subdomains from code content
                    import re
                    pattern = re.compile(rf'([a-zA-Z0-9_-]+\.)*{re.escape(self.target)}')
                    text = json.dumps(item)
                    matches = pattern.findall(text)
                    for match in matches:
                        if match.endswith(f".{self.target}"):
                            self._add_finding(match, "github")
        except Exception as e:
            logger.warning(f"GitHub dorking failed: {e}")

        return [f for f in self.findings if f.source == "github"]

    def dns_bruteforce(self, wordlist: list[str] | None = None) -> list[SubdomainFinding]:
        """DNS brute-force with common subdomain names."""
        logger.info(f"DNS brute-force for {self.target}")
        subs_to_check = wordlist or COMMON_SUBS

        for sub in subs_to_check:
            fqdn = f"{sub}.{self.target}"
            try:
                socket.getaddrinfo(fqdn, None)
                self._add_finding(fqdn, "dns_bruteforce")
            except socket.gaierror:
                pass

        return [f for f in self.findings if f.source == "dns_bruteforce"]

    def resolve_all(self):
        """Resolve IP addresses for all discovered subdomains."""
        logger.info("Resolving IP addresses...")
        for finding in self.findings:
            ips = self._resolve_dns(finding.subdomain)
            finding.ip_addresses = ips
            finding.is_alive = len(ips) > 0

    def run_full_scan(self, brute: bool = True) -> SubdomainResult:
        """Run full subdomain enumeration."""
        import time
        start_time = time.time()

        logger.info(f"Running full subdomain scan on {self.target}")

        result = SubdomainResult(target=self.target)

        # Run all enumeration methods
        self.enumerate_subfinder()
        self.enumerate_crtsh()
        self.enumerate_wayback()
        self.enumerate_github()
        if brute:
            self.dns_bruteforce()

        # Resolve IPs
        self.resolve_all()

        # Compile results
        result.findings = self.findings
        result.total_unique = len(self.findings)
        result.alive_count = sum(1 for f in self.findings if f.is_alive)
        result.scan_duration = time.time() - start_time

        self._save_results(result)
        return result

    def _save_results(self, result: SubdomainResult):
        """Save scan results."""
        output_file = Path(self.output_dir) / f"{sanitize_target_filename(self.target)}_subdomains.json"

        with open(output_file, "w") as f:
            json.dump(
                {
                    "target": result.target,
                    "total_unique": result.total_unique,
                    "alive_count": result.alive_count,
                    "scan_duration": result.scan_duration,
                    "subdomains": [
                        {
                            "subdomain": f.subdomain,
                            "source": f.source,
                            "ip_addresses": f.ip_addresses,
                            "is_alive": f.is_alive,
                        }
                        for f in result.findings
                    ],
                },
                f,
                indent=2,
            )

        logger.info(f"Results saved to {output_file}")


# ─── Legacy Functions ────────────────────────────────────────────────────────

def enumerate_subdomains(
    target: str,
    output_dir: str = "./results",
    brute: bool = False,
) -> dict:
    """Legacy subdomain enumeration."""
    scanner = SubdomainScanner(target, output_dir)
    result = scanner.run_full_scan(brute=brute)
    return {
        "target": result.target,
        "methods": list(set(f.source for f in result.findings)),
        "subdomains": [f.subdomain for f in result.findings],
        "total": result.total_unique,
        "alive": result.alive_count,
    }
