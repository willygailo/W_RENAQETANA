"""Subdomain takeover detection module — 2026 techniques.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 8:
- Subdomain takeover via CNAME dangling records
- NS takeover (dead nameservers)
- DNS record analysis with DoH providers (Cloudflare / Google fallback)
- Fingerprint-based detection (55+ services)
- A/AAAA record takeover (dangling IPs)
- MX takeover (expired email domains)
- SRV / TXT / CAA record analysis
- Wildcard CNAME detection
- Async bulk scanning for wordlist-driven mass scans
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)

# ─── 2026 Service Fingerprints (55+ services, no duplicate keys) ───────────

SERVICES: dict[str, dict] = {
    # --- Cloud Hosting ---
    "github.io": {
        "service": "GitHub Pages",
        "verify_patterns": [
            "There isn't a GitHub Pages site here.",
            "Repository not found.",
        ],
        "severity": "high",
    },
    "herokuapp.com": {"service": "Heroku", "verify_patterns": ["no-such-app"], "severity": "high"},
    "heroku.com": {"service": "Heroku", "verify_patterns": ["no-such-app"], "severity": "high"},
    "netlify.app": {"service": "Netlify", "verify_patterns": ["Not Found - Request ID"], "severity": "high"},
    "vercel.app": {"service": "Vercel", "verify_patterns": ["DEPLOYMENT_NOT_FOUND"], "severity": "high"},
    "surge.sh": {"service": "Surge", "verify_patterns": ["project not found"], "severity": "high"},
    "render.com": {"service": "Render", "verify_patterns": ["Service not found"], "severity": "high"},
    "fly.io": {"service": "Fly.io", "verify_patterns": ["not found"], "severity": "high"},
    "railway.app": {"service": "Railway", "verify_patterns": ["No such project"], "severity": "high"},
    "pages.dev": {"service": "Cloudflare Pages", "verify_patterns": ["Page not found"], "severity": "high"},
    "workers.dev": {"service": "Cloudflare Workers", "verify_patterns": ["No such namespace"], "severity": "high"},
    # 2026 new platforms
    "deno.dev": {"service": "Deno Deploy", "verify_patterns": ["404", "not found"], "severity": "high"},
    "koyeb.app": {"service": "Koyeb", "verify_patterns": ["Application not found"], "severity": "high"},
    "qoddi.app": {"service": "Qoddi", "verify_patterns": ["404"], "severity": "medium"},
    "zeabur.app": {"service": "Zeabur", "verify_patterns": ["not found"], "severity": "high"},
    "val.run": {"service": "val.town", "verify_patterns": ["not found", "404"], "severity": "medium"},
    "onrender.com": {"service": "Render (onrender)", "verify_patterns": ["Service not found"], "severity": "high"},
    "up.railway.app": {"service": "Railway (up)", "verify_patterns": ["No such project"], "severity": "high"},
    "cyclic.sh": {"service": "Cyclic", "verify_patterns": ["not found"], "severity": "high"},
    "adaptable.app": {"service": "Adaptable.io", "verify_patterns": ["not found", "404"], "severity": "medium"},
    "glitch.me": {"service": "Glitch", "verify_patterns": ["Project not found"], "severity": "medium"},

    # --- Cloud Providers ---
    "s3.amazonaws.com": {"service": "AWS S3", "verify_patterns": ["NoSuchBucket"], "severity": "critical"},
    "s3-website": {"service": "AWS S3 Website", "verify_patterns": ["NoSuchBucket", "NoSuchKey"], "severity": "critical"},
    "amazonaws.com": {"service": "AWS", "verify_patterns": ["NoSuchBucket"], "severity": "high"},
    "cloudfront.net": {"service": "AWS CloudFront", "verify_patterns": ["Bad request", "ERROR: The request could not be satisfied"], "severity": "high"},
    "elasticbeanstalk.com": {"service": "AWS Elastic Beanstalk", "verify_patterns": ["502 Bad Gateway"], "severity": "medium"},
    "azurewebsites.net": {"service": "Azure Web App", "verify_patterns": ["Azure Web App - Your web app is running", "404 Web Site not found"], "severity": "high"},
    "cloudapp.net": {"service": "Azure", "verify_patterns": ["Azure Web App"], "severity": "high"},
    "azure-api.net": {"service": "Azure API Management", "verify_patterns": ["Azure Web App"], "severity": "high"},
    "azurefd.net": {"service": "Azure Front Door", "verify_patterns": ["Azure Web App"], "severity": "high"},
    "azureedge.net": {"service": "Azure CDN", "verify_patterns": ["Azure Web App"], "severity": "high"},
    "azurehdinsight.net": {"service": "Azure HDInsight", "verify_patterns": ["Azure Web App"], "severity": "high"},
    "blob.core.windows.net": {"service": "Azure Blob", "verify_patterns": ["The specified container does not exist"], "severity": "high"},
    "storage.googleapis.com": {"service": "Google Cloud Storage", "verify_patterns": ["NoSuchBucket", "The specified bucket does not exist"], "severity": "high"},
    "appspot.com": {"service": "Google App Engine", "verify_patterns": ["404. That's an error."], "severity": "high"},
    "firebaseapp.com": {
        "service": "Firebase Hosting",
        "verify_patterns": ["Site Not Found", "Firebase Hosting"],
        "severity": "high",
    },
    "web.app": {"service": "Firebase (web.app)", "verify_patterns": ["Site Not Found"], "severity": "high"},

    # --- SaaS & Platforms ---
    "ghost.io": {"service": "Ghost", "verify_patterns": ["The thing you were looking for is no longer here"], "severity": "high"},
    "shopify.com": {"service": "Shopify", "verify_patterns": ["Sorry, this shop is currently unavailable"], "severity": "high"},
    "bitbucket.io": {"service": "Bitbucket", "verify_patterns": ["Repository not found"], "severity": "high"},
    "cargocollective.com": {"service": "Cargo", "verify_patterns": ["If this is your website"], "severity": "medium"},
    "feedpress.me": {"service": "FeedPress", "verify_patterns": ["The feed could not be found"], "severity": "medium"},
    "freshdesk.com": {"service": "FreshDesk", "verify_patterns": ["No such account"], "severity": "medium"},
    "helpjuice.com": {"service": "Helpjuice", "verify_patterns": ["We could not find what you're looking for"], "severity": "medium"},
    "helpscoutdocs.com": {"service": "HelpScout", "verify_patterns": ["No settings were found for this company"], "severity": "medium"},
    "hosted.zendesk.com": {"service": "Zendesk (hosted)", "verify_patterns": ["Help Center Closed"], "severity": "high"},
    "zendesk.com": {"service": "Zendesk", "verify_patterns": ["Help Center Closed"], "severity": "high"},
    "intercom.io": {"service": "Intercom", "verify_patterns": ["This page is reserved for artistic dogs"], "severity": "medium"},
    "landingi.com": {"service": "Landingi", "verify_patterns": ["It looks like you're lost"], "severity": "medium"},
    "mashery.com": {"service": "Mashery", "verify_patterns": ["Unrecognized domain"], "severity": "medium"},
    "ngrok.io": {"service": "ngrok", "verify_patterns": ["Tunnel not found"], "severity": "high"},
    "readme.io": {"service": "Readme", "verify_patterns": ["Project doesnt exist"], "severity": "medium"},
    "readthedocs.io": {"service": "ReadTheDocs", "verify_patterns": ["unknown to Read the Docs"], "severity": "medium"},
    "sentry.io": {"service": "Sentry", "verify_patterns": ["Looks like you've wandered into the void"], "severity": "medium"},
    "statuspage.io": {"service": "StatusPage", "verify_patterns": ["Better StatusPage"], "severity": "medium"},
    "teamwork.com": {"service": "TeamWork", "verify_patterns": ["Oops - We didn't find your site"], "severity": "medium"},
    "tumblr.com": {"service": "Tumblr", "verify_patterns": ["Whatever you were looking for doesn't currently exist"], "severity": "medium"},
    "uservoice.com": {"service": "UserVoice", "verify_patterns": ["This UserVoice subdomain is currently available!"], "severity": "high"},
    "webflow.io": {"service": "Webflow", "verify_patterns": ["The page you are looking for doesn't exist"], "severity": "medium"},
    "wordpress.com": {"service": "WordPress", "verify_patterns": ["Do you want to register"], "severity": "medium"},
    "unbounce.com": {"service": "Unbounce", "verify_patterns": ["The requested URL was not found on this server"], "severity": "medium"},
    "uberflip.com": {"service": "Uberflip", "verify_patterns": ["Blog not found"], "severity": "medium"},
    "pingdom.com": {"service": "Pingdom", "verify_patterns": ["Sorry, couldn't find the status page"], "severity": "low"},
    "launchrock.com": {"service": "LaunchRock", "verify_patterns": ["It looks like you may have taken a wrong turn"], "severity": "medium"},

    # --- Analytics / Dev tools ---
    "sendgrid.net": {"service": "SendGrid", "verify_patterns": ["404"], "severity": "low"},
    "mailgun.org": {"service": "Mailgun", "verify_patterns": ["404"], "severity": "low"},
    "stripe.com": {"service": "Stripe", "verify_patterns": ["404"], "severity": "low"},

    # --- 2026 additions ---
    "supabase.co": {"service": "Supabase", "verify_patterns": ["404", "not found"], "severity": "high"},
    "planetscale.dev": {"service": "PlanetScale", "verify_patterns": ["not found"], "severity": "high"},
    "neon.tech": {"service": "Neon Postgres", "verify_patterns": ["not found"], "severity": "high"},
    "convex.cloud": {"service": "Convex", "verify_patterns": ["not found"], "severity": "high"},
    "sanity.studio": {"service": "Sanity Studio", "verify_patterns": ["not found", "404"], "severity": "medium"},
}

# DoH providers for fallback when `dig` is unavailable
DOH_PROVIDERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]


@dataclass
class TakeoverFinding:
    """Takeover finding."""

    subdomain: str
    cname: str = ""
    a_record: str = ""
    ns_record: str = ""
    mx_record: str = ""
    srv_record: str = ""
    txt_record: str = ""
    service: str = ""
    finding_type: str = "cname"  # cname, ns, a_record, mx, srv, txt, caa, wildcard
    severity: str = "high"
    description: str = ""
    evidence: str = ""
    remediation: str = ""


@dataclass
class TakeoverResult:
    """Complete takeover scan result."""

    target: str
    findings: list[TakeoverFinding] = field(default_factory=list)
    cname_vulnerable: bool = False
    ns_vulnerable: bool = False
    a_record_vulnerable: bool = False
    mx_vulnerable: bool = False
    srv_vulnerable: bool = False
    txt_vulnerable: bool = False
    wildcard_detected: bool = False
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class TakeoverScanner:
    """Advanced subdomain takeover scanner — 2026 techniques."""

    def __init__(
        self,
        target: str,
        output_dir: str = "./results",
        timeout: int = 10,
        verify_ssl: bool = False,
        use_doh: bool = True,
    ):
        self.target = target.rstrip("/")
        self.output_dir = output_dir
        self.timeout = timeout
        self.use_doh = use_doh
        self.findings: list[TakeoverFinding] = []
        self.session = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
            http2=False,
        )
        os.makedirs(output_dir, exist_ok=True)

    # ─── DNS Resolution ───────────────────────────────────────────────────────

    def _dig(self, record_type: str, domain: str) -> list[str]:
        """Resolve DNS record using dig, with DoH fallback."""
        # Try dig first
        try:
            result = subprocess.run(
                ["dig", "+short", record_type, domain],
                capture_output=True, text=True, timeout=self.timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                return [line.strip().rstrip(".") for line in result.stdout.splitlines() if line.strip()]
        except FileNotFoundError:
            logger.debug("dig not available — falling back to DoH")
        except subprocess.TimeoutExpired:
            logger.warning(f"dig timed out for {domain}")

        # DoH fallback
        if self.use_doh:
            return self._doh_resolve(record_type, domain)
        return []

    def _doh_resolve(self, record_type: str, domain: str) -> list[str]:
        """Resolve DNS via DNS-over-HTTPS (Cloudflare → Google fallback)."""
        rtype_map = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "SRV": 33, "TXT": 16, "CAA": 257}
        rtype_num = rtype_map.get(record_type.upper(), 1)

        for provider in DOH_PROVIDERS:
            try:
                resp = self.session.get(
                    provider,
                    params={"name": domain, "type": rtype_num},
                    headers={"Accept": "application/dns-json"},
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    results = []
                    for answer in answers:
                        val = answer.get("data", "").strip().rstrip(".")
                        if val:
                            results.append(val)
                    if results:
                        return results
            except Exception as e:
                logger.debug(f"DoH resolve failed ({provider}): {e}")

        return []

    # ─── Service Verification ─────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=1, max=5))
    def _send_request(self, url: str, **kwargs) -> httpx.Response:
        """Send HTTP request with retry."""
        return self.session.request("GET", url, **kwargs)

    def _verify_service(self, hostname: str, patterns: list[str]) -> tuple[bool, str]:
        """Verify if service is dangling by checking response against patterns list."""
        for scheme in ("https", "http"):
            try:
                resp = self._send_request(f"{scheme}://{hostname}", timeout=self.timeout)
                body = resp.text.lower()
                for pattern in patterns:
                    if pattern.lower() in body:
                        return True, f"{scheme}://{hostname} → '{pattern}' matched (HTTP {resp.status_code})"
            except Exception:
                continue
        return False, ""

    # ─── Wildcard CNAME Detection ─────────────────────────────────────────────

    def check_wildcard(self) -> Optional[TakeoverFinding]:
        """Detect wildcard CNAME that could mask real dangling records."""
        import random, string
        rand_sub = "".join(random.choices(string.ascii_lowercase, k=16))
        parent = ".".join(self.target.split(".")[-2:])
        probe = f"{rand_sub}.{parent}"

        cnames = self._dig("CNAME", probe)
        if cnames:
            finding = TakeoverFinding(
                subdomain=self.target,
                cname=cnames[0],
                service="Wildcard CNAME",
                finding_type="wildcard",
                severity="medium",
                description=f"Wildcard CNAME detected: *.{parent} → {cnames[0]}",
                evidence=f"Random subdomain {probe} resolved to CNAME {cnames[0]}",
                remediation="Audit wildcard CNAME targets — ensure pointed service is claimed and controlled.",
            )
            self.findings.append(finding)
            return finding
        return None

    # ─── CNAME Takeover ───────────────────────────────────────────────────────

    def check_cname(self) -> list[TakeoverFinding]:
        """Check for CNAME-based subdomain takeover."""
        logger.info(f"Checking CNAME takeover for {self.target}")
        findings: list[TakeoverFinding] = []

        cnames = self._dig("CNAME", self.target)
        for cname in cnames:
            for domain_suffix, info in SERVICES.items():
                if cname.endswith(domain_suffix):
                    vulnerable, evidence = self._verify_service(cname, info["verify_patterns"])
                    if vulnerable:
                        finding = TakeoverFinding(
                            subdomain=self.target,
                            cname=cname,
                            service=info["service"],
                            finding_type="cname",
                            severity=info.get("severity", "high"),
                            description=f"Dangling CNAME: {self.target} → {cname} ({info['service']})",
                            evidence=evidence,
                            remediation=f"Register {info['service']} project for {cname} or remove CNAME record.",
                        )
                        findings.append(finding)

        self.findings.extend(findings)
        return findings

    # ─── NS Takeover ──────────────────────────────────────────────────────────

    def check_ns(self) -> list[TakeoverFinding]:
        """Check for NS-based subdomain takeover (dead nameservers)."""
        logger.info(f"Checking NS takeover for {self.target}")
        findings: list[TakeoverFinding] = []

        ns_servers = self._dig("NS", self.target)
        for ns in ns_servers:
            a_records = self._dig("A", ns)
            if not a_records:
                finding = TakeoverFinding(
                    subdomain=self.target,
                    ns_record=ns,
                    service="DNS",
                    finding_type="ns",
                    severity="critical",
                    description=f"Dead nameserver: {ns} has no A record",
                    evidence=f"NS {ns} → unresolvable",
                    remediation=f"Replace dead nameserver {ns} or claim its registration.",
                )
                findings.append(finding)

        self.findings.extend(findings)
        return findings

    # ─── A Record Takeover ───────────────────────────────────────────────────

    def check_a_record(self) -> list[TakeoverFinding]:
        """Check for A record takeover (dangling cloud IPs)."""
        logger.info(f"Checking A record takeover for {self.target}")
        findings: list[TakeoverFinding] = []

        CLOUD_PREFIXES = {
            "52.": "AWS", "54.": "AWS", "34.": "GCP/AWS", "35.": "GCP",
            "13.": "AWS", "40.": "Azure", "51.": "Azure", "104.": "Cloudflare",
            "20.": "Azure", "23.": "Azure", "8.": "Google", "74.": "AWS",
        }

        a_records = self._dig("A", self.target)
        for ip in a_records:
            for prefix, provider in CLOUD_PREFIXES.items():
                if ip.startswith(prefix):
                    try:
                        resp = self._send_request(f"http://{ip}", timeout=5)
                        if resp.status_code in [502, 503, 521, 522, 523, 524, 525, 526]:
                            finding = TakeoverFinding(
                                subdomain=self.target,
                                a_record=ip,
                                service=provider,
                                finding_type="a_record",
                                severity="medium",
                                description=f"Possibly dangling IP: {ip} ({provider}) — returns {resp.status_code}",
                                evidence=f"IP {ip} returns error {resp.status_code}",
                                remediation=f"Verify IP {ip} is still managed or remove DNS record.",
                            )
                            findings.append(finding)
                    except Exception:
                        continue

        self.findings.extend(findings)
        return findings

    # ─── MX Takeover ─────────────────────────────────────────────────────────

    def check_mx(self) -> list[TakeoverFinding]:
        """Check for MX-based takeover (expired email domains)."""
        logger.info(f"Checking MX takeover for {self.target}")
        findings: list[TakeoverFinding] = []

        mx_records = self._dig("MX", self.target)
        for mx in mx_records:
            mx_host = mx.split(" ", 1)[-1] if " " in mx else mx
            a_records = self._dig("A", mx_host)
            if not a_records:
                finding = TakeoverFinding(
                    subdomain=self.target,
                    mx_record=mx_host,
                    service="Email",
                    finding_type="mx",
                    severity="critical",
                    description=f"Dead MX server: {mx_host} has no A record",
                    evidence=f"MX {mx_host} → unresolvable",
                    remediation=f"Register email domain or remove MX record for {mx_host}.",
                )
                findings.append(finding)

        self.findings.extend(findings)
        return findings

    # ─── SRV Record Takeover ─────────────────────────────────────────────────

    def check_srv(self) -> list[TakeoverFinding]:
        """Check for SRV record takeover (dead SRV targets)."""
        logger.info(f"Checking SRV takeover for {self.target}")
        findings: list[TakeoverFinding] = []

        # Probe common SRV records
        SRV_PREFIXES = [
            "_http._tcp", "_https._tcp", "_xmpp._tcp", "_sip._tcp",
            "_turn._tcp", "_stun._tcp", "_caldav._tcp", "_carddav._tcp",
        ]

        for prefix in SRV_PREFIXES:
            srv_domain = f"{prefix}.{self.target}"
            srv_records = self._dig("SRV", srv_domain)
            for srv in srv_records:
                parts = srv.split()
                if len(parts) >= 4:
                    target_host = parts[3].rstrip(".")
                    a_records = self._dig("A", target_host)
                    if not a_records:
                        finding = TakeoverFinding(
                            subdomain=self.target,
                            srv_record=srv,
                            service="SRV Target",
                            finding_type="srv",
                            severity="high",
                            description=f"Dead SRV target: {target_host} (from {srv_domain})",
                            evidence=f"SRV {srv_domain} → {target_host} → unresolvable",
                            remediation=f"Remove or update SRV record for {srv_domain}.",
                        )
                        findings.append(finding)

        self.findings.extend(findings)
        return findings

    # ─── TXT Record Takeover ─────────────────────────────────────────────────

    def check_txt(self) -> list[TakeoverFinding]:
        """Check TXT records for domain verification tokens of abandoned services."""
        logger.info(f"Checking TXT records for {self.target}")
        findings: list[TakeoverFinding] = []

        # Services that use TXT-based domain verification
        TXT_VERIFICATION_PATTERNS = {
            "google-site-verification=": "Google Search Console",
            "docusign=": "DocuSign",
            "atlassian-domain-verification=": "Atlassian",
            "facebook-domain-verification=": "Facebook",
            "apple-domain-verification=": "Apple",
            "shopify-domain-verification=": "Shopify",
            "stripe-verification=": "Stripe",
            "twilio-domain-validation=": "Twilio",
            "mandrill-domain-verification=": "Mandrill",
            "have-i-been-pwned-verification=": "HIBP",
        }

        txt_records = self._dig("TXT", self.target)
        for txt in txt_records:
            txt_clean = txt.strip('"')
            for pattern, service in TXT_VERIFICATION_PATTERNS.items():
                if txt_clean.lower().startswith(pattern.lower()):
                    # TXT verification tokens don't directly allow takeover
                    # but indicate service dependencies — flag for review
                    finding = TakeoverFinding(
                        subdomain=self.target,
                        txt_record=txt_clean,
                        service=service,
                        finding_type="txt",
                        severity="info",
                        description=f"TXT domain verification for {service}: {txt_clean[:60]}",
                        evidence=f"TXT record found: {txt_clean}",
                        remediation=f"Verify {service} account is still active and owned.",
                    )
                    findings.append(finding)

        self.findings.extend(findings)
        return findings

    # ─── CAA Record Check ────────────────────────────────────────────────────

    def check_caa(self) -> list[TakeoverFinding]:
        """Check CAA records — missing CAA allows any CA to issue certs."""
        logger.info(f"Checking CAA records for {self.target}")
        findings: list[TakeoverFinding] = []

        caa_records = self._dig("CAA", self.target)
        if not caa_records:
            finding = TakeoverFinding(
                subdomain=self.target,
                service="Certificate Authority",
                finding_type="caa",
                severity="low",
                description=f"No CAA records found for {self.target}",
                evidence="No CAA records — any CA can issue certificates for this domain",
                remediation='Add CAA record: 0 issue "letsencrypt.org" (or your preferred CA).',
            )
            findings.append(finding)

        self.findings.extend(findings)
        return findings

    # ─── Full Scan ────────────────────────────────────────────────────────────

    def run_full_scan(self) -> TakeoverResult:
        """Run full subdomain takeover scan across all record types."""
        start_time = time.time()
        logger.info(f"Running full takeover scan on {self.target}")

        result = TakeoverResult(target=self.target)

        # Wildcard detection first
        wildcard = self.check_wildcard()
        if wildcard:
            result.wildcard_detected = True

        # All record-type checks
        cname_f = self.check_cname()
        result.cname_vulnerable = len(cname_f) > 0

        ns_f = self.check_ns()
        result.ns_vulnerable = len(ns_f) > 0

        a_f = self.check_a_record()
        result.a_record_vulnerable = len(a_f) > 0

        mx_f = self.check_mx()
        result.mx_vulnerable = len(mx_f) > 0

        srv_f = self.check_srv()
        result.srv_vulnerable = len(srv_f) > 0

        txt_f = self.check_txt()
        result.txt_vulnerable = len(txt_f) > 0

        self.check_caa()  # adds to self.findings

        result.findings = self.findings
        result.scan_duration = time.time() - start_time

        self._save_results(result)
        return result

    def _save_results(self, result: TakeoverResult) -> None:
        """Save scan results to JSON."""
        output_file = Path(self.output_dir) / "takeover_scan.json"
        with open(output_file, "w") as f:
            json.dump(
                {
                    "target": result.target,
                    "cname_vulnerable": result.cname_vulnerable,
                    "ns_vulnerable": result.ns_vulnerable,
                    "a_record_vulnerable": result.a_record_vulnerable,
                    "mx_vulnerable": result.mx_vulnerable,
                    "srv_vulnerable": result.srv_vulnerable,
                    "txt_vulnerable": result.txt_vulnerable,
                    "wildcard_detected": result.wildcard_detected,
                    "scan_duration": result.scan_duration,
                    "findings_count": len(result.findings),
                    "findings": [
                        {
                            "subdomain": f.subdomain,
                            "cname": f.cname,
                            "a_record": f.a_record,
                            "ns_record": f.ns_record,
                            "mx_record": f.mx_record,
                            "srv_record": f.srv_record,
                            "txt_record": f.txt_record,
                            "service": f.service,
                            "finding_type": f.finding_type,
                            "severity": f.severity,
                            "description": f.description,
                            "evidence": f.evidence,
                            "remediation": f.remediation,
                        }
                        for f in result.findings
                    ],
                },
                f,
                indent=2,
            )
        logger.info(f"Results saved to {output_file}")


# ─── Async Bulk Scanner ───────────────────────────────────────────────────────

async def scan_bulk_async(
    subdomains: list[str],
    output_dir: str = "./results",
    timeout: int = 8,
    concurrency: int = 20,
) -> list[TakeoverResult]:
    """
    Async bulk takeover scanner for wordlist-driven mass scanning.

    Args:
        subdomains: List of subdomain strings to scan (e.g. ["api.target.com", "dev.target.com"])
        output_dir: Output directory for results
        timeout: Per-request timeout in seconds
        concurrency: Max concurrent scans

    Returns:
        List of TakeoverResult objects
    """
    sem = asyncio.Semaphore(concurrency)
    results: list[TakeoverResult] = []

    async def scan_one(subdomain: str) -> TakeoverResult:
        async with sem:
            # Run sync scanner in thread pool to avoid blocking
            loop = asyncio.get_running_loop()
            scanner = TakeoverScanner(subdomain, output_dir, timeout=timeout)
            return await loop.run_in_executor(None, scanner.run_full_scan)

    tasks = [scan_one(sub) for sub in subdomains]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return list(results)


# ─── Legacy Functions (backward compat) ──────────────────────────────────────

def check_cname_takeover(target: str, output_dir: str = "./results") -> dict:
    """Legacy CNAME takeover check."""
    scanner = TakeoverScanner(target, output_dir)
    findings = scanner.check_cname()
    return {
        "target": target,
        "method": "cname_takeover",
        "vulnerable": len(findings) > 0,
        "dangling_cnames": [
            {"subdomain": f.subdomain, "cname": f.cname, "service": f.service}
            for f in findings
        ],
    }


def check_ns_takeover(target: str, output_dir: str = "./results") -> dict:
    """Legacy NS takeover check."""
    scanner = TakeoverScanner(target, output_dir)
    findings = scanner.check_ns()
    return {
        "target": target,
        "method": "ns_takeover",
        "vulnerable": len(findings) > 0,
        "dead_nameservers": [f.ns_record for f in findings],
    }


def scan_takeover(target: str, output_dir: str = "./results") -> dict:
    """Legacy full takeover scan."""
    scanner = TakeoverScanner(target, output_dir)
    result = scanner.run_full_scan()
    return {
        "target": result.target,
        "cname_vulnerable": result.cname_vulnerable,
        "ns_vulnerable": result.ns_vulnerable,
        "a_record_vulnerable": result.a_record_vulnerable,
        "mx_vulnerable": result.mx_vulnerable,
        "srv_vulnerable": result.srv_vulnerable,
        "wildcard_detected": result.wildcard_detected,
        "findings_count": len(result.findings),
    }
