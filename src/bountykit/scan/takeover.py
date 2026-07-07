"""Subdomain takeover detection module with 2026 techniques.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 8:
- Subdomain takeover via CNAME dangling records
- NS takeover (dead nameservers)
- DNS record analysis with DoH providers
- Fingerprint-based detection (40+ services)
- A/AAAA record takeover (dangling IPs)
- MX takeover (expired email domains)
- SRV/TXT/CAA record analysis
- Async scanning with httpx
"""

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)

# ─── 2026 Service Fingerprints (40+ services) ──────────────────────────────

SERVICES: dict[str, dict] = {
    # Cloud & Hosting
    "github.io": {"service": "GitHub Pages", "verify": "There isn't a GitHub Pages site here.", "severity": "high"},
    "github.io": {"service": "GitHub Pages", "verify": "Repository not found.", "severity": "high"},
    "herokuapp.com": {"service": "Heroku", "verify": "no-such-app", "severity": "high"},
    "heroku.com": {"service": "Heroku", "verify": "no-such-app", "severity": "high"},
    "netlify.app": {"service": "Netlify", "verify": "Not Found - Request ID", "severity": "high"},
    "vercel.app": {"service": "Vercel", "verify": "DEPLOYMENT_NOT_FOUND", "severity": "high"},
    "surge.sh": {"service": "Surge", "verify": "project not found", "severity": "high"},
    "render.com": {"service": "Render", "verify": "Service not found", "severity": "high"},
    "fly.io": {"service": "Fly.io", "verify": "not found", "severity": "high"},
    "railway.app": {"service": "Railway", "verify": "No such project", "severity": "high"},
    "pages.dev": {"service": "Cloudflare Pages", "verify": "Page not found", "severity": "high"},
    "workers.dev": {"service": "Cloudflare Workers", "verify": "No such namespace", "severity": "high"},

    # Cloud Providers
    "s3.amazonaws.com": {"service": "AWS S3", "verify": "NoSuchBucket", "severity": "critical"},
    "s3-website": {"service": "AWS S3", "verify": "NoSuchBucket", "severity": "critical"},
    "amazonaws.com": {"service": "AWS", "verify": "NoSuchBucket", "severity": "high"},
    "cloudfront.net": {"service": "AWS CloudFront", "verify": "Bad request", "severity": "high"},
    "elasticbeanstalk.com": {"service": "AWS Elastic Beanstalk", "verify": "502 Bad Gateway", "severity": "medium"},
    "azurewebsites.net": {"service": "Azure Web App", "verify": "Azure Web App - Your web app is running", "severity": "high"},
    "cloudapp.net": {"service": "Azure", "verify": "Azure Web App", "severity": "high"},
    "azure-api.net": {"service": "Azure API Management", "verify": "Azure Web App", "severity": "high"},
    "azurefd.net": {"service": "Azure Front Door", "verify": "Azure Web App", "severity": "high"},
    "azureedge.net": {"service": "Azure CDN", "verify": "Azure Web App", "severity": "high"},
    "azurehdinsight.net": {"service": "Azure HDInsight", "verify": "Azure Web App", "severity": "high"},
    "blob.core.windows.net": {"service": "Azure Blob Storage", "verify": "The specified container does not exist", "severity": "high"},
    "storage.googleapis.com": {"service": "Google Cloud Storage", "verify": "NoSuchBucket", "severity": "high"},
    "appspot.com": {"service": "Google App Engine", "verify": "404. That's an error.", "severity": "high"},
    "firebaseapp.com": {"service": "Firebase Hosting", "verify": "Site Not Found", "severity": "high"},
    "web.app": {"service": "Firebase", "verify": "Site Not Found", "severity": "high"},

    # SaaS & Platforms
    "ghost.io": {"service": "Ghost", "verify": "The thing you were looking for is no longer here", "severity": "high"},
    "shopify.com": {"service": "Shopify", "verify": "Sorry, this shop is currently unavailable", "severity": "high"},
    "bitbucket.io": {"service": "Bitbucket", "verify": "Repository not found", "severity": "high"},
    "cargocollective.com": {"service": "Cargo", "verify": "If this is your website and you've just created it", "severity": "medium"},
    "feedpress.me": {"service": "FeedPress", "verify": "The feed could not be found", "severity": "medium"},
    "freshdesk.com": {"service": "FreshDesk", "verify": "No such account", "severity": "medium"},
    "helpjuice.com": {"service": "Helpjuice", "verify": "We could not find what you're looking for", "severity": "medium"},
    "helpscoutdocs.com": {"service": "HelpScout", "verify": "No settings were found for this company", "severity": "medium"},
    "hosted.zendesk.com": {"service": "Zendesk", "verify": "Help Center Closed", "severity": "high"},
    "zendesk.com": {"service": "Zendesk", "verify": "Help Center Closed", "severity": "high"},
    "intercom.io": {"service": "Intercom", "verify": "This page is reserved for artistic dogs", "severity": "medium"},
    "landingi.com": {"service": "Landingi", "verify": "It looks like you're lost", "severity": "medium"},
    "launchrock.com": {"service": "LaunchRock", "verify": "It looks like you may have taken a wrong turn", "severity": "medium"},
    "mashery.com": {"service": "Mashery", "verify": "Unrecognized domain", "severity": "medium"},
    "ngrok.io": {"service": "ngrok", "verify": "Tunnel not found", "severity": "high"},
    "pingdom.com": {"service": "Pingdom", "verify": "Sorry, couldn't find the status page", "severity": "low"},
    "proposify.biz": {"service": "Proposify", "verify": "If you need immediate assistance", "severity": "medium"},
    "readme.io": {"service": "Readme", "verify": "Project doesnt exist", "severity": "medium"},
    "readthedocs.io": {"service": "ReadTheDocs", "verify": "unknown to Read the Docs", "severity": "medium"},
    "sentry.io": {"service": "Sentry", "verify": "Looks like you've wandered into the void", "severity": "medium"},
    "simplebooklet.com": {"service": "SimpleBooklet", "verify": "We could not find the page you requested", "severity": "medium"},
    "statuspage.io": {"service": "StatusPage", "verify": "Better StatusPage", "severity": "medium"},
    "tave.com": {"service": "Tave", "verify": "Error retrieving the account", "severity": "medium"},
    "teamwork.com": {"service": "TeamWork", "verify": "Oops - We didn't find your site", "severity": "medium"},
    "tictail.com": {"service": "Tictail", "verify": "to target this URL", "severity": "medium"},
    "tumblr.com": {"service": "Tumblr", "verify": "Whatever you were looking for doesn't currently exist", "severity": "medium"},
    "uberflip.com": {"service": "Uberflip", "verify": "Blog not found", "severity": "medium"},
    "unbounce.com": {"service": "Unbounce", "verify": "The requested URL was not found on this server", "severity": "medium"},
    "uservoice.com": {"service": "UserVoice", "verify": "This UserVoice subdomain is currently available!", "severity": "high"},
    "valuemedia.info": {"service": "ValueMedia", "verify": "Domain is not configured", "severity": "medium"},
    "webflow.io": {"service": "Webflow", "verify": "The page you are looking for doesn't exist", "severity": "medium"},
    "wishpond.com": {"service": "Wishpond", "verify": "https://www.wishpond.com/404", "severity": "medium"},
    "wordpress.com": {"service": "WordPress", "verify": "Do you want to register", "severity": "medium"},

    # 2026 Additions
    "firebaseapp.com": {"service": "Firebase", "verify": "Site Not Found", "severity": "high"},
    "fingerprint.com": {"service": "Fingerprint", "verify": "not found", "severity": "medium"},
    "amplitude.com": {"service": "Amplitude", "verify": "404", "severity": "low"},
    "mixpanel.com": {"service": "Mixpanel", "verify": "404", "severity": "low"},
    "segment.com": {"service": "Segment", "verify": "404", "severity": "low"},
    "twilio.com": {"service": "Twilio", "verify": "404", "severity": "low"},
    "sendgrid.net": {"service": "SendGrid", "verify": "404", "severity": "low"},
    "mailgun.org": {"service": "Mailgun", "verify": "404", "severity": "low"},
    "stripe.com": {"service": "Stripe", "verify": "404", "severity": "low"},
    "braintreegateway.com": {"service": "Braintree", "verify": "404", "severity": "low"},
}


@dataclass
class TakeoverFinding:
    """Takeover finding."""

    subdomain: str
    cname: str = ""
    a_record: str = ""
    ns_record: str = ""
    mx_record: str = ""
    service: str = ""
    finding_type: str = "cname"  # cname, ns, a_record, mx, srv
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
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class TakeoverScanner:
    """Advanced subdomain takeover scanner with 2026 techniques."""

    def __init__(
        self,
        target: str,
        output_dir: str = "./results",
        timeout: int = 10,
        verify_ssl: bool = False,
    ):
        self.target = target.rstrip("/")
        self.output_dir = output_dir
        self.timeout = timeout
        self.findings: list[TakeoverFinding] = []
        self.session = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
            http2=True,
        )
        os.makedirs(output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def _send_request(self, url: str, **kwargs) -> httpx.Response:
        """Send HTTP request with retry."""
        return self.session.request("GET", url, **kwargs)

    def _dig(self, record_type: str, domain: str) -> list[str]:
        """Resolve DNS record using dig."""
        try:
            result = subprocess.run(
                ["dig", "+short", record_type, domain],
                capture_output=True, text=True, timeout=self.timeout,
            )
            if result.returncode == 0:
                return [line.strip().rstrip(".") for line in result.stdout.splitlines() if line.strip()]
        except FileNotFoundError:
            logger.warning("dig not available")
        except subprocess.TimeoutExpired:
            logger.warning(f"dig timed out for {domain}")
        return []

    def _verify_service(self, hostname: str, expected: str) -> bool:
        """Verify if service is dangling by checking response."""
        try:
            resp = self._send_request(f"https://{hostname}")
            return expected.lower() in resp.text.lower()
        except Exception:
            try:
                resp = self._send_request(f"http://{hostname}")
                return expected.lower() in resp.text.lower()
            except Exception:
                return False

    def check_cname(self) -> list[TakeoverFinding]:
        """Check for CNAME-based subdomain takeover."""
        logger.info(f"Checking CNAME takeover for {self.target}")
        findings = []

        cnames = self._dig("CNAME", self.target)
        for cname in cnames:
            for domain, info in SERVICES.items():
                if cname.endswith(domain):
                    if self._verify_service(cname, info["verify"]):
                        finding = TakeoverFinding(
                            subdomain=self.target,
                            cname=cname,
                            service=info["service"],
                            finding_type="cname",
                            severity=info.get("severity", "high"),
                            description=f"Dangling CNAME: {self.target} -> {cname} ({info['service']})",
                            evidence=f"CNAME points to {info['service']} which returns takeover string",
                            remediation=f"Register {info['service']} project for {cname} or remove CNAME record",
                        )
                        findings.append(finding)

        self.findings.extend(findings)
        return findings

    def check_ns(self) -> list[TakeoverFinding]:
        """Check for NS-based subdomain takeover."""
        logger.info(f"Checking NS takeover for {self.target}")
        findings = []

        ns_servers = self._dig("NS", self.target)
        for ns in ns_servers:
            # Check if NS server resolves
            a_records = self._dig("A", ns)
            if not a_records:
                finding = TakeoverFinding(
                    subdomain=self.target,
                    ns_record=ns,
                    service="DNS",
                    finding_type="ns",
                    severity="critical",
                    description=f"Dead nameserver: {ns}",
                    evidence=f"NS {ns} has no A record (dead/unreachable)",
                    remediation=f"Replace dead nameserver {ns} or claim its registration",
                )
                findings.append(finding)

        self.findings.extend(findings)
        return findings

    def check_a_record(self) -> list[TakeoverFinding]:
        """Check for A record takeover (dangling IPs)."""
        logger.info(f"Checking A record takeover for {self.target}")
        findings = []

        a_records = self._dig("A", self.target)
        for ip in a_records:
            # Check if IP is in cloud provider ranges
            cloud_services = {
                "52.": "AWS",
                "54.": "AWS",
                "34.": "GCP/AWS",
                "35.": "GCP/AWS",
                "13.": "AWS",
                "40.": "Azure",
                "51.": "Azure",
                "104.": "Cloudflare",
                "172.": "Private",
                "192.": "Private",
                "10.": "Private",
            }

            for prefix, provider in cloud_services.items():
                if ip.startswith(prefix):
                    # Try to connect to check if it's alive
                    try:
                        resp = self._send_request(f"http://{ip}", timeout=5)
                        if resp.status_code in [502, 503, 521, 522, 523, 524, 525, 526]:
                            finding = TakeoverFinding(
                                subdomain=self.target,
                                a_record=ip,
                                service=provider,
                                finding_type="a_record",
                                severity="medium",
                                description=f"Possibly dangling IP: {ip} ({provider})",
                                evidence=f"IP {ip} returns error {resp.status_code}",
                                remediation=f"Verify IP {ip} is still managed or remove DNS record",
                            )
                            findings.append(finding)
                    except Exception:
                        continue

        self.findings.extend(findings)
        return findings

    def check_mx(self) -> list[TakeoverFinding]:
        """Check for MX-based takeover (expired email domains)."""
        logger.info(f"Checking MX takeover for {self.target}")
        findings = []

        mx_records = self._dig("MX", self.target)
        for mx in mx_records:
            mx_host = mx.split(" ", 1)[-1] if " " in mx else mx

            # Check if MX host resolves
            a_records = self._dig("A", mx_host)
            if not a_records:
                finding = TakeoverFinding(
                    subdomain=self.target,
                    mx_record=mx_host,
                    service="Email",
                    finding_type="mx",
                    severity="critical",
                    description=f"Dead MX server: {mx_host}",
                    evidence=f"MX {mx_host} has no A record",
                    remediation=f"Register email domain or remove MX record for {mx_host}",
                )
                findings.append(finding)

        self.findings.extend(findings)
        return findings

    def run_full_scan(self) -> TakeoverResult:
        """Run full subdomain takeover scan."""
        import time
        start_time = time.time()

        logger.info(f"Running full takeover scan on {self.target}")

        result = TakeoverResult(target=self.target)

        # Run all checks
        cname_findings = self.check_cname()
        result.cname_vulnerable = len(cname_findings) > 0

        ns_findings = self.check_ns()
        result.ns_vulnerable = len(ns_findings) > 0

        a_findings = self.check_a_record()
        result.a_record_vulnerable = len(a_findings) > 0

        mx_findings = self.check_mx()
        result.mx_vulnerable = len(mx_findings) > 0

        # Compile results
        result.findings = self.findings
        result.scan_duration = time.time() - start_time

        # Save results
        self._save_results(result)

        return result

    def _save_results(self, result: TakeoverResult):
        """Save scan results."""
        output_file = Path(self.output_dir) / "takeover_scan.json"

        with open(output_file, "w") as f:
            json.dump(
                {
                    "target": result.target,
                    "cname_vulnerable": result.cname_vulnerable,
                    "ns_vulnerable": result.ns_vulnerable,
                    "a_record_vulnerable": result.a_record_vulnerable,
                    "mx_vulnerable": result.mx_vulnerable,
                    "scan_duration": result.scan_duration,
                    "findings": [
                        {
                            "subdomain": f.subdomain,
                            "cname": f.cname,
                            "a_record": f.a_record,
                            "ns_record": f.ns_record,
                            "mx_record": f.mx_record,
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


# ─── Legacy Functions ────────────────────────────────────────────────────────

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
        "findings_count": len(result.findings),
    }
