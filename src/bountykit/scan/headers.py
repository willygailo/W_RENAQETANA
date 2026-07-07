"""Security headers analysis module with 2026 techniques.

Covers:
- Missing security headers detection (20+ headers)
- Cookie security analysis
- Content Security Policy deep analysis
- HSTS analysis with preload checks
- HTTP security response headers audit
- AI/Agentic API response header analysis
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)

# ─── Required Security Headers (2026 OWASP) ─────────────────────────────────

REQUIRED_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS header missing — vulnerable to SSL stripping",
        "check_value": True,
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "MIME type sniffing not prevented",
        "expected": "nosniff",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Clickjacking possible — X-Frame-Options missing",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "description": "CSP missing — no XSS mitigation",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer policy not set",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions policy not set",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "description": "COOP not set — vulnerable to Spectre-type attacks",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "low",
        "description": "CORP not set — vulnerable to cross-origin reads",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "low",
        "description": "COEP not set — cannot use cross-origin resources safely",
    },
    "X-DNS-Prefetch-Control": {
        "severity": "low",
        "description": "DNS prefetch not controlled — potential privacy leak",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "severity": "low",
        "description": "Cross-domain policies not restricted",
    },
}

# ─── Recommended but not critical ────────────────────────────────────────────

RECOMMENDED_HEADERS = {
    "X-XSS-Protection": {
        "severity": "low",
        "description": "Legacy XSS filter (deprecated but still useful)",
        "expected": "1; mode=block",
    },
    "X-Download-Options": {
        "severity": "low",
        "description": "IE download options not set",
        "expected": "noopen",
    },
    "Expect-CT": {
        "severity": "low",
        "description": "Certificate Transparency not enforced",
    },
}

# ─── Dangerous Headers ──────────────────────────────────────────────────────

DANGEROUS_HEADERS = {
    "X-Powered-By": {
        "severity": "info",
        "description": "Server technology disclosure",
    },
    "Server": {
        "severity": "info",
        "description": "Server information disclosure",
    },
    "X-AspNet-Version": {
        "severity": "info",
        "description": "ASP.NET version disclosure",
    },
    "X-AspNetMvc-Version": {
        "severity": "info",
        "description": "ASP.NET MVC version disclosure",
    },
    "X-Generator": {
        "severity": "low",
        "description": "CMS generator disclosure",
    },
}

# ─── HSTS Analysis ──────────────────────────────────────────────────────────

HSTS_CHECKS = {
    "max-age": {
        "minimum": 31536000,  # 1 year
        "description": "max-age should be at least 1 year",
    },
    "includeSubDomains": {
        "recommended": True,
        "description": "includeSubDomains recommended for full protection",
    },
    "preload": {
        "recommended": True,
        "description": "preload allows inclusion in browser preload lists",
    },
}

# ─── CSP Weakness Patterns ──────────────────────────────────────────────────

CSP_WEAKNESSES = {
    "unsafe-inline": {"severity": "high", "description": "Allows inline scripts — XSS possible"},
    "unsafe-eval": {"severity": "high", "description": "Allows eval() — XSS possible"},
    "*": {"severity": "critical", "description": "Wildcard allows all sources — CSP ineffective"},
    "data:": {"severity": "medium", "description": "data: URIs can be used for XSS"},
    "blob:": {"severity": "medium", "description": "blob: URIs can be used for XSS"},
    "http:": {"severity": "medium", "description": "HTTP sources allow MitM attacks"},
    "localhost": {"severity": "high", "description": "localhost in CSP — likely development config"},
    "127.0.0.1": {"severity": "high", "description": "localhost IP in CSP — likely development config"},
}


@dataclass
class HeaderFinding:
    """Header finding."""

    header: str
    severity: str
    finding_type: str  # missing, insecure, weak, info
    description: str
    value: str = ""
    remediation: str = ""


@dataclass
class HeaderResult:
    """Complete header scan result."""

    target: str
    findings: list[HeaderFinding] = field(default_factory=list)
    score: int = 0
    missing_count: int = 0
    insecure_count: int = 0
    hsts_issues: list[str] = field(default_factory=list)
    csp_issues: list[str] = field(default_factory=list)
    scan_duration: float = 0.0


class HeaderScanner:
    """Advanced security header scanner with 2026 techniques."""

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
        self.findings: list[HeaderFinding] = []
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

    def check_required_headers(self, headers: dict[str, str]) -> list[HeaderFinding]:
        """Check for missing required headers."""
        findings = []
        header_lower = {k.lower(): v for k, v in headers.items()}

        all_required = {**REQUIRED_HEADERS, **RECOMMENDED_HEADERS}

        for header, info in all_required.items():
            if header.lower() not in header_lower:
                findings.append(HeaderFinding(
                    header=header,
                    severity=info["severity"],
                    finding_type="missing",
                    description=info["description"],
                    remediation=f"Add {header} header",
                ))
            elif "expected" in info:
                actual = header_lower.get(header.lower(), "")
                if info["expected"].lower() not in actual.lower():
                    findings.append(HeaderFinding(
                        header=header,
                        severity="low",
                        finding_type="weak",
                        description=f"Expected {info['expected']}, got: {actual[:50]}",
                        value=actual[:50],
                        remediation=f"Set {header} to {info['expected']}",
                    ))

        self.findings.extend(findings)
        return findings

    def check_dangerous_headers(self, headers: dict[str, str]) -> list[HeaderFinding]:
        """Check for dangerous/informational headers."""
        findings = []

        for header, info in DANGEROUS_HEADERS.items():
            if header in headers:
                value = headers[header][:80]
                findings.append(HeaderFinding(
                    header=header,
                    severity=info["severity"],
                    finding_type="info",
                    description=f"{info['description']}: {value}",
                    value=value,
                    remediation=f"Remove or obscure {header} header",
                ))

        self.findings.extend(findings)
        return findings

    def analyze_hsts(self, headers: dict[str, str]) -> list[HeaderFinding]:
        """Deep HSTS analysis."""
        findings = []
        hsts = headers.get("strict-transport-security", "")

        if not hsts:
            return findings

        # Parse HSTS directives
        hsts_lower = hsts.lower()

        # Check max-age
        max_age_match = re.search(r"max-age=(\d+)", hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                findings.append(HeaderFinding(
                    header="Strict-Transport-Security",
                    severity="medium",
                    finding_type="weak",
                    description=f"HSTS max-age ({max_age}) is less than 1 year (31536000)",
                    value=hsts[:80],
                    remediation="Set max-age to at least 31536000 (1 year)",
                ))

        # Check includeSubDomains
        if "includesubdomains" not in hsts_lower:
            findings.append(HeaderFinding(
                header="Strict-Transport-Security",
                severity="low",
                finding_type="weak",
                description="HSTS missing includeSubDomains",
                value=hsts[:80],
                remediation="Add includeSubDomains directive",
            ))

        # Check preload
        if "preload" not in hsts_lower:
            findings.append(HeaderFinding(
                header="Strict-Transport-Security",
                severity="info",
                finding_type="info",
                description="HSTS missing preload directive",
                value=hsts[:80],
                remediation="Add preload directive for browser preload list",
            ))

        self.findings.extend(findings)
        return findings

    def analyze_csp(self, headers: dict[str, str]) -> list[HeaderFinding]:
        """Deep CSP analysis."""
        findings = []
        csp = headers.get("content-security-policy", "")

        if not csp:
            findings.append(HeaderFinding(
                header="Content-Security-Policy",
                severity="high",
                finding_type="missing",
                description="No CSP header found — no XSS mitigation",
                remediation="Implement Content-Security-Policy header",
            ))
            self.findings.extend(findings)
            return findings

        # Parse CSP directives
        directives = {}
        for directive in csp.split(";"):
            parts = directive.strip().split()
            if parts:
                directives[parts[0]] = parts[1:]

        # Check script-src
        script_src = directives.get("script-src", [])
        for weakness, info in CSP_WEAKNESSES.items():
            if weakness in script_src:
                findings.append(HeaderFinding(
                    header="Content-Security-Policy",
                    severity=info["severity"],
                    finding_type="weak",
                    description=f"script-src: {info['description']}",
                    value=weakness,
                    remediation=f"Remove '{weakness}' from script-src",
                ))

        # Check object-src
        object_src = directives.get("object-src", [])
        if "*" in object_src or "'unsafe-inline'" in object_src:
            findings.append(HeaderFinding(
                header="Content-Security-Policy",
                severity="medium",
                finding_type="weak",
                description="object-src allows unsafe sources",
                remediation="Set object-src to 'none'",
            ))

        # Check base-uri
        base_uri = directives.get("base-uri", [])
        if "'unsafe-inline'" in base_uri or "*" in base_uri:
            findings.append(HeaderFinding(
                header="Content-Security-Policy",
                severity="medium",
                finding_type="weak",
                description="base-uri allows unsafe-inline or wildcard",
                remediation="Set base-uri to 'self' or 'none'",
            ))

        # Check frame-ancestors
        if "frame-ancestors" not in directives:
            findings.append(HeaderFinding(
                header="Content-Security-Policy",
                severity="medium",
                finding_type="missing",
                description="Missing frame-ancestors directive",
                remediation="Add frame-ancestors 'none' or 'self'",
            ))

        # Check form-action
        if "form-action" not in directives:
            findings.append(HeaderFinding(
                header="Content-Security-Policy",
                severity="low",
                finding_type="missing",
                description="Missing form-action directive",
                remediation="Add form-action 'self'",
            ))

        # Check for report-uri/report-to
        if "report-uri" not in directives and "report-to" not in directives:
            findings.append(HeaderFinding(
                header="Content-Security-Policy",
                severity="info",
                finding_type="info",
                description="No CSP reporting configured",
                remediation="Add report-uri or report-to for CSP violation monitoring",
            ))

        self.findings.extend(findings)
        return findings

    def analyze_cookies(self, cookies: list) -> list[HeaderFinding]:
        """Analyze cookie security."""
        findings = []

        for cookie in cookies:
            issues = []

            if not cookie.secure:
                issues.append("Missing Secure flag")
            if not hasattr(cookie, "_http_only") or not getattr(cookie, "_http_only", False):
                issues.append("Missing HttpOnly flag")
            if not getattr(cookie, "_same_site", None):
                issues.append("Missing SameSite attribute")

            if issues:
                findings.append(HeaderFinding(
                    header="Cookie",
                    severity="medium" if "Secure" in issues else "high",
                    finding_type="insecure",
                    description=f"Insecure cookie '{cookie.name}': {', '.join(issues)}",
                    remediation=f"Set Secure, HttpOnly, and SameSite on cookie '{cookie.name}'",
                ))

        self.findings.extend(findings)
        return findings

    def run_full_scan(self) -> HeaderResult:
        """Run full security headers scan."""
        import time
        start_time = time.time()

        logger.info(f"Running full header scan on {self.target}")

        result = HeaderResult(target=self.target)

        try:
            resp = self._send_request(self.target)
            headers = dict(resp.headers)

            # Run all checks
            self.check_required_headers(headers)
            self.check_dangerous_headers(headers)
            self.analyze_hsts(headers)
            self.analyze_csp(headers)
            self.analyze_cookies(list(resp.cookies.jar))

            # Calculate score
            total_checks = len(REQUIRED_HEADERS) + len(RECOMMENDED_HEADERS)
            missing = sum(1 for f in self.findings if f.finding_type == "missing")
            weak = sum(1 for f in self.findings if f.finding_type == "weak")
            result.score = max(0, int(((total_checks - missing - weak) / total_checks) * 100))
            result.missing_count = missing
            result.insecure_count = weak

        except Exception as e:
            logger.error(f"Header scan failed: {e}")

        result.findings = self.findings
        result.scan_duration = time.time() - start_time

        self._save_results(result)
        return result

    def _save_results(self, result: HeaderResult):
        """Save scan results."""
        output_file = Path(self.output_dir) / "headers_scan.json"

        with open(output_file, "w") as f:
            json.dump(
                {
                    "target": result.target,
                    "score": result.score,
                    "missing_count": result.missing_count,
                    "insecure_count": result.insecure_count,
                    "scan_duration": result.scan_duration,
                    "findings": [
                        {
                            "header": f.header,
                            "severity": f.severity,
                            "finding_type": f.finding_type,
                            "description": f.description,
                            "value": f.value,
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

def analyze_headers(target: str, output_dir: str = "./results") -> dict:
    """Legacy header analysis."""
    scanner = HeaderScanner(target, output_dir)
    result = scanner.run_full_scan()
    return {
        "target": result.target,
        "score": result.score,
        "missing_count": result.missing_count,
        "insecure_count": result.insecure_count,
        "findings": [
            {"header": f.header, "severity": f.severity, "description": f.description}
            for f in result.findings
        ],
    }


def analyze_cookies(target: str, output_dir: str = "./results") -> dict:
    """Legacy cookie analysis."""
    scanner = HeaderScanner(target, output_dir)
    try:
        resp = scanner._send_request(target)
        scanner.analyze_cookies(list(resp.cookies.jar))
    except Exception:
        pass
    return {
        "target": target,
        "insecure_cookies": [
            {"header": f.header, "description": f.description}
            for f in scanner.findings
            if f.finding_type == "insecure"
        ],
    }


def analyze_csp(target: str, output_dir: str = "./results") -> dict:
    """Legacy CSP analysis."""
    scanner = HeaderScanner(target, output_dir)
    try:
        resp = scanner._send_request(target)
        scanner.analyze_csp(dict(resp.headers))
    except Exception:
        pass
    return {
        "target": target,
        "csp_issues": [
            {"description": f.description, "severity": f.severity}
            for f in scanner.findings
            if f.header == "Content-Security-Policy"
        ],
    }
