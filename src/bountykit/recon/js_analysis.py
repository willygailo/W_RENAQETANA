"""JavaScript recon and analysis module with 2026 techniques.

Covers:
- JS file discovery and download (katana, curl, httpx)
- Secret extraction from JS (API keys, tokens, AWS keys, JWTs, 2026 patterns)
- DOM-based XSS hunting (dangerous sinks/sources, mutation XSS)
- Endpoint extraction from JS files
- Source map analysis
- Webpack bundle analysis
- AI/LLM token extraction
- GraphQL schema extraction from JS
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

# ─── Secret Extraction Patterns (2026) ──────────────────────────────────────

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "api_key": re.compile(
        r'(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)'
        r'["\s]*[:=]["\s]*["\']?([a-zA-Z0-9_\-]{8,})',
        re.IGNORECASE,
    ),
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret_key": re.compile(
        r'(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)'
        r'["\s]*[:=]["\s]*["\']?([a-zA-Z0-9/+=]{40})',
        re.IGNORECASE,
    ),
    "jwt_token": re.compile(
        r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'
    ),
    "generic_secret": re.compile(
        r'(?:secret|password|passwd|token|auth|private[_-]?key)'
        r'["\s]*[:=]["\s]*["\']?([a-zA-Z0-9_\-]{8,})',
        re.IGNORECASE,
    ),
    "firebase_url": re.compile(
        r'https://[a-zA-Z0-9_-]+\.firebaseio\.com'
    ),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "slack_webhook": re.compile(
        r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'
    ),
    "github_token": re.compile(
        r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}'
    ),
    # 2026 additions
    "openai_key": re.compile(r'sk-[a-zA-Z0-9]{48}'),
    "anthropic_key": re.compile(r'sk-ant-[a-zA-Z0-9\-]{40,}'),
    "huggingface_token": re.compile(r'hf_[a-zA-Z0-9]{34}'),
    "npm_token": re.compile(r'npm_[a-zA-Z0-9]{36}'),
    "pypi_token": re.compile(r'pypi-[a-zA-Z0-9\-]{50,}'),
    "stripe_key": re.compile(r'(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{20,}'),
    "twilio_sid": re.compile(r'AC[a-f0-9]{32}'),
    "sendgrid_key": re.compile(r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'),
    "mailgun_key": re.compile(r'key-[a-zA-Z0-9]{32}'),
    "heroku_api_key": re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    "alibaba_access_key':": re.compile(r'LTAI[a-zA-Z0-9]{12,20}'),
    "digitalocean_token": re.compile(r'dop_v1_[a-f0-9]{64}'),
    "netlify_token": re.compile(r'fp_[a-f0-9]{40}'),
    "vercel_token": re.compile(r'.vercel_([a-zA-Z0-9]{20,})'),
    "cloudflare_api_key": re.compile(r'[a-f0-9]{37}'),
    "gitlab_token": re.compile(r'glpat-[a-zA-Z0-9\-_]{20,}'),
    "bitbucket_token": re.compile(r'ATBB[a-zA-Z0-9]{32}'),
    "npmrc_token": re.compile(r'//registry\.npmjs\.org/:_authToken=[a-zA-Z0-9\-]+'),
}

# ─── DOM XSS Dangerous Sinks ───────────────────────────────────────────────

DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "location.assign(", "location.replace(", "document.domain",
    "insertAdjacentHTML", "Range.createContextualFragment",
    "MSApp.execUnsafeLocalFunction",
]

# ─── DOM XSS Sources ───────────────────────────────────────────────────────

DOM_SOURCES = [
    "location.hash", "location.search", "location.href",
    "location.pathname", "document.URL", "document.referrer",
    "document.cookie", "window.name", "postMessage",
    "localStorage", "sessionStorage", "IndexedDB",
]

# ─── Webpack/Source Map Indicators ──────────────────────────────────────────

WEBPACK_PATTERNS = [
    re.compile(r'webpackJsonp|webpackChunk|__webpack_require__'),
    re.compile(r'//#\s*sourceMappingURL=data:'),
    re.compile(r'//#\s*sourceMappingURL='),
]

SOURCE_MAP_PATTERNS = [
    re.compile(r'\.map["\']?\s*$', re.MULTILINE),
    re.compile(r'sourceMappingURL\s*=\s*["\']?[^"\']+\.map'),
]

# ─── AI/LLM Token Patterns ─────────────────────────────────────────────────

AI_TOKEN_PATTERNS = {
    "openai_key": re.compile(r'sk-[a-zA-Z0-9]{48}'),
    "anthropic_key": re.compile(r'sk-ant-[a-zA-Z0-9\-]{40,}'),
    "cohere_key": re.compile(r'[a-zA-Z0-9]{40}'),
    "mistral_key": re.compile(r'[a-zA-Z0-9]{32}'),
    "replicate_token": re.compile(r'r8_[a-zA-Z0-9]{40}'),
    "huggingface_token": re.compile(r'hf_[a-zA-Z0-9]{34}'),
    "ollama_endpoint": re.compile(r'localhost:11434|127\.0\.0\.1:11434'),
    "langchain_api_key": re.compile(r'lc_[a-zA-Z0-9]{32}'),
    "pinecone_key": re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'),
    "weaviate_key':": re.compile(r'wcs_[a-zA-Z0-9]{32}'),
    "chroma_key": re.compile(r'chroma_[a-zA-Z0-9]{32}'),
}

# ─── GraphQL Endpoint Patterns ──────────────────────────────────────────────

GRAPHQL_PATTERNS = [
    re.compile(r'/graphql(?:/[a-zA-Z0-9_]+)?'),
    re.compile(r'gql|graphql|graphiql'),
    re.compile(r'__schema|__type|__typename'),
]


@dataclass
class JSFinding:
    """JS analysis finding."""

    finding_type: str  # secret, endpoint, dom_xss, webpack, source_map, graphql, ai_token
    severity: str
    description: str
    evidence: str = ""
    file: str = ""
    line: int = 0
    remediation: str = ""


@dataclass
class JSResult:
    """Complete JS analysis result."""

    target: str
    findings: list[JSFinding] = field(default_factory=list)
    js_files_found: int = 0
    secrets_found: int = 0
    endpoints_found: int = 0
    dom_xss_candidates: int = 0
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class JSScanner:
    """Advanced JavaScript analysis scanner with 2026 techniques."""

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
        self.findings: list[JSFinding] = []
        self.session = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
        )
        os.makedirs(output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def _send_request(self, url: str, **kwargs) -> httpx.Response:
        """Send HTTP request with retry."""
        return self.session.request("GET", url, **kwargs)

    def discover_js_files(self) -> list[str]:
        """Discover JS files from target."""
        logger.info(f"Discovering JS files on {self.target}")
        js_urls = []

        try:
            resp = self._send_request(self.target)
            body = resp.text

            # Extract JS URLs from HTML
            js_pattern = re.compile(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']')
            matches = js_pattern.findall(body)

            for match in matches:
                if match.startswith("//"):
                    match = "https:" + match
                elif match.startswith("/"):
                    match = self.target.rstrip("/") + match
                elif not match.startswith("http"):
                    match = self.target.rstrip("/") + "/" + match
                js_urls.append(match)

            # Also check for script tags with inline content
            script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL)
            scripts = script_pattern.findall(body)

            js_urls = list(set(js_urls))
            logger.info(f"Found {len(js_urls)} JS files")

        except Exception as e:
            logger.warning(f"JS discovery failed: {e}")

        return js_urls

    def extract_secrets(self, js_content: str, file_name: str = "unknown") -> list[JSFinding]:
        """Extract secrets from JS content."""
        findings = []

        for pattern_name, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(js_content) or pattern.search(js_content)
            if matches:
                if isinstance(matches, list):
                    for match in matches:
                        if isinstance(match, str) and len(match) >= 8:
                            findings.append(JSFinding(
                                finding_type="secret",
                                severity="high",
                                description=f"Secret found: {pattern_name}",
                                evidence=f"Value: {match[:20]}...",
                                file=file_name,
                                remediation=f"Rotate {pattern_name} and ensure it's not in client-side code",
                            ))
                elif isinstance(matches, re.Match):
                    findings.append(JSFinding(
                        finding_type="secret",
                        severity="high",
                        description=f"Secret found: {pattern_name}",
                        evidence=f"Value: {matches.group()[:30]}",
                        file=file_name,
                        remediation=f"Rotate {pattern_name} and ensure it's not in client-side code",
                    ))

        return findings

    def extract_ai_tokens(self, js_content: str, file_name: str = "unknown") -> list[JSFinding]:
        """Extract AI/LLM API tokens from JS content."""
        findings = []

        for pattern_name, pattern in AI_TOKEN_PATTERNS.items():
            matches = pattern.findall(js_content)
            for match in matches:
                if isinstance(match, str) and len(match) >= 8:
                    findings.append(JSFinding(
                        finding_type="ai_token",
                        severity="critical",
                        description=f"AI/LLM token found: {pattern_name}",
                        evidence=f"Value: {match[:20]}...",
                        file=file_name,
                        remediation=f"Rotate {pattern_name} immediately and move to server-side",
                    ))

        return findings

    def hunt_dom_xss(self, js_content: str, file_name: str = "unknown") -> list[JSFinding]:
        """Hunt for DOM-based XSS in JS content."""
        findings = []
        lines = js_content.splitlines()

        for i, line in enumerate(lines, 1):
            if len(line) > 1000:  # Skip minified
                continue

            # Check for dangerous sinks
            for sink in DOM_SINKS:
                if sink.lower() in line.lower():
                    # Check if any source is also present
                    for source in DOM_SOURCES:
                        if source.lower() in line.lower() or source.lower() in js_content.lower():
                            findings.append(JSFinding(
                                finding_type="dom_xss",
                                severity="high",
                                description=f"Potential DOM XSS: sink '{sink}' with source '{source}'",
                                evidence=f"Line {i}: {line.strip()[:100]}",
                                file=file_name,
                                line=i,
                                remediation=f"Avoid using {sink} with user-controlled data from {source}",
                            ))
                            break

        return findings

    def detect_webpack(self, js_content: str, file_name: str = "unknown") -> list[JSFinding]:
        """Detect webpack bundles and source maps."""
        findings = []

        for pattern in WEBPACK_PATTERNS:
            if pattern.search(js_content):
                findings.append(JSFinding(
                    finding_type="webpack",
                    severity="info",
                    description="Webpack bundle detected",
                    file=file_name,
                    remediation="Check for exposed source maps",
                ))
                break

        for pattern in SOURCE_MAP_PATTERNS:
            if pattern.search(js_content):
                findings.append(JSFinding(
                    finding_type="source_map",
                    severity="medium",
                    description="Source map reference found",
                    file=file_name,
                    remediation="Remove source maps from production builds",
                ))
                break

        return findings

    def extract_endpoints(self, js_content: str, file_name: str = "unknown") -> list[JSFinding]:
        """Extract API endpoints from JS content."""
        findings = []
        endpoints = set()

        patterns = [
            re.compile(r'["\'](/[a-zA-Z0-9_/\-\.]+(?:\?[^"\']*)?)["\']'),
            re.compile(r'(?:fetch|axios|ajax|XMLHttpRequest)\s*\(\s*["\']([^"\']+)["\']'),
            re.compile(r'(?:location\.(?:href|assign|replace))\s*=\s*["\']([^"\']+)["\']'),
        ]

        for pattern in patterns:
            matches = pattern.findall(js_content)
            for match in matches:
                if isinstance(match, str) and len(match) > 1:
                    endpoints.add(match)

        if endpoints:
            findings.append(JSFinding(
                finding_type="endpoint",
                severity="info",
                description=f"Found {len(endpoints)} potential endpoints",
                evidence=f"First 5: {list(endpoints)[:5]}",
                file=file_name,
            ))

        return findings

    def detect_graphql(self, js_content: str, file_name: str = "unknown") -> list[JSFinding]:
        """Detect GraphQL usage and schema exposure."""
        findings = []

        for pattern in GRAPHQL_PATTERNS:
            matches = pattern.findall(js_content)
            if matches:
                findings.append(JSFinding(
                    finding_type="graphql",
                    severity="info",
                    description="GraphQL usage detected",
                    evidence=f"Matches: {matches[:3]}",
                    file=file_name,
                ))
                break

        return findings

    def run_full_scan(self) -> JSResult:
        """Run full JS analysis scan."""
        import time
        start_time = time.time()

        logger.info(f"Running full JS analysis on {self.target}")

        result = JSResult(target=self.target)

        # Discover JS files
        js_urls = self.discover_js_files()
        result.js_files_found = len(js_urls)

        # Analyze each JS file
        js_dir = Path(self.output_dir) / "js_files"
        js_dir.mkdir(exist_ok=True)

        for i, url in enumerate(js_urls[:50]):  # Limit to 50 files
            try:
                resp = self._send_request(url)
                if resp.status_code == 200:
                    content = resp.text
                    file_name = url.split("/")[-1].split("?")[0]
                    if not file_name.endswith(".js"):
                        file_name = f"js_{i:04d}.js"

                    # Save file
                    (js_dir / file_name).write_text(content)

                    # Run all analyses
                    self.findings.extend(self.extract_secrets(content, file_name))
                    self.findings.extend(self.extract_ai_tokens(content, file_name))
                    self.findings.extend(self.hunt_dom_xss(content, file_name))
                    self.findings.extend(self.detect_webpack(content, file_name))
                    self.findings.extend(self.extract_endpoints(content, file_name))
                    self.findings.extend(self.detect_graphql(content, file_name))

            except Exception as e:
                logger.warning(f"Failed to analyze {url}: {e}")

        # Compile results
        result.findings = self.findings
        result.secrets_found = sum(1 for f in self.findings if f.finding_type in ["secret", "ai_token"])
        result.endpoints_found = sum(1 for f in self.findings if f.finding_type == "endpoint")
        result.dom_xss_candidates = sum(1 for f in self.findings if f.finding_type == "dom_xss")
        result.scan_duration = time.time() - start_time

        self._save_results(result)
        return result

    def _save_results(self, result: JSResult):
        """Save scan results."""
        output_file = Path(self.output_dir) / "js_analysis.json"

        with open(output_file, "w") as f:
            json.dump(
                {
                    "target": result.target,
                    "js_files_found": result.js_files_found,
                    "secrets_found": result.secrets_found,
                    "endpoints_found": result.endpoints_found,
                    "dom_xss_candidates": result.dom_xss_candidates,
                    "scan_duration": result.scan_duration,
                    "findings": [
                        {
                            "finding_type": f.finding_type,
                            "severity": f.severity,
                            "description": f.description,
                            "evidence": f.evidence,
                            "file": f.file,
                            "line": f.line,
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

def discover_js_files(target: str, output_dir: str = "./results") -> dict:
    """Legacy JS discovery."""
    scanner = JSScanner(target, output_dir)
    js_urls = scanner.discover_js_files()
    return {"target": target, "js_files": js_urls, "total": len(js_urls)}


def extract_secrets(target: str, js_dir: str = "./results/js_files", output_dir: str = "./results") -> dict:
    """Legacy secret extraction."""
    scanner = JSScanner(target, output_dir)
    js_path = Path(js_dir)
    if js_path.exists():
        for js_file in js_path.glob("**/*.js"):
            content = js_file.read_text(errors="ignore")
            scanner.findings.extend(scanner.extract_secrets(content, js_file.name))
    return {
        "target": target,
        "secrets": [
            {"type": f.finding_type, "description": f.description, "file": f.file}
            for f in scanner.findings
            if f.finding_type in ["secret", "ai_token"]
        ],
    }


def hunt_dom_xss(target: str, js_dir: str = "./results/js_files", output_dir: str = "./results") -> dict:
    """Legacy DOM XSS hunting."""
    scanner = JSScanner(target, output_dir)
    js_path = Path(js_dir)
    if js_path.exists():
        for js_file in js_path.glob("**/*.js"):
            content = js_file.read_text(errors="ignore")
            scanner.findings.extend(scanner.hunt_dom_xss(content, js_file.name))
    return {
        "target": target,
        "potential_xss": [
            {"description": f.description, "file": f.file, "line": f.line}
            for f in scanner.findings
            if f.finding_type == "dom_xss"
        ],
    }


def extract_endpoints(target: str, js_dir: str = "./results/js_files", output_dir: str = "./results") -> dict:
    """Legacy endpoint extraction."""
    scanner = JSScanner(target, output_dir)
    js_path = Path(js_dir)
    if js_path.exists():
        for js_file in js_path.glob("**/*.js"):
            content = js_file.read_text(errors="ignore")
            scanner.findings.extend(scanner.extract_endpoints(content, js_file.name))
    return {
        "target": target,
        "endpoints": [
            {"description": f.description, "evidence": f.evidence}
            for f in scanner.findings
            if f.finding_type == "endpoint"
        ],
    }
