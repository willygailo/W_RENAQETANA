"""WebSocket security testing module.

Covers 2026 WebSocket security testing:
- WebSocket endpoint discovery (HTML, JS, known patterns)
- SSL/TLS security assessment
- Origin bypass / Cross-Site WebSocket Hijacking (CSWSH)
- Message injection (SQLi, XSS, NoSQL, command injection)
- DoS / resource exhaustion (connection flood, ping-pong, large messages)
- Message tampering / JSON parameter pollution
- Authentication bypass
- Subprotocol hijacking
"""

import asyncio
import json
import os
import re
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import websockets
    from websockets.client import connect as ws_connect
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    logger.warning("websockets library not installed. WebSocket scanner disabled. Install with: pip install websockets")

# ─── Common WebSocket Endpoint Patterns ───────────────────────────────────────

WS_ENDPOINT_PATTERNS = [
    "/ws", "/wss", "/websocket", "/socket", "/ws/v1", "/ws/v2",
    "/socket.io", "/sockjs", "/stomp", "/mqtt",
    "/ws/chat", "/ws/notifications", "/ws/realtime",
    "/api/ws", "/graphql", "/subscriptions",
    "/cable", "/live", "/events", "/stream",
]

WS_JS_PATTERNS = [
    r'new WebSocket\([\'\"](.+?)[\'\"]',
    r'wss?://[^\s\"\'<>]+',
    r'WebSocket\([\'\"](.+?)[\'\"]',
]

# ─── Injection Payloads ──────────────────────────────────────────────────────

INJECTION_PAYLOADS = [
    # SQL Injection
    {"name": "sqli_basic", "payload": "' OR '1'='1", "type": "sqli"},
    {"name": "sqli_union", "payload": "' UNION SELECT * FROM users--", "type": "sqli"},
    {"name": "sqli_time", "payload": "1' WAITFOR DELAY '0:0:5'--", "type": "sqli"},
    # XSS
    {"name": "xss_basic", "payload": "<script>alert(1)</script>", "type": "xss"},
    {"name": "xss_img", "payload": "<img src=x onerror=alert(1)>", "type": "xss"},
    {"name": "xss_svg", "payload": "<svg/onload=alert(1)>", "type": "xss"},
    # NoSQL Injection
    {"name": "nosql_dollar", "payload": '{"$ne": null}', "type": "nosql"},
    {"name": "nosql_gt", "payload": '{"$gt": ""}', "type": "nosql"},
    {"name": "nosql_where", "payload": '{"$where": "1==1"}', "type": "nosql"},
    # Command Injection
    {"name": "cmdi_basic", "payload": "; cat /etc/passwd", "type": "cmdi"},
    {"name": "cmdi_pipe", "payload": "| cat /etc/passwd", "type": "cmdi"},
    {"name": "cmdi_backtick", "payload": "`cat /etc/passwd`", "type": "cmdi"},
    # CRLF Injection
    {"name": "crlf_basic", "payload": "test\r\nX-Injected: true", "type": "crlf"},
    {"name": "crlf_ws", "payload": "test\n\nNext message content", "type": "crlf"},
    # Path Traversal
    {"name": "path_traversal", "payload": "../../../etc/passwd", "type": "path"},
    {"name": "path_encoded", "payload": "..%2F..%2F..%2Fetc%2Fpasswd", "type": "path"},
    # Prototype Pollution (JSON)
    {"name": "proto_pollution", "payload": '{"__proto__": {"admin": true}}', "type": "proto"},
    {"name": "constructor_pollution", "payload": '{"constructor": {"prototype": {"admin": true}}}', "type": "proto"},
    # LDAP Injection
    {"name": "ldap_wildcard", "payload": "*", "type": "ldap"},
    {"name": "ldap_admin", "payload": "admin(|(uid=*))", "type": "ldap"},
    # XXE
    {"name": "xxe_basic", "payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "type": "xxe"},
    # Template Injection
    {"name": "ssti_basic", "payload": "{{7*7}}", "type": "ssti"},
    {"name": "ssti_math", "payload": "${7*7}", "type": "ssti"},
]


@dataclass
class WebSocketFinding:
    """WebSocket security finding."""

    test_name: str
    finding_type: str
    severity: str
    description: str
    evidence: str = ""
    affected_endpoints: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class WebSocketResult:
    """Complete WebSocket scan result."""

    target: str
    findings: list[WebSocketFinding] = field(default_factory=list)
    endpoints_discovered: int = 0
    insecure_ws_enabled: bool = False
    origin_bypass_possible: bool = False
    auth_bypass_possible: bool = False
    dos_vulnerable: bool = False
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class WebSocketScanner:
    """Advanced WebSocket security scanner with 2026 techniques."""

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
        self.verify_ssl = verify_ssl
        self.findings: list[WebSocketFinding] = []
        self.session = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
            http2=False,
        )
        os.makedirs(output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=1, max=5))
    def _send_request(self, url: str, method: str = "GET", **kwargs) -> httpx.Response:
        """Send HTTP request with retry."""
        return self.session.request(method, url, **kwargs)

    def discover_endpoints(self) -> list[str]:
        """Discover WebSocket endpoints from target page and common patterns."""
        logger.info(f"Discovering WebSocket endpoints on {self.target}")

        endpoints: set[str] = set()

        # 1. Check page HTML/JS for WebSocket URLs
        try:
            resp = self._send_request(self.target)
            body = resp.text

            # Pattern match from JS
            for pattern in WS_JS_PATTERNS:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for m in matches:
                    if m.startswith("ws") or m.startswith("wss"):
                        endpoints.add(m)
                    elif m.startswith("/"):
                        parsed = urlparse(self.target)
                        endpoints.add(f"wss://{parsed.netloc}{m}")

            # Check Upgrade header in response
            upgrade = resp.headers.get("upgrade", "").lower()
            if "websocket" in upgrade:
                parsed = urlparse(self.target)
                ws_scheme = "wss" if parsed.scheme == "https" else "ws"
                endpoints.add(f"{ws_scheme}://{parsed.netloc}{parsed.path}")

        except Exception as e:
            logger.debug(f"Page fetch failed: {e}")

        # 2. Probe common WebSocket endpoint paths
        parsed = urlparse(self.target)
        base_ws = f"wss://{parsed.netloc}" if parsed.scheme == "https" else f"ws://{parsed.netloc}"

        for path in WS_ENDPOINT_PATTERNS:
            ws_url = f"{base_ws}{path}"
            if HAS_WEBSOCKETS:
                try:
                    conn = asyncio.run(
                        ws_connect(ws_url, timeout=self.timeout, open_timeout=5)
                    )
                    asyncio.run(conn.close())
                    endpoints.add(ws_url)
                    logger.info(f"WS endpoint confirmed: {ws_url}")
                except Exception:
                    pass

        return sorted(endpoints)

    def test_connection(self, endpoint: str) -> WebSocketFinding:
        """Test basic WebSocket connection and handshake."""
        logger.info(f"Testing connection to {endpoint}")

        if not HAS_WEBSOCKETS:
            return WebSocketFinding(
                test_name="Connection Test",
                finding_type="connection",
                severity="info",
                description="websockets library not available. Install with: pip install websockets",
            )

        try:
            start = time.time()

            async def _connect():
                async with ws_connect(endpoint, timeout=self.timeout, close_timeout=5) as ws:
                    latency = (time.time() - start) * 1000
                    resp_headers = dict(ws.response_headers) if hasattr(ws, 'response_headers') else {}
                    subprotocol = ws.subprotocol
                    return latency, resp_headers, subprotocol

            latency, headers, subprotocol = asyncio.run(_connect())

            # Check for insecure ws://
            parsed = urlparse(endpoint)
            if parsed.scheme == "ws":
                scheme = parsed.scheme
                finding = WebSocketFinding(
                    test_name="Insecure WebSocket",
                    finding_type="connection",
                    severity="high",
                    description=f"WebSocket connection over unencrypted ws://. "
                                f"Allows MITM attacks on real-time data.",
                    evidence=f"Endpoint: {endpoint} | Latency: {latency:.0f}ms",
                    affected_endpoints=[endpoint],
                    remediation="Always use wss:// for WebSocket connections.",
                )
                self.findings.append(finding)
                return finding

            return WebSocketFinding(
                test_name="Connection Test",
                finding_type="connection",
                severity="info",
                description=f"WebSocket connection successful. Latency: {latency:.0f}ms"
                            f"{f', Subprotocol: {subprotocol}' if subprotocol else ''}",
                affected_endpoints=[endpoint],
            )

        except Exception as e:
            return WebSocketFinding(
                test_name="Connection Test",
                finding_type="connection",
                severity="info",
                description=f"Connection failed: {str(e)[:100]}",
            )

    def test_origin_bypass(self, endpoint: str) -> WebSocketFinding:
        """Test for Cross-Site WebSocket Hijacking (CSWSH) via Origin bypass."""
        logger.info(f"Testing origin bypass on {endpoint}")

        if not HAS_WEBSOCKETS:
            return WebSocketFinding(
                test_name="Origin Bypass",
                finding_type="cswsh",
                severity="info",
                description="websockets library not available.",
            )

        origins_to_test = [
            ("No Origin", None),
            ("Null Origin", "null"),
            ("Evil Origin", "https://evil.com"),
            ("Attacker Origin", "https://attacker.com"),
            ("Subdomain Origin", f"https://evil.{urlparse(endpoint).netloc}"),
            ("Referer Origin", "https://evil.com/"),
        ]

        findings: list[WebSocketFinding] = []

        for origin_name, origin_value in origins_to_test:
            try:
                async def _test_origin():
                    extra_headers = {}
                    if origin_value:
                        extra_headers["Origin"] = origin_value

                    try:
                        async with ws_connect(
                            endpoint,
                            timeout=self.timeout,
                            open_timeout=5,
                            extra_headers=extra_headers,
                        ) as ws:
                            # Check if connection succeeded
                            test_msg = json.dumps({"type": "ping"})
                            await ws.send(test_msg)
                            try:
                                resp = await asyncio.wait_for(ws.recv(), timeout=3)
                                return True, str(resp)[:200]
                            except asyncio.TimeoutError:
                                return True, "Connected but no response"
                    except Exception as e:
                        return False, str(e)[:100]

                success, evidence = asyncio.run(_test_origin())

                if success:
                    finding = WebSocketFinding(
                        test_name=f"Origin Bypass ({origin_name})",
                        finding_type="cswsh",
                        severity="critical" if origin_name != "Subdomain Origin" else "high",
                        description=f"Cross-Site WebSocket Hijacking (CSWSH): Connection accepted "
                                    f"with {origin_name.lower()}.",
                        evidence=evidence,
                        affected_endpoints=[endpoint],
                        remediation="Validate Origin header against strict whitelist. Use CSRF tokens for WebSocket connections.",
                    )
                    findings.append(finding)

            except Exception as e:
                logger.debug(f"Origin test {origin_name} failed: {e}")

        if findings:
            self.findings.extend(findings)
            return findings[0]

        return WebSocketFinding(
            test_name="Origin Bypass",
            finding_type="cswsh",
            severity="info",
            description="Origin validation appears to be enforced.",
            affected_endpoints=[endpoint],
        )

    def test_injection(self, endpoint: str) -> list[WebSocketFinding]:
        """Test message injection vulnerabilities via WebSocket."""
        logger.info(f"Testing message injection on {endpoint}")

        if not HAS_WEBSOCKETS:
            return [WebSocketFinding(
                test_name="Injection Test",
                finding_type="injection",
                severity="info",
                description="websockets library not available.",
            )]

        findings: list[WebSocketFinding] = []

        for payload in INJECTION_PAYLOADS:
            try:
                async def _test_payload():
                    async with ws_connect(
                        endpoint, timeout=self.timeout, open_timeout=5
                    ) as ws:
                        await ws.send(payload["payload"])
                        try:
                            response = await asyncio.wait_for(ws.recv(), timeout=5)
                            return str(response)
                        except asyncio.TimeoutError:
                            return None

                response = asyncio.run(_test_payload())

                if response:
                    resp_lower = response.lower()

                    # Check for SQL errors
                    if payload["type"] == "sqli":
                        if any(p in resp_lower for p in ["sql", "syntax", "mysql", "postgresql",
                                                          "unclosed", "quotation", "odbc"]):
                            finding = WebSocketFinding(
                                test_name=f"Injection: {payload['name']}",
                                finding_type="sqli",
                                severity="critical",
                                description=f"SQL injection detected via WebSocket message. "
                                            f"Payload: {payload['payload']}",
                                evidence=f"Response: {response[:300]}",
                                affected_endpoints=[endpoint],
                                remediation="Use parameterized queries. Sanitize all WebSocket message inputs.",
                            )
                            findings.append(finding)
                            self.findings.append(finding)
                            continue

                    # Check for XSS reflection
                    if payload["type"] == "xss":
                        if payload["payload"] in response or "<script>" in resp_lower:
                            finding = WebSocketFinding(
                                test_name=f"Injection: {payload['name']}",
                                finding_type="xss",
                                severity="high",
                                description=f"XSS payload reflected via WebSocket. "
                                            f"Payload: {payload['payload']}",
                                evidence=f"Response: {response[:300]}",
                                affected_endpoints=[endpoint],
                                remediation="Sanitize and encode all WebSocket message outputs.",
                            )
                            findings.append(finding)
                            self.findings.append(finding)
                            continue

                    # Check for NoSQL errors
                    if payload["type"] == "nosql":
                        if any(p in resp_lower for p in ["mongo", "mongodb", "$where",
                                                          "unexpected token", "bson"]):
                            finding = WebSocketFinding(
                                test_name=f"Injection: {payload['name']}",
                                finding_type="nosqli",
                                severity="critical",
                                description=f"NoSQL injection detected via WebSocket message. "
                                            f"Payload: {payload['payload']}",
                                evidence=f"Response: {response[:300]}",
                                affected_endpoints=[endpoint],
                                remediation="Sanitize JSON inputs. Use allow-lists for query operators.",
                            )
                            findings.append(finding)
                            self.findings.append(finding)
                            continue

                    # Check for command injection
                    if payload["type"] == "cmdi":
                        if any(p in resp_lower for p in ["root:", "bin:", "nobody",
                                                          "/etc/passwd", "/bin/bash"]):
                            finding = WebSocketFinding(
                                test_name=f"Injection: {payload['name']}",
                                finding_type="cmdi",
                                severity="critical",
                                description=f"Command injection detected via WebSocket message. "
                                            f"Payload: {payload['payload']}",
                                evidence=f"Response: {response[:300]}",
                                affected_endpoints=[endpoint],
                                remediation="Never pass WebSocket message content to shell commands.",
                            )
                            findings.append(finding)
                            self.findings.append(finding)
                            continue

                    # CRLF / message smuggling
                    if payload["type"] == "crlf":
                        finding = WebSocketFinding(
                            test_name=f"Injection: {payload['name']}",
                            finding_type="crlf",
                            severity="medium",
                            description=f"CRLF injection payload accepted via WebSocket. "
                                        f"May allow message smuggling.",
                            evidence=f"Payload: {payload['payload']}",
                            affected_endpoints=[endpoint],
                            remediation="Strip control characters from WebSocket messages.",
                        )
                        findings.append(finding)
                        self.findings.append(finding)

            except Exception as e:
                logger.debug(f"Injection test {payload['name']} failed: {e}")

        if not findings:
            findings.append(WebSocketFinding(
                test_name="Injection Test",
                finding_type="injection",
                severity="info",
                description="No injection vulnerabilities detected in WebSocket messages.",
            ))

        return findings

    def test_dos(self, endpoint: str) -> WebSocketFinding:
        """Test WebSocket DoS / resource exhaustion vectors."""
        logger.info(f"Testing DoS vectors on {endpoint}")

        if not HAS_WEBSOCKETS:
            return WebSocketFinding(
                test_name="DoS Test",
                finding_type="dos",
                severity="info",
                description="websockets library not available.",
            )

        vulnerable = False
        dos_details = []

        # 1. Large payload test
        try:
            async def _test_large_payload():
                async with ws_connect(
                    endpoint, timeout=self.timeout, open_timeout=5
                ) as ws:
                    large_msg = "A" * 1000000
                    await ws.send(large_msg)
                    try:
                        resp = await asyncio.wait_for(ws.recv(), timeout=10)
                        return len(str(resp))
                    except asyncio.TimeoutError:
                        return None

            resp_len = asyncio.run(_test_large_payload())
            if resp_len is not None:
                dos_details.append(f"Large message (1MB) accepted, response: {resp_len}")
                vulnerable = True
        except Exception as e:
            logger.debug(f"Large payload test: {e}")
            if "timeout" in str(e).lower():
                dos_details.append("Large message (1MB) caused delay")
                vulnerable = True

        # 2. Rapid message flood test
        try:
            async def _test_message_flood():
                async with ws_connect(
                    endpoint, timeout=self.timeout, open_timeout=5
                ) as ws:
                    start = time.time()
                    sent = 0
                    for _ in range(100):
                        try:
                            await ws.send("ping")
                            sent += 1
                        except Exception:
                            break
                    duration = time.time() - start
                    return sent, duration

            sent_msgs, duration = asyncio.run(_test_message_flood())
            rate = sent_msgs / duration
            if duration < 1.0 and sent_msgs >= 100:
                dos_details.append(f"High message rate: {rate:.0f} msg/s ({sent_msgs} in {duration:.2f}s)")
                vulnerable = True
        except Exception as e:
            logger.debug(f"Message flood test: {e}")

        # 3. Concurrent connection flood test
        try:
            async def _test_connection_flood():
                conns = []
                try:
                    for _ in range(20):
                        conn = await ws_connect(
                            endpoint, timeout=self.timeout, open_timeout=5
                        )
                        conns.append(conn)
                    return len(conns)
                finally:
                    for c in conns:
                        try:
                            await c.close()
                        except Exception:
                            pass

            accepted = asyncio.run(_test_connection_flood())
            if accepted >= 20:
                dos_details.append(f"Concurrent connections accepted: {accepted}")
                vulnerable = True
        except Exception as e:
            logger.debug(f"Connection flood test: {e}")

        if vulnerable:
            details_str = "; ".join(dos_details)
            finding = WebSocketFinding(
                test_name="DoS Vulnerabilities",
                finding_type="dos",
                severity="high",
                description=f"WebSocket endpoint shows DoS susceptibility. {details_str}",
                evidence=details_str,
                affected_endpoints=[endpoint],
                remediation="Implement rate limiting, max message size limits, and connection throttling.",
            )
            self.findings.append(finding)
            return finding

        return WebSocketFinding(
            test_name="DoS Test",
            finding_type="dos",
            severity="info",
            description="No DoS vulnerabilities detected.",
            affected_endpoints=[endpoint],
        )

    def test_auth_bypass(self, endpoint: str) -> WebSocketFinding:
        """Test for authentication bypass in WebSocket connections."""
        logger.info(f"Testing authentication bypass on {endpoint}")

        if not HAS_WEBSOCKETS:
            return WebSocketFinding(
                test_name="Auth Bypass",
                finding_type="auth",
                severity="info",
                description="websockets library not available.",
            )

        auth_tests = [
            ("No Auth", None),
            ("Empty Token", {"Authorization": ""}),
            ("Invalid Bearer", {"Authorization": "Bearer invalid_token_xyz"}),
            ("Basic Auth", {"Authorization": "Basic " + __import__("base64").b64encode(b"admin:admin").decode()}),
            ("Cookie Bypass", {"Cookie": "session=invalid"}),
        ]

        for test_name, headers_dict in auth_tests:
            try:
                async def _test_auth():
                    extra = headers_dict or {}
                    try:
                        async with ws_connect(
                            endpoint,
                            timeout=self.timeout,
                            open_timeout=5,
                            extra_headers=extra,
                        ) as ws:
                            test_msg = json.dumps({"type": "ping", "data": "test"})
                            await ws.send(test_msg)
                            try:
                                resp = await asyncio.wait_for(ws.recv(), timeout=3)
                                return True, resp
                            except asyncio.TimeoutError:
                                return True, "Connected (no response)"
                    except Exception as e:
                        return False, str(e)[:100]

                success, evidence = asyncio.run(_test_auth())

                if success:
                    finding = WebSocketFinding(
                        test_name=f"Auth Bypass ({test_name})",
                        finding_type="auth",
                        severity="critical" if test_name == "No Auth" else "high",
                        description=f"WebSocket connection accepted with {test_name.lower()}.",
                        evidence=f"Evidence: {evidence[:200]}",
                        affected_endpoints=[endpoint],
                        remediation="Enforce authentication for all WebSocket connections. Validate tokens on upgrade.",
                    )
                    self.findings.append(finding)
                    return finding

            except Exception as e:
                logger.debug(f"Auth test {test_name} failed: {e}")

        return WebSocketFinding(
            test_name="Auth Bypass",
            finding_type="auth",
            severity="info",
            description="Authentication is properly enforced.",
            affected_endpoints=[endpoint],
        )

    def test_subprotocols(self, endpoint: str) -> WebSocketFinding:
        """Test subprotocol negotiation for security issues."""
        logger.info(f"Testing subprotocol negotiation on {endpoint}")

        if not HAS_WEBSOCKETS:
            return WebSocketFinding(
                test_name="Subprotocol Test",
                finding_type="subprotocol",
                severity="info",
                description="websockets library not available.",
            )

        # Dangerous subprotocols that might indicate GraphQL subscriptions, etc.
        dangerous_subprotocols = [
            "graphql-ws", "subscriptions-transport-ws",
            "graphql-transport-ws", "stomp", "mqtt",
            "v1.subscriptions", "realtime.subscriptions",
        ]

        findings: list[WebSocketFinding] = []

        for sub in dangerous_subprotocols:
            try:
                async def _test_sub():
                    try:
                        async with ws_connect(
                            endpoint,
                            timeout=self.timeout,
                            open_timeout=5,
                            subprotocols=[sub],
                        ) as ws:
                            negotiated = ws.subprotocol
                            return negotiated == sub
                    except Exception:
                        return False

                accepted = asyncio.run(_test_sub())

                if accepted:
                    finding = WebSocketFinding(
                        test_name=f"Subprotocol: {sub}",
                        finding_type="subprotocol",
                        severity="medium",
                        description=f"Dangerous subprotocol '{sub}' accepted. "
                                    f"May expose subscription-based attacks or GraphQL-over-WS.",
                        affected_endpoints=[endpoint],
                        remediation="Restrict allowed subprotocols to a whitelist.",
                    )
                    findings.append(finding)
                    self.findings.append(finding)

            except Exception as e:
                logger.debug(f"Subprotocol test {sub} failed: {e}")

        if not findings:
            return WebSocketFinding(
                test_name="Subprotocol Test",
                finding_type="subprotocol",
                severity="info",
                description="No dangerous subprotocols accepted.",
                affected_endpoints=[endpoint],
            )

        return findings[0]

    def test_message_tampering(self, endpoint: str) -> list[WebSocketFinding]:
        """Test message tampering and JSON parameter pollution."""
        logger.info(f"Testing message tampering on {endpoint}")

        if not HAS_WEBSOCKETS:
            return [WebSocketFinding(
                test_name="Message Tampering",
                finding_type="tampering",
                severity="info",
                description="websockets library not available.",
            )]

        tamper_tests = [
            # JSON parameter pollution
            {"name": "json_dup_keys", "msg": '{"user": "admin", "user": "victim"}',
             "desc": "Duplicate JSON keys accepted"},
            # Binary message
            {"name": "binary_message", "msg": b"\x00\x01\x02\xff\xfe\xfd",
             "desc": "Binary messages accepted"},
            # Extremely nested JSON
            {"name": "deeply_nested", "msg": '{"a": {"b": {"c": {"d": {"e": "f"}}}}}' * 100,
             "desc": "Deeply nested JSON accepted"},
            # UTF-16 / Unicode edge cases
            {"name": "unicode_lt", "msg": '<script>alert(1)</script>',
             "desc": "Unicode message reflected"},
            # Empty message
            {"name": "empty_message", "msg": "",
             "desc": "Empty message accepted"},
            # Very long key
            {"name": "long_key", "msg": '{"' + 'A' * 10000 + '": "test"}',
             "desc": "Very long JSON key accepted"},
        ]

        findings: list[WebSocketFinding] = []

        for test in tamper_tests:
            try:
                async def _test_tamper():
                    async with ws_connect(
                        endpoint, timeout=self.timeout, open_timeout=5
                    ) as ws:
                        msg = test["msg"]
                        if isinstance(msg, bytes):
                            await ws.send(msg)
                        else:
                            await ws.send(msg)
                        try:
                            resp = await asyncio.wait_for(ws.recv(), timeout=5)
                            return True, str(resp)[:200]
                        except asyncio.TimeoutError:
                            return True, "No response"

                success, evidence = asyncio.run(_test_tamper())

                if success:
                    finding = WebSocketFinding(
                        test_name=f"Message Tampering: {test['name']}",
                        finding_type="tampering",
                        severity="low" if test["name"] in ["empty_message", "unicode_lt"] else "medium",
                        description=f"{test['desc']}.",
                        evidence=evidence,
                        affected_endpoints=[endpoint],
                        remediation="Validate and sanitize all WebSocket messages. Implement message schema validation.",
                    )
                    findings.append(finding)
                    self.findings.append(finding)

            except Exception as e:
                logger.debug(f"Tamper test {test['name']} failed: {e}")

        if not findings:
            findings.append(WebSocketFinding(
                test_name="Message Tampering",
                finding_type="tampering",
                severity="info",
                description="No message tampering vulnerabilities detected.",
            ))

        return findings

    def run_full_scan(self) -> WebSocketResult:
        """Run full WebSocket security scan."""
        start_time = time.time()

        logger.info(f"Running full WebSocket scan on {self.target}")

        result = WebSocketResult(target=self.target)

        if not HAS_WEBSOCKETS:
            result.errors.append("websockets library not installed.")
            result.scan_duration = time.time() - start_time
            return result

        # 1. Discover endpoints
        endpoints = self.discover_endpoints()
        result.endpoints_discovered = len(endpoints)

        if not endpoints:
            result.errors.append("No WebSocket endpoints discovered.")
            result.scan_duration = time.time() - start_time
            return result

        # Run tests against first valid endpoint
        primary_endpoint = endpoints[0]

        # 2. Test connection
        conn_finding = self.test_connection(primary_endpoint)
        result.insecure_ws_enabled = conn_finding.severity == "high"

        # 3. Test origin bypass (CSWSH)
        origin_finding = self.test_origin_bypass(primary_endpoint)
        result.origin_bypass_possible = origin_finding.severity in ["high", "critical"]

        # 4. Test authentication bypass
        auth_finding = self.test_auth_bypass(primary_endpoint)
        result.auth_bypass_possible = auth_finding.severity in ["high", "critical"]

        # 5. Test message injection
        injection_findings = self.test_injection(primary_endpoint)

        # 6. Test DoS
        dos_finding = self.test_dos(primary_endpoint)
        result.dos_vulnerable = dos_finding.severity in ["high", "critical"]

        # 7. Test subprotocols
        self.test_subprotocols(primary_endpoint)

        # 8. Test message tampering
        self.test_message_tampering(primary_endpoint)

        # Also test all discovered endpoints briefly
        for ep in endpoints[1:]:
            self.test_connection(ep)
            self.test_origin_bypass(ep)
            self.test_auth_bypass(ep)

        # Compile results
        result.findings = self.findings
        result.scan_duration = time.time() - start_time

        # Save results
        self._save_results(result)

        return result

    def _save_results(self, result: WebSocketResult):
        """Save scan results."""
        output_file = Path(self.output_dir) / "websocket_scan.json"

        with open(output_file, "w") as f:
            json.dump(
                {
                    "target": result.target,
                    "endpoints_discovered": result.endpoints_discovered,
                    "insecure_ws_enabled": result.insecure_ws_enabled,
                    "origin_bypass_possible": result.origin_bypass_possible,
                    "auth_bypass_possible": result.auth_bypass_possible,
                    "dos_vulnerable": result.dos_vulnerable,
                    "scan_duration": result.scan_duration,
                    "findings": [
                        {
                            "test_name": f.test_name,
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

def scan_websocket(target: str, output_dir: str = "./results") -> dict:
    """Legacy full WebSocket scan."""
    scanner = WebSocketScanner(target, output_dir)
    result = scanner.run_full_scan()
    return {
        "target": result.target,
        "endpoints_discovered": result.endpoints_discovered,
        "insecure_ws_enabled": result.insecure_ws_enabled,
        "origin_bypass_possible": result.origin_bypass_possible,
        "auth_bypass_possible": result.auth_bypass_possible,
        "dos_vulnerable": result.dos_vulnerable,
        "findings_count": len(result.findings),
    }
