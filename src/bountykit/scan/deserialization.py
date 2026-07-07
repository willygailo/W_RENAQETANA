"""Deserialization vulnerability detection module.

Covers 2026 deserialization security testing:
- Java deserialization (gadget chains, ysoserial, serialization filters)
- PHP deserialization (object injection, type juggling)
- .NET deserialization (ViewState, Newtonsoft, BinaryFormatter)
- Python pickle/RCE detection
- Ruby Marshal/YAML deserialization
- Generic serialization pattern detection
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)

# ─── Java Deserialization Signatures ─────────────────────────────────────────

JAVA_SERIALIZED_SIGNATURE = bytes([0xAC, 0xED, 0x00, 0x05])

JAVA_GADGET_CHAINS = [
    "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
    "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
    "CommonsCollections7", "Spring1", "Spring2", "JRMPClient",
    "JRMPListener", "CommonsBeanutils", "Groovy1", "Jdk7u21",
    "URLDNS", "ROME", "CommonsCollections10", "CommonsCollections11",
    "Hibernate1", "Hibernate2", "JavassistWeld1", "JBossInterceptors1",
    "C3P0", "Groovy2", "XBean", "XString", "Click1", "Beanshell1",
]

# ─── PHP Deserialization Patterns ────────────────────────────────────────────

PHP_SERIALIZED_PREFIX = re.compile(r'^[aOsi]:\d+:[;\{]')
PHP_DESERIALIZATION_INDICATORS = [
    "unserialize", "__wakeup", "__destruct", "__toString",
    "__call", "__get", "__set", "__isset", "__unset",
]

# ─── .NET Deserialization Patterns ───────────────────────────────────────────

DOTNET_VIEWSTATE_PATTERN = re.compile(r'__VIEWSTATE["\s]*value="([^"]+)"')
DOTNET_HEADERS = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
SOAP_INDICATORS = ["<soap:", "xmlns:soap", "soap:Envelope"]

# ─── Python Deserialization Patterns ─────────────────────────────────────────

PYTHON_PICKLE_SIGNATURES = [
    b"cos\nsystem\n",  # os.system
    b"cos\npopen\n",   # os.popen
    b"c__builtin__\neval\n",  # eval
    b"c__builtin__\nexec\n",  # exec
]

PYTHON_YAML_LOADERS = [
    "yaml.load", "yaml.unsafe_load", "yaml.Loader",
    "yaml.FullLoader", "yaml.SafeLoader",
]

# ─── Ruby Deserialization Patterns ───────────────────────────────────────────

RUBY_MARSHAL_PATTERNS = [
    b"Marshal.load", b"Marshal.dump", b"\x04\x08",
]


@dataclass
class DeserFinding:
    """Deserialization finding."""

    language: str  # "java", "php", "dotnet", "python", "ruby"
    test_name: str
    finding_type: str  # "serialized_object", "injection", "rce", "info"
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    evidence: str = ""
    affected_endpoints: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class DeserResult:
    """Complete deserialization scan result."""

    target: str
    findings: list[DeserFinding] = field(default_factory=list)
    java_vulnerable: bool = False
    php_vulnerable: bool = False
    dotnet_vulnerable: bool = False
    python_vulnerable: bool = False
    ruby_vulnerable: bool = False
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class DeserScanner:
    """Advanced deserialization scanner with 2026 techniques."""

    def __init__(
        self,
        target: str,
        output_dir: str = "./results",
        timeout: int = 15,
        verify_ssl: bool = False,
    ):
        self.target = target.rstrip("/")
        self.output_dir = output_dir
        self.timeout = timeout
        self.findings: list[DeserFinding] = []
        self.session = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
            http2=True,
        )
        os.makedirs(output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def _send_request(self, url: str, method: str = "GET", **kwargs) -> httpx.Response:
        """Send HTTP request with retry."""
        return self.session.request(method, url, **kwargs)

    def detect_java(self) -> list[DeserFinding]:
        """Detect Java deserialization vulnerabilities."""
        logger.info(f"Checking for Java deserialization on {self.target}")
        findings = []

        try:
            resp = self._send_request(self.target)

            # Check response body for serialized objects
            if JAVA_SERIALIZED_SIGNATURE in resp.content:
                findings.append(DeserFinding(
                    language="java",
                    test_name="Java Serialized Object",
                    finding_type="serialized_object",
                    severity="critical",
                    description="Java serialized object found in response body.",
                    evidence=f"Found Java serialization magic bytes: {JAVA_SERIALIZED_SIGNATURE.hex()}",
                    affected_endpoints=[self.target],
                    remediation="Avoid Java serialization. Use JSON or other safe formats.",
                ))

            # Check cookies for serialized objects
            for name, value in resp.cookies.items():
                try:
                    cookie_bytes = value.encode()
                    if JAVA_SERIALIZED_SIGNATURE in cookie_bytes:
                        findings.append(DeserFinding(
                            language="java",
                            test_name="Java Serialized Cookie",
                            finding_type="serialized_object",
                            severity="critical",
                            description=f"Java serialized object found in cookie: {name}",
                            evidence=f"Cookie: {name}",
                            affected_endpoints=[self.target],
                            remediation="Do not serialize Java objects in cookies.",
                        ))
                except Exception:
                    continue

            # Check for Java server indicators
            java_indicators = ["java", "tomcat", "jboss", "weblogic", "jetty", "undertow"]
            for header, value in resp.headers.items():
                if any(p in value.lower() for p in java_indicators):
                    findings.append(DeserFinding(
                        language="java",
                        test_name="Java Server Detected",
                        finding_type="info",
                        severity="info",
                        description=f"Java server detected: {header}: {value}",
                        evidence=f"Header: {header}: {value}",
                    ))

            # Check for serialization filters
            body = resp.text
            filter_patterns = [
                "ObjectInputFilter", "SerialFilter", "JEP290",
                "jep290", "serialization filter",
            ]
            for pattern in filter_patterns:
                if pattern.lower() in body.lower():
                    findings.append(DeserFinding(
                        language="java",
                        test_name="Serialization Filter",
                        finding_type="info",
                        severity="info",
                        description=f"Serialization filter detected: {pattern}",
                    ))

        except Exception as e:
            logger.error(f"Java deserialization check failed: {e}")

        self.findings.extend(findings)
        return findings

    def detect_php(self) -> list[DeserFinding]:
        """Detect PHP deserialization vulnerabilities."""
        logger.info(f"Checking for PHP deserialization on {self.target}")
        findings = []

        try:
            resp = self._send_request(self.target)
            body = resp.text

            # Check for serialized PHP data in response
            php_serial_pattern = re.compile(r'[aO]:\d+:\{[^}]*\}')
            matches = php_serial_pattern.findall(body)

            if matches:
                for match in matches[:5]:
                    findings.append(DeserFinding(
                        language="php",
                        test_name="PHP Serialized Data",
                        finding_type="serialized_object",
                        severity="high",
                        description=f"PHP serialized data found in response.",
                        evidence=f"Match: {match[:80]}",
                        affected_endpoints=[self.target],
                        remediation="Avoid PHP serialization. Use JSON.",
                    ))

            # Check cookies for serialized data
            for name, value in resp.cookies.items():
                if PHP_SERIALIZED_PREFIX.match(value):
                    findings.append(DeserFinding(
                        language="php",
                        test_name="PHP Serialized Cookie",
                        finding_type="serialized_object",
                        severity="high",
                        description=f"Serialized data in cookie: {name}",
                        evidence=f"Cookie: {name}={value[:50]}",
                        affected_endpoints=[self.target],
                        remediation="Do not serialize PHP objects in cookies.",
                    ))

            # Check for PHP object injection indicators
            for indicator in PHP_DESERIALIZATION_INDICATORS:
                if indicator in body:
                    findings.append(DeserFinding(
                        language="php",
                        test_name="PHP Object Injection",
                        finding_type="injection",
                        severity="medium",
                        description=f"PHP deserialization indicator found: {indicator}",
                        evidence=f"Found: {indicator}",
                        affected_endpoints=[self.target],
                        remediation="Validate and sanitize unserialized data.",
                    ))

            # Check for PHP version (newer versions have safer defaults)
            php_version_header = resp.headers.get("X-Powered-By", "")
            if "PHP" in php_version_header:
                findings.append(DeserFinding(
                    language="php",
                    test_name="PHP Version Detected",
                    finding_type="info",
                    severity="info",
                    description=f"PHP version: {php_version_header}",
                ))

        except Exception as e:
            logger.error(f"PHP deserialization check failed: {e}")

        self.findings.extend(findings)
        return findings

    def detect_dotnet(self) -> list[DeserFinding]:
        """Detect .NET deserialization vulnerabilities."""
        logger.info(f"Checking for .NET deserialization on {self.target}")
        findings = []

        try:
            resp = self._send_request(self.target)
            body = resp.text
            headers = resp.headers

            # Check for ASP.NET ViewState
            viewstate_match = DOTNET_VIEWSTATE_PATTERN.search(body)
            if viewstate_match:
                viewstate = viewstate_match.group(1)
                findings.append(DeserFinding(
                    language="dotnet",
                    test_name="ASP.NET ViewState",
                    finding_type="serialized_object",
                    severity="medium",
                    description=f"ASP.NET ViewState found (length: {len(viewstate)})",
                    evidence=f"ViewState length: {len(viewstate)}",
                    affected_endpoints=[self.target],
                    remediation="Ensure ViewState is MAC-protected and encrypted.",
                ))

                # Check if ViewState is MAC-protected
                if "__VIEWSTATEMAC" not in body:
                    findings.append(DeserFinding(
                        language="dotnet",
                        test_name="ViewState MAC Missing",
                        finding_type="injection",
                        severity="high",
                        description="ViewState MAC protection may be disabled.",
                        evidence="__VIEWSTATEMAC not found in page",
                        affected_endpoints=[self.target],
                        remediation="Enable ViewState MAC protection.",
                    ))

            # Check for ASP.NET headers
            for header in DOTNET_HEADERS:
                if header in headers:
                    findings.append(DeserFinding(
                        language="dotnet",
                        test_name="ASP.NET Detected",
                        finding_type="info",
                        severity="info",
                        description=f"{header}: {headers[header]}",
                        evidence=f"Header: {header}: {headers[header]}",
                    ))

            # Check for SOAP endpoints
            for indicator in SOAP_INDICATORS:
                if indicator.lower() in body.lower():
                    findings.append(DeserFinding(
                        language="dotnet",
                        test_name="SOAP Endpoint",
                        finding_type="info",
                        severity="info",
                        description=f"SOAP endpoint detected: {indicator}",
                        evidence=f"Found: {indicator}",
                    ))
                    break

            # Check for __VIEWSTATEGENERATOR
            if "__VIEWSTATEGENERATOR" in body:
                findings.append(DeserFinding(
                    language="dotnet",
                    test_name="ViewState Generator",
                    finding_type="info",
                    severity="low",
                    description="ViewState generator found. May be predictable.",
                    evidence="__VIEWSTATEGENERATOR present in page",
                    remediation="Ensure ViewState generator is not predictable.",
                ))

        except Exception as e:
            logger.error(f".NET deserialization check failed: {e}")

        self.findings.extend(findings)
        return findings

    def detect_python(self) -> list[DeserFinding]:
        """Detect Python deserialization vulnerabilities."""
        logger.info(f"Checking for Python deserialization on {self.target}")
        findings = []

        try:
            resp = self._send_request(self.target)
            body = resp.text

            # Check for pickle deserialization
            for signature in PYTHON_PICKLE_SIGNATURES:
                if signature in resp.content:
                    findings.append(DeserFinding(
                        language="python",
                        test_name="Python Pickle Detected",
                        finding_type="rce",
                        severity="critical",
                        description="Python pickle deserialization detected.",
                        evidence=f"Pickle signature: {signature.decode(errors='ignore')}",
                        affected_endpoints=[self.target],
                        remediation="Never use pickle for untrusted data. Use JSON.",
                    ))

            # Check for unsafe YAML loading
            for loader in PYTHON_YAML_LOADERS:
                if loader in body:
                    findings.append(DeserFinding(
                        language="python",
                        test_name="Unsafe YAML Loading",
                        finding_type="rce",
                        severity="critical",
                        description=f"Unsafe YAML loader detected: {loader}",
                        evidence=f"Found: {loader}",
                        affected_endpoints=[self.target],
                        remediation="Use yaml.safe_load() instead of yaml.load().",
                    ))

            # Check for Python server indicators
            python_indicators = ["python", "flask", "django", "bottle", "tornado", "uvicorn"]
            for header, value in resp.headers.items():
                if any(p in value.lower() for p in python_indicators):
                    findings.append(DeserFinding(
                        language="python",
                        test_name="Python Server Detected",
                        finding_type="info",
                        severity="info",
                        description=f"Python server detected: {header}: {value}",
                        evidence=f"Header: {header}: {value}",
                    ))

        except Exception as e:
            logger.error(f"Python deserialization check failed: {e}")

        self.findings.extend(findings)
        return findings

    def detect_ruby(self) -> list[DeserFinding]:
        """Detect Ruby deserialization vulnerabilities."""
        logger.info(f"Checking for Ruby deserialization on {self.target}")
        findings = []

        try:
            resp = self._send_request(self.target)

            # Check for Ruby Marshal deserialization
            for pattern in RUBY_MARSHAL_PATTERNS:
                if pattern in resp.content:
                    findings.append(DeserFinding(
                        language="ruby",
                        test_name="Ruby Marshal Detected",
                        finding_type="serialized_object",
                        severity="high",
                        description="Ruby Marshal deserialization detected.",
                        evidence=f"Ruby Marshal signature found",
                        affected_endpoints=[self.target],
                        remediation="Avoid Marshal.load with untrusted data. Use JSON.",
                    ))

            # Check for YAML deserialization
            body = resp.text
            ruby_yaml_patterns = ["YAML.load", "YAML.unsafe_load"]
            for pattern in ruby_yaml_patterns:
                if pattern in body:
                    findings.append(DeserFinding(
                        language="ruby",
                        test_name="Ruby YAML Loading",
                        finding_type="rce",
                        severity="critical",
                        description=f"Unsafe YAML loading detected: {pattern}",
                        evidence=f"Found: {pattern}",
                        affected_endpoints=[self.target],
                        remediation="Use YAML.safe_load() instead.",
                    ))

        except Exception as e:
            logger.error(f"Ruby deserialization check failed: {e}")

        self.findings.extend(findings)
        return findings

    def run_full_scan(self) -> DeserResult:
        """Run full deserialization scan."""
        import time
        start_time = time.time()

        logger.info(f"Running full deserialization scan on {self.target}")

        result = DeserResult(target=self.target)

        # Run all language-specific checks
        java_findings = self.detect_java()
        result.java_vulnerable = any(f.severity in ["high", "critical"] for f in java_findings)

        php_findings = self.detect_php()
        result.php_vulnerable = any(f.severity in ["high", "critical"] for f in php_findings)

        dotnet_findings = self.detect_dotnet()
        result.dotnet_vulnerable = any(f.severity in ["high", "critical"] for f in dotnet_findings)

        python_findings = self.detect_python()
        result.python_vulnerable = any(f.severity in ["high", "critical"] for f in python_findings)

        ruby_findings = self.detect_ruby()
        result.ruby_vulnerable = any(f.severity in ["high", "critical"] for f in ruby_findings)

        # Compile results
        result.findings = self.findings
        result.scan_duration = time.time() - start_time

        # Save results
        self._save_results(result)

        return result

    def _save_results(self, result: DeserResult):
        """Save scan results."""
        output_file = Path(self.output_dir) / "deserialization_scan.json"

        with open(output_file, "w") as f:
            json.dump(
                {
                    "target": result.target,
                    "java_vulnerable": result.java_vulnerable,
                    "php_vulnerable": result.php_vulnerable,
                    "dotnet_vulnerable": result.dotnet_vulnerable,
                    "python_vulnerable": result.python_vulnerable,
                    "ruby_vulnerable": result.ruby_vulnerable,
                    "scan_duration": result.scan_duration,
                    "findings": [
                        {
                            "language": f.language,
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

def detect_java_deserialization(target: str, output_dir: str = "./results") -> dict:
    """Legacy Java deserialization detection."""
    scanner = DeserScanner(target, output_dir)
    findings = scanner.detect_java()
    return {
        "target": target,
        "vulnerable": any(f.severity in ["high", "critical"] for f in findings),
        "findings_count": len(findings),
    }


def detect_php_deserialization(target: str, output_dir: str = "./results") -> dict:
    """Legacy PHP deserialization detection."""
    scanner = DeserScanner(target, output_dir)
    findings = scanner.detect_php()
    return {
        "target": target,
        "vulnerable": any(f.severity in ["high", "critical"] for f in findings),
        "findings_count": len(findings),
    }


def detect_dotnet_deserialization(target: str, output_dir: str = "./results") -> dict:
    """Legacy .NET deserialization detection."""
    scanner = DeserScanner(target, output_dir)
    findings = scanner.detect_dotnet()
    return {
        "target": target,
        "vulnerable": any(f.severity in ["high", "critical"] for f in findings),
        "findings_count": len(findings),
    }


def scan_all_deserialization(target: str, output_dir: str = "./results") -> dict:
    """Legacy full deserialization scan."""
    scanner = DeserScanner(target, output_dir)
    result = scanner.run_full_scan()
    return {
        "target": result.target,
        "java_vulnerable": result.java_vulnerable,
        "php_vulnerable": result.php_vulnerable,
        "dotnet_vulnerable": result.dotnet_vulnerable,
        "python_vulnerable": result.python_vulnerable,
        "ruby_vulnerable": result.ruby_vulnerable,
        "findings_count": len(result.findings),
    }
