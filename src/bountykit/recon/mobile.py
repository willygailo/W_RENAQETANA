"""Mobile application reconnaissance module.

2026 techniques:
- APK/IPA decompilation and analysis
- Flutter/React Native framework detection
- Certificate pinning detection
- Hardcoded secrets extraction (20+ patterns including AI tokens)
- API endpoint extraction from mobile apps
- Deep link and intent scheme detection
- Binary analysis for native libraries
- OAuth/JWT token extraction from storage
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MobileFinding:
    source_file: str
    finding_type: str
    detail: str
    severity: str = "info"
    evidence: str = ""


@dataclass
class MobileResult:
    target: str
    method: str = "mobile_analysis"
    findings: list = field(default_factory=list)
    permissions: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    deep_links: list = field(default_factory=list)
    framework: str = "unknown"
    certificate_pinning: bool = False
    total_findings: int = 0
    errors: list = field(default_factory=list)


class MobileAnalyzer:
    """Analyze mobile applications for security issues."""

    SECRET_PATTERNS = {
        "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "aws_secret_key": re.compile(r'(?i)aws_secret_key["\s:=]+["\']([a-zA-Z0-9/+=]{40})["\']'),
        "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "firebase_key": re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
        "firebase_url": re.compile(r'https://[a-zA-Z0-9_-]+\.firebaseio\.com'),
        "github_token": re.compile(r'ghp_[A-Za-z0-9]{36}'),
        "github_oauth": re.compile(r'gho_[A-Za-z0-9]{36}'),
        "slack_token": re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z\-]+'),
        "stripe_key": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
        "openai_key": re.compile(r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'),
        "anthropic_key": re.compile(r'sk-ant-[A-Za-z0-9\-]{20,}'),
        "huggingface_token": re.compile(r'hf_[A-Za-z0-9]{34,}'),
        "npm_token": re.compile(r'npm_[A-Za-z0-9]{36}'),
        "pypi_token": re.compile(r'pypi-[A-Za-z0-9\-]{20,}'),
        "jwt_token": re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
        "basic_auth": re.compile(r'(?i)basic\s+[A-Za-z0-9+/=]{20,}'),
        "bearer_token": re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_.]+'),
        "private_key_header": re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
        "password_literal": re.compile(r'(?i)(password|passwd|pwd)["\s:=]+["\']([^"\']{4,})["\']'),
        "api_secret": re.compile(r'(?i)(api_secret|secret_key|app_secret)["\s:=]+["\']([a-zA-Z0-9_\-]{16,})["\']'),
        "database_url": re.compile(r'(?i)(mysql|postgres|mongodb|redis)://[^\s"\']+'),
    }

    ENDPOINT_PATTERNS = [
        re.compile(r'https?://[a-zA-Z0-9._\-/]+(?:\?[a-zA-Z0-9._\-=&]+)?'),
        re.compile(r'"(/api/[a-zA-Z0-9/_\-]+)"'),
        re.compile(r'"(v[0-9]+/[a-zA-Z0-9/_\-]+)"'),
        re.compile(r'"(https?://[a-zA-Z0-9._\-/]+)"'),
    ]

    DEEP_LINK_PATTERNS = [
        re.compile(r'android:scheme="(\w+)"', re.IGNORECASE),
        re.compile(r'android:host="([^"]+)"', re.IGNORECASE),
        re.compile(r'CFBundleURLSchemes.*?(\w+)', re.IGNORECASE),
        re.compile(r'(myapp|appname)://[a-zA-Z0-9/]+', re.IGNORECASE),
        re.compile(r'(\w+)://deeplink', re.IGNORECASE),
    ]

    FRAMEWORK_SIGNATURES = {
        "Flutter": ["libflutter.so", "libapp.so", "flutter_assets", "libflutter_arm64"],
        "React Native": ["libreactnativejni.so", "ReactNative", "index.android.bundle", "RCTBridgeModule"],
        "Xamarin": ["libxamarin-app.so", "libmonodroid.so", "Xamarin.Forms"],
        "Ionic": ["ionic", "cordova", "capacitor"],
        "Kotlin Multiplatform": ["kotlin", "multiplatform"],
        "Jetpack Compose": ["Compose", "androidx.compose"],
        "SwiftUI": ["SwiftUI", "_TtC7SwiftUI"],
        "NativeScript": ["nativescript", "tns-core-modules"],
    }

    def __init__(self, timeout: int = 30, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def _fetch(self, url: str, client: httpx.AsyncClient) -> Optional[httpx.Response]:
        try:
            return await client.get(url, follow_redirects=True, timeout=self.timeout)
        except Exception:
            return None

    def analyze_apk(self, apk_path: str, output_dir: str = "./results") -> dict:
        """Analyze an Android APK file."""
        results = {"method": "apk_analysis", "apk_path": apk_path, "permissions": [], "activities": [], "hardcoded_secrets": []}
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Analyzing APK: {apk_path}")

        try:
            cmd = ["apktool", "d", apk_path, "-o", f"{output_dir}/apk_decoded", "-f"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                logger.info("APK decompiled successfully")
                self._scan_decompiled_apk(f"{output_dir}/apk_decoded", results)
        except FileNotFoundError:
            logger.warning("apktool not installed")
        except subprocess.TimeoutExpired:
            logger.warning("apktool timed out")

        try:
            cmd = ["aapt", "dump", "badging", apk_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "uses-permission" in line:
                        perm = line.split("'")[1] if "'" in line else ""
                        if perm:
                            results["permissions"].append(perm)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        output_file = Path(output_dir) / "apk_analysis.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        return results

    def extract_mobile_endpoints(self, apk_dir: str, output_dir: str = "./results") -> dict:
        """Extract API endpoints from decompiled mobile app."""
        results = {"method": "mobile_endpoint_extraction", "endpoints": [], "api_keys": []}
        os.makedirs(output_dir, exist_ok=True)

        apk_path = Path(apk_dir)
        if not apk_path.exists():
            logger.warning(f"Decompiled directory not found: {apk_dir}")
            return results

        logger.info(f"Extracting endpoints from decompiled app")

        api_key_patterns = [
            re.compile(r'api[_\-]?key["\s:=]+["\']([a-zA-Z0-9_\-]{16,})["\']'),
            re.compile(r'AKIA[0-9A-Z]{16}'),
            re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        ]

        for ext in ["*.smali", "*.xml", "*.java", "*.kt"]:
            for file in apk_path.rglob(ext):
                try:
                    content = file.read_text(errors="ignore")
                    for pattern in self.ENDPOINT_PATTERNS:
                        for match in pattern.findall(content):
                            if len(match) > 5:
                                results["endpoints"].append({
                                    "endpoint": match,
                                    "file": str(file.relative_to(apk_path)),
                                })
                    for pattern in api_key_patterns:
                        for match in pattern.findall(content):
                            if isinstance(match, str) and len(match) >= 16:
                                results["api_keys"].append({
                                    "key": match[:20] + "...",
                                    "file": str(file.relative_to(apk_path)),
                                })
                except Exception:
                    continue

        seen = set()
        unique = []
        for e in results["endpoints"]:
            if e["endpoint"] not in seen:
                seen.add(e["endpoint"])
                unique.append(e)
        results["endpoints"] = unique

        logger.info(f"Found {len(results['endpoints'])} endpoints, {len(results['api_keys'])} API keys")
        output_file = Path(output_dir) / "mobile_endpoints.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        return results

    def detect_framework(self, apk_dir: str) -> str:
        """Detect mobile framework from decompiled files."""
        apk_path = Path(apk_dir)
        if not apk_path.exists():
            return "unknown"

        for framework, signatures in self.FRAMEWORK_SIGNATURES.items():
            for sig in signatures:
                if any(p.name == sig or sig in str(p) for p in apk_path.rglob("*") if p.is_file()):
                    return framework

            for ext in ["*.so", "*.jar", "*.js", "*.xml"]:
                for f in apk_path.rglob(ext):
                    try:
                        content = f.read_text(errors="ignore")[:10000]
                        if any(s.lower() in content.lower() for s in signatures):
                            return framework
                    except Exception:
                        continue
        return "unknown"

    def detect_certificate_pinning(self, apk_dir: str) -> bool:
        """Detect if certificate pinning is implemented."""
        apk_path = Path(apk_dir)
        if not apk_path.exists():
            return False

        pinning_indicators = [
            "CertificatePinner", "TrustManager", "checkServerTrusted",
            "X509TrustManager", "SSLSocketFactory", "PinningTrustManager",
            "network_security_config", "pin-set", "SHA256",
        ]

        for ext in ["*.smali", "*.java", "*.kt", "*.xml"]:
            for f in apk_path.rglob(ext):
                try:
                    content = f.read_text(errors="ignore")
                    if any(ind in content for ind in pinning_indicators):
                        return True
                except Exception:
                    continue
        return False

    def _scan_decompiled_apk(self, apk_dir: str, results: dict):
        """Scan decompiled APK for hardcoded secrets."""
        apk_path = Path(apk_dir)
        for ext in ["*.smali", "*.xml", "*.java", "*.kt", "*.json", "*.properties"]:
            for file in apk_path.rglob(ext):
                try:
                    content = file.read_text(errors="ignore")
                    for secret_type, pattern in self.SECRET_PATTERNS.items():
                        for match in pattern.finditer(content):
                            val = match.group(1) if match.lastindex else match.group(0)
                            if len(val) >= 8:
                                results["hardcoded_secrets"].append({
                                    "type": secret_type,
                                    "value": val[:40] + "..." if len(val) > 40 else val,
                                    "file": str(file.relative_to(apk_path)),
                                })
                except Exception:
                    continue

    async def run_full_scan(self, apk_path: str = None, apk_dir: str = None, output_dir: str = "./results") -> MobileResult:
        """Run full mobile analysis pipeline."""
        result = MobileResult(target=apk_path or apk_dir or "unknown")
        os.makedirs(output_dir, exist_ok=True)

        logger.info(f"Running mobile analysis")

        if apk_path and os.path.isfile(apk_path):
            self.analyze_apk(apk_path, output_dir)
            apk_dir = f"{output_dir}/apk_decoded"

        if apk_dir:
            # Framework detection
            result.framework = self.detect_framework(apk_dir)
            logger.info(f"Detected framework: {result.framework}")

            # Certificate pinning
            result.certificate_pinning = self.detect_certificate_pinning(apk_dir)
            if result.certificate_pinning:
                result.findings.append(MobileFinding(
                    source_file=apk_dir, finding_type="certificate_pinning",
                    detail="Certificate pinning detected",
                    severity="info"
                ))

            # Endpoints and secrets
            ep = self.extract_mobile_endpoints(apk_dir, output_dir)
            result.endpoints = ep.get("endpoints", [])
            result.secrets = ep.get("api_keys", [])

            # Deep link extraction
            apk_path_obj = Path(apk_dir)
            for ext in ["*.xml", "*.smali", "*.java", "*.kt"]:
                for f in apk_path_obj.rglob(ext):
                    try:
                        content = f.read_text(errors="ignore")
                        for pattern in self.DEEP_LINK_PATTERNS:
                            for match in pattern.finditer(content):
                                result.deep_links.append({
                                    "link": match.group(0) if not match.lastindex else match.group(1),
                                    "file": str(f.relative_to(apk_path_obj)),
                                })
                    except Exception:
                        continue

            # Classify secrets by severity
            for secret in result.secrets:
                result.findings.append(MobileFinding(
                    source_file=secret.get("file", ""),
                    finding_type="hardcoded_secret",
                    detail=f"API key found: {secret.get('key', '')[:20]}",
                    severity="high",
                    evidence=f"Type: {secret.get('key', '')}"
                ))

            for link in result.deep_links:
                result.findings.append(MobileFinding(
                    source_file=link.get("file", ""),
                    finding_type="deep_link",
                    detail=f"Deep link: {link.get('link', '')}",
                    severity="low"
                ))

        result.total_findings = len(result.findings)

        output_file = Path(output_dir) / "mobile_analysis.json"
        with open(output_file, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)

        logger.info(f"Found {result.total_findings} findings, framework: {result.framework}")
        return result


def analyze_apk(apk_path: str, output_dir: str = "./results") -> dict:
    analyzer = MobileAnalyzer()
    return analyzer.analyze_apk(apk_path, output_dir)


def extract_mobile_endpoints(apk_dir: str, output_dir: str = "./results") -> dict:
    analyzer = MobileAnalyzer()
    return analyzer.extract_mobile_endpoints(apk_dir, output_dir)
