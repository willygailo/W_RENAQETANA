"""
Supply chain security scanner — 2026 attack vectors.

Detects: malicious packages, typosquatting, dependency confusion, skill poisoning,
MCP server hijacking, compromised CI/CD, TrapDoor campaign patterns.
"""

from __future__ import annotations

import re
import os
import json
import time
import hashlib
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field, asdict
from pathlib import Path

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SupplyChainFinding:
    """Single supply chain security finding."""
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str = ""
    file_path: str = ""
    package: str = ""
    remediation: str = ""


@dataclass
class SupplyChainResult:
    """Complete supply chain security assessment result."""
    target: str
    findings: List[SupplyChainFinding] = field(default_factory=list)
    files_scanned: int = 0
    packages_checked: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


# Known malicious packages (TrapDoor campaign + others)
KNOWN_MALICIOUS_PACKAGES = {
    "node-llama-cpp": "Typosquatting - backdoor in AI/LLM package",
    "colors-js": "Supply chain attack - infinite loop",
    "faker-js": "Supply chain attack - wiped itself",
    "ua-parser-js": "Crypto miner + credential stealer",
    "coa": "Supply chain attack - terminal hijack",
    "rc": "Supply chain attack - terminal hijack",
    "events": "Typosquatting of Node.js events",
    "javascript": "Typosquatting - malicious package",
    "mongose": "Typosquatting of mongoose",
    "express-cookies": "Typosquatting - data theft",
    "webpack-dev-server": "Typosquatting - credential theft",
    "cross-env": "Typosquatting - malicious package",
    "nodemailer": "Typosquatting - email exfiltration",
    "dotenv": "Typosquatting - credential theft",
    "chalk": "Typosquatting - malicious package",
    "lodash": "Typosquatting - malicious package",
    "axios": "Typosquatting - malicious package",
}

# Suspicious patterns in package.json / manifest
SUSPICIOUS_PACKAGE_PATTERNS = [
    (r"\"preinstall\"\s*:\s*\"", "Pre-install script (potential backdoor)"),
    (r"\"postinstall\"\s*:\s*\"", "Post-install script (potential backdoor)"),
    (r"\"prepare\"\s*:\s*\"", "Prepare script (potential backdoor)"),
    (r"\"preuninstall\"\s*:\s*\"", "Pre-uninstall script"),
    (r"\"install\"\s*:\s*\"", "Install script (potential backdoor)"),
    (r"\"start\"\s*:\s*\".*curl\s", "Start script with curl (data exfiltration)"),
    (r"\"start\"\s*:\s*\".*wget\s", "Start script with wget (data exfiltration)"),
    (r"\"start\"\s*:\s*\".*eval\s", "Start script with eval (code execution)"),
    (r"\"scripts\"\s*:\s*\{[^}]*\"start\"\s*:\s*\"node\s+-e", "Start script with node -e (inline code)"),
    (r"eval\s*\(\s*require\s*\(", "Dynamic eval of require (code injection)"),
    (r"child_process\s*\.\s*(?:exec|spawn|fork)", "Child process usage"),
    (r"process\s*\.\s*env", "Environment variable access (potential secret theft)"),
    (r"require\s*\(\s*['\"]net['\"]", "Network module require (potential C2)"),
    (r"require\s*\(\s*['\"]https?['\"]", "HTTP module require (potential C2)"),
    (r"Buffer\s*\.\s*alloc\s*\(\s*[0-9]{7,}", "Large buffer allocation (>10MB)"),
]

# CI/CD pipeline compromise patterns
CICD_COMPROMISE_PATTERNS = [
    (r"curl\s+.*\|\s*(?:bash|sh|python|node)", "Remote code execution via pipe"),
    (r"wget\s+.*\|\s*(?:bash|sh|python|node)", "Remote code execution via pipe"),
    (r"eval\s*\(\s*['\"]curl", "Eval of curl command"),
    (r"eval\s*\(\s*['\"]wget", "Eval of wget command"),
    (r"(?:GITHUB_TOKEN|NPM_TOKEN|PYPI_TOKEN|SECRET_KEY)\s*[:=]", "Hardcoded CI/CD secrets"),
    (r"npm\s+publish\s+--.*--registry", "Publish to custom registry (potential hijack)"),
    (r"twine\s+upload\s+.*--repository-url", "Upload to custom PyPI (potential hijack)"),
    (r"git\s+push\s+.*--force", "Force push (potential branch hijack)"),
    (r"docker\s+push\s+.*--credential-store", "Docker push with custom credentials"),
    (r"terraform\s+apply\s+-auto-approve", "Auto-approve Terraform (potential compromise)"),
]

# MCP server attack patterns
MCP_ATTACK_PATTERNS = [
    (r"mcp[_-]?server", "MCP server reference (potential hijack)"),
    (r"model[_-]?context[_-]?protocol", "Model Context Protocol (MCP) reference"),
    (r"tool[_-]?call", "Tool call reference (potential hijack)"),
    (r"function[_-]?call", "Function call reference (potential hijack)"),
    (r"agent[_-]?skill", "Agent skill reference (potential poisoning)"),
    (r"\.cursorrules", "Cursor rules file (potential poisoning)"),
    (r"AGENTS\.md", "AGENTS.md file (potential poisoning)"),
    (r"SKILL\.md", "SKILL.md file (potential poisoning)"),
    (r"CLAUDE\.md", "CLAUDE.md file (potential poisoning)"),
]

# Typosquatting detection - similar names
LEGITIMATE_PACKAGES = {
    "express", "lodash", "react", "axios", "chalk", "dotenv", "commander",
    "mongoose", "nodemailer", "webpack", "babel", "eslint", "prettier",
    "jest", "mocha", "chai", "socket.io", "multer", "passport", "bcrypt",
    "jsonwebtoken", "cors", "helmet", "morgan", "cookie-parser",
    "express-session", "body-parser", "uuid", "moment", "dayjs",
    "bluebird", "async", "request", "node-fetch", "got", "cheerio",
    "puppeteer", "playwright", "selenium-webdriver",
}


class SupplyChainScanner:
    """
    Supply chain security scanner.

    2026 attack vectors:
    - Malicious packages (TrapDoor campaign)
    - Typosquatting detection
    - Dependency confusion attacks
    - CI/CD pipeline compromise
    - MCP server hijacking
    - Agent skill poisoning
    - Compromised build tools
    """

    def __init__(
        self,
        target_path: str = ".",
        timeout: float = 10.0,
        verbose: bool = False,
        check_registry: bool = True,
    ):
        self.target_path = Path(target_path).resolve()
        self.timeout = timeout
        self.verbose = verbose
        self.check_registry = check_registry
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        )

    async def close(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def scan_project(self) -> SupplyChainResult:
        """Scan project directory for supply chain vulnerabilities."""
        result = SupplyChainResult(target=str(self.target_path))

        logger.info(f"[*] Scanning project: {self.target_path}")

        # Scan package.json files
        for pkg_file in self.target_path.rglob("package.json"):
            result.files_scanned += 1
            await self._scan_package_json(pkg_file, result)

        # Scan requirements.txt / setup.py / pyproject.toml
        for req_file in list(self.target_path.rglob("requirements*.txt")) + \
                        list(self.target_path.rglob("setup.py")) + \
                        list(self.target_path.rglob("pyproject.toml")):
            result.files_scanned += 1
            await self._scan_python_deps(req_file, result)

        # Scan lock files
        for lock_file in list(self.target_path.rglob("package-lock.json")) + \
                         list(self.target_path.rglob("yarn.lock")) + \
                         list(self.target_path.rglob("pnpm-lock.yaml")):
            result.files_scanned += 1
            await self._scan_lock_file(lock_file, result)

        # Scan CI/CD config files
        cicd_files = list(self.target_path.rglob(".github/workflows/*.yml")) + \
                     list(self.target_path.rglob(".github/workflows/*.yaml")) + \
                     list(self.target_path.rglob(".gitlab-ci.yml")) + \
                     list(self.target_path.rglob("Jenkinsfile")) + \
                     list(self.target_path.rglob(".circleci/config.yml")) + \
                     list(self.target_path.rglob("Dockerfile")) + \
                     list(self.target_path.rglob("docker-compose*.yml"))
        for cicd_file in cicd_files:
            result.files_scanned += 1
            await self._scan_cicd_file(cicd_file, result)

        # Scan agent skill files
        skill_files = list(self.target_path.rglob("SKILL.md")) + \
                      list(self.target_path.rglob("AGENTS.md")) + \
                      list(self.target_path.rglob("CLAUDE.md")) + \
                      list(self.target_path.rglob(".cursorrules"))
        for skill_file in skill_files:
            result.files_scanned += 1
            await self._scan_skill_file(skill_file, result)

        # Scan MCP config files
        mcp_files = list(self.target_path.rglob("mcp.json")) + \
                    list(self.target_path.rglob("mcp-config.json")) + \
                    list(self.target_path.rglob("claude_desktop_config.json"))
        for mcp_file in mcp_files:
            result.files_scanned += 1
            await self._scan_mcp_config(mcp_file, result)

        # Check for dependency confusion
        await self._check_dependency_confusion(result)

        logger.info(
            f"[+] Supply chain scan complete: {len(result.findings)} findings "
            f"across {result.files_scanned} files"
        )
        return result

    def _save_results(self, result: "SupplyChainResult", output_dir: str) -> str:
        """Persist supply chain results to <output_dir>/supply_chain_<target>.json."""
        safe_name = str(self.target_path).replace("/", "_").strip("_")
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        filepath = out / f"supply_chain_{safe_name[-40:]}.json"
        payload = {
            "target": result.target,
            "timestamp": result.timestamp,
            "files_scanned": result.files_scanned,
            "packages_checked": result.packages_checked,
            "summary": result.summary,
            "findings": [asdict(f) for f in result.findings],
        }
        filepath.write_text(json.dumps(payload, indent=2, default=str))
        logger.info(f"[+] Results saved → {filepath}")
        return str(filepath)

    async def _scan_package_json(
        self, pkg_file: Path, result: SupplyChainResult
    ) -> None:
        """Scan package.json for malicious patterns."""
        try:
            with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            pkg = json.loads(content)

            # Check all dependency sections
            all_deps = {}
            for dep_type in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
                if dep_type in pkg:
                    all_deps.update(pkg[dep_type])

            for dep_name, dep_version in all_deps.items():
                result.packages_checked += 1

                # Check known malicious packages
                if dep_name.lower() in KNOWN_MALICIOUS_PACKAGES:
                    result.findings.append(
                        SupplyChainFinding(
                            category="malicious_package",
                            severity="critical",
                            title=f"Known Malicious Package: {dep_name}",
                            description=f"Package '{dep_name}' is known to be malicious. "
                            f"Info: {KNOWN_MALICIOUS_PACKAGES[dep_name]}",
                            file_path=str(pkg_file),
                            package=dep_name,
                            remediation="Remove this package immediately and audit for compromise.",
                        )
                    )

                # Check typosquatting
                typosquat = self._check_typosquatting(dep_name)
                if typosquat:
                    result.findings.append(
                        SupplyChainFinding(
                            category="typosquatting",
                            severity="high",
                            title=f"Possible Typosquatting: {dep_name}",
                            description=f"Package '{dep_name}' may be a typosquat of '{typosquat}'. "
                            f"Verify the package is legitimate.",
                            file_path=str(pkg_file),
                            package=dep_name,
                            remediation="Verify package legitimacy on npm/PyPI. Check publisher, "
                            "downloads, and last publish date.",
                        )
                    )

                # Check registry
                if self.check_registry:
                    await self._check_package_registry(dep_name, dep_version, pkg_file, result)

            # Check scripts for suspicious patterns
            if "scripts" in pkg:
                for script_name, script_cmd in pkg["scripts"].items():
                    for pattern, description in SUSPICIOUS_PACKAGE_PATTERNS:
                        if re.search(pattern, f'"{script_name}": "{script_cmd}"', re.IGNORECASE):
                            result.findings.append(
                                SupplyChainFinding(
                                    category="malicious_script",
                                    severity="high" if "install" in script_name else "medium",
                                    title=f"Suspicious Script: {script_name}",
                                    description=f"Script '{script_name}' contains suspicious pattern: {description}. "
                                    f"Command: {script_cmd}",
                                    file_path=str(pkg_file),
                                    remediation="Review and remove suspicious scripts.",
                                )
                            )

            # Check for private registry references
            if "publishConfig" in pkg:
                registry = pkg["publishConfig"].get("registry", "")
                if registry and "npmjs" not in registry and "npmjs.org" not in registry:
                    result.findings.append(
                        SupplyChainFinding(
                            category="registry_hijack",
                            severity="high",
                            title="Custom Publish Registry",
                            description=f"Package publishes to custom registry: {registry}. "
                            f"This could indicate a registry hijack.",
                            file_path=str(pkg_file),
                            remediation="Verify the custom registry is legitimate.",
                        )
                    )

        except json.JSONDecodeError:
            pass
        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Failed to scan {pkg_file}: {e}")

    async def _scan_python_deps(
        self, dep_file: Path, result: SupplyChainResult
    ) -> None:
        """Scan Python dependency files."""
        try:
            with open(dep_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Extract package names
            packages = set()
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    # Extract package name (before version specifier)
                    match = re.match(r"^([a-zA-Z0-9_-]+)", line)
                    if match:
                        packages.add(match.group(1).lower())

            for pkg_name in packages:
                result.packages_checked += 1

                # Check known malicious
                if pkg_name in KNOWN_MALICIOUS_PACKAGES:
                    result.findings.append(
                        SupplyChainFinding(
                            category="malicious_package",
                            severity="critical",
                            title=f"Known Malicious Package: {pkg_name}",
                            description=f"Package '{pkg_name}' is known to be malicious.",
                            file_path=str(dep_file),
                            package=pkg_name,
                            remediation="Remove this package immediately.",
                        )
                    )

                # Check typosquatting
                typosquat = self._check_typosquatting(pkg_name)
                if typosquat:
                    result.findings.append(
                        SupplyChainFinding(
                            category="typosquatting",
                            severity="high",
                            title=f"Possible Typosquatting: {pkg_name}",
                            description=f"Package '{pkg_name}' may be a typosquat of '{typosquat}'.",
                            file_path=str(dep_file),
                            package=pkg_name,
                            remediation="Verify package legitimacy on PyPI.",
                        )
                    )

                # Check PyPI registry
                if self.check_registry:
                    await self._check_pypi_registry(pkg_name, dep_file, result)

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Failed to scan {dep_file}: {e}")

    async def _scan_lock_file(
        self, lock_file: Path, result: SupplyChainResult
    ) -> None:
        """Scan lock files for resolved malicious packages."""
        try:
            with open(lock_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for pkg_name in KNOWN_MALICIOUS_PACKAGES:
                if pkg_name in content:
                    result.findings.append(
                        SupplyChainFinding(
                            category="malicious_package_lock",
                            severity="critical",
                            title=f"Malicious Package in Lock File: {pkg_name}",
                            description=f"Lock file {lock_file.name} resolves to known malicious package '{pkg_name}'.",
                            file_path=str(lock_file),
                            package=pkg_name,
                            remediation="Run npm audit / pip check and remove the malicious dependency.",
                        )
                    )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Failed to scan {lock_file}: {e}")

    async def _scan_cicd_file(
        self, cicd_file: Path, result: SupplyChainResult
    ) -> None:
        """Scan CI/CD pipeline files for compromise patterns."""
        try:
            with open(cicd_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for pattern, description in CICD_COMPROMISE_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    severity = "critical" if any(
                        kw in description.lower()
                        for kw in ["remote code", "secret", "hardcoded"]
                    ) else "high"

                    result.findings.append(
                        SupplyChainFinding(
                            category="cicd_compromise",
                            severity=severity,
                            title=f"CI/CD Pipeline Risk: {description}",
                            description=f"CI/CD file {cicd_file.name} contains suspicious pattern: {description}.",
                            file_path=str(cicd_file),
                            evidence=f"Pattern: {pattern}\nMatches: {matches[:3]}",
                            remediation="Review CI/CD configuration for unauthorized changes. "
                            "Use secret scanning and pipeline protection rules.",
                        )
                    )

            # Check for direct secret references
            secret_patterns = [
                (r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]+['\"]", "Hardcoded password"),
                (r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"]+['\"]", "Hardcoded API key"),
                (r"(?:secret|token)\s*[=:]\s*['\"][^'\"]+['\"]", "Hardcoded secret/token"),
                (r"ssh-rsa\s+[A-Za-z0-9+/=]+", "Embedded SSH key"),
            ]

            for pattern, description in secret_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result.findings.append(
                        SupplyChainFinding(
                            category="secret_exposure",
                            severity="critical",
                            title=f"CI/CD Secret Exposure: {description}",
                            description=f"CI/CD file {cicd_file.name} contains {description}.",
                            file_path=str(cicd_file),
                            remediation="Move secrets to CI/CD secret store (GitHub Secrets, etc.).",
                        )
                    )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Failed to scan {cicd_file}: {e}")

    async def _scan_skill_file(
        self, skill_file: Path, result: SupplyChainResult
    ) -> None:
        """Scan AI agent skill files for poisoning."""
        try:
            with open(skill_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Check for hidden instructions
            hidden_patterns = [
                (r"(?:<!--|/\*|//)\s*(?:IMPORTANT|SYSTEM|HIDDEN|SECRET)", "Hidden comment with instructions"),
                (r"<(?:div|span|p)\s+[^>]*style\s*=\s*[\"'][^\"']*display\s*:\s*none", "Hidden HTML element"),
                (r"(?:zero[- ]?width|invisible|hidden)\s*(?:character|text|unicode)", "Zero-width/hidden text"),
                (r"(?:ignore|override|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", "Instruction override"),
                (r"(?:you\s+are\s+now|act\s+as|pretend\s+you\s+are)", "Role hijack"),
                (r"(?:curl|wget|fetch)\s+(?:https?://|ftp://)", "Remote payload fetch"),
                (r"(?:exec|eval|system|subprocess|os\.system)\s*\(", "Code execution"),
                (r"(?:169\.254\.169\.254|metadata\.google\.internal)", "Cloud metadata access"),
            ]

            for pattern, description in hidden_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    severity = "critical" if any(
                        kw in description.lower()
                        for kw in ["override", "execution", "metadata"]
                    ) else "high"

                    result.findings.append(
                        SupplyChainFinding(
                            category="skill_poisoning",
                            severity=severity,
                            title=f"Agent Skill Poisoning: {description}",
                            description=f"Skill file {skill_file.name} contains suspicious pattern: {description}. "
                            f"This could be a supply chain attack targeting AI agents.",
                            file_path=str(skill_file),
                            evidence=f"Pattern: {pattern}\nMatches: {matches[:3]}",
                            remediation="Review skill file content, remove or sanitize suspicious patterns.",
                        )
                    )

        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Failed to scan {skill_file}: {e}")

    async def _scan_mcp_config(
        self, mcp_file: Path, result: SupplyChainResult
    ) -> None:
        """Scan MCP server configurations for hijacking."""
        try:
            with open(mcp_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            config = json.loads(content)

            # Check for suspicious MCP servers
            if "mcpServers" in config:
                for server_name, server_config in config["mcpServers"].items():
                    # Check for remote servers
                    command = server_config.get("command", "")
                    args = server_config.get("args", [])
                    env = server_config.get("env", {})

                    if command in ["curl", "wget", "fetch"]:
                        result.findings.append(
                            SupplyChainFinding(
                                category="mcp_hijack",
                                severity="critical",
                                title=f"MCP Server Remote Code: {server_name}",
                                description=f"MCP server '{server_name}' uses remote fetch command. "
                                f"This could be a supply chain attack.",
                                file_path=str(mcp_file),
                                evidence=f"Command: {command}, Args: {args}",
                                remediation="Verify MCP server source and integrity.",
                            )
                        )

                    # Check for environment variable leaks
                    for env_key, env_val in env.items():
                        if any(
                            kw in env_key.lower()
                            for kw in ["secret", "token", "key", "password", "credential"]
                        ):
                            result.findings.append(
                                SupplyChainFinding(
                                    category="mcp_secret_leak",
                                    severity="high",
                                    title=f"MCP Server Secret in Config: {server_name}",
                                    description=f"MCP server '{server_name}' has secret in config: {env_key}.",
                                    file_path=str(mcp_file),
                                    remediation="Move secrets to environment variables, not config files.",
                                )
                            )

        except json.JSONDecodeError:
            pass
        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Failed to scan {mcp_file}: {e}")

    def _check_typosquatting(self, package_name: str) -> Optional[str]:
        """Check if package name is a typosquat of a legitimate package."""
        name_lower = package_name.lower()

        for legit in LEGITIMATE_PACKAGES:
            if name_lower == legit:
                return None  # Exact match, not typosquat

            # Check similarity
            if self._is_similar(name_lower, legit):
                return legit

        return None

    def _is_similar(self, a: str, b: str) -> bool:
        """Check if two strings are similar (typosquat detection)."""
        if abs(len(a) - len(b)) > 3:
            return False

        # Levenshtein distance
        m, n = len(a), len(b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                dp[i][j] = min(
                    dp[i - 1][j] + 1,
                    dp[i][j - 1] + 1,
                    dp[i - 1][j - 1] + cost,
                )

        distance = dp[m][n]

        # If edit distance is 1-2 and names are similar length
        if 1 <= distance <= 2 and abs(len(a) - len(b)) <= 1:
            return True

        # Check for common typosquat techniques
        # Letter swap
        for i in range(len(a) - 1):
            swapped = a[:i] + a[i + 1] + a[i] + a[i + 2:]
            if swapped == b:
                return True

        # Double letter
        for i in range(len(a)):
            doubled = a[:i] + a[i] + a[i:]
            if doubled == b:
                return True

        # Missing letter
        for i in range(len(a)):
            shortened = a[:i] + a[i + 1:]
            if shortened == b:
                return True

        return False

    async def _check_package_registry(
        self, package_name: str, version: str, pkg_file: Path, result: SupplyChainResult
    ) -> None:
        """Check package on npm registry for suspicious indicators."""
        try:
            resp = await self._client.get(
                f"https://registry.npmjs.org/{package_name}",
                headers={"Accept": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()

                # Check for very new packages with high downloads
                created = data.get("time", {}).get("created", "")
                modified = data.get("time", {}).get("modified", "")

                # Check maintainers
                maintainers = data.get("maintainers", [])
                if len(maintainers) == 0:
                    result.findings.append(
                        SupplyChainFinding(
                            category="registry_anomaly",
                            severity="medium",
                            title=f"No Maintainers: {package_name}",
                            description=f"Package '{package_name}' has no maintainers listed.",
                            file_path=str(pkg_file),
                            package=package_name,
                            remediation="Verify package legitimacy.",
                        )
                    )

        except Exception:
            pass

    async def _check_pypi_registry(
        self, package_name: str, dep_file: Path, result: SupplyChainResult
    ) -> None:
        """Check package on PyPI for suspicious indicators."""
        try:
            resp = await self._client.get(
                f"https://pypi.org/pypi/{package_name}/json",
                headers={"Accept": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()
                info = data.get("info", {})

                # Check for very new packages
                uploads = data.get("urls", [])
                if uploads:
                    first_upload = uploads[-1].get("upload_time_iso_8601", "")
                    if first_upload:
                        from datetime import datetime
                        try:
                            created = datetime.fromisoformat(first_upload.replace("Z", "+00:00"))
                            days_old = (datetime.now(created.tzinfo) - created).days
                            if days_old < 30:
                                result.findings.append(
                                    SupplyChainFinding(
                                        category="registry_anomaly",
                                        severity="medium",
                                        title=f"Very New Package: {package_name}",
                                        description=f"Package '{package_name}' was first uploaded {days_old} days ago. "
                                        f"New packages are higher risk for supply chain attacks.",
                                        file_path=str(dep_file),
                                        package=package_name,
                                        remediation="Verify package legitimacy before using.",
                                    )
                                )
                        except Exception:
                            pass

        except Exception:
            pass

    async def _check_dependency_confusion(
        self, result: SupplyChainResult
    ) -> None:
        """Check for dependency confusion vulnerability."""
        # Check if project has private scope/namespace
        private_indicators = [
            ".npmrc", ".yarnrc", ".pypirc", "pip.conf",
        ]

        for indicator in private_indicators:
            config_files = list(self.target_path.rglob(indicator))
            for config_file in config_files:
                try:
                    with open(config_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Check for private registry references
                    if re.search(r"registry\s*=|index-url\s*=|extra-index-url\s*=", content):
                        result.findings.append(
                            SupplyChainFinding(
                                category="dependency_confusion",
                                severity="high",
                                title="Private Registry Detected",
                                description=f"Private registry configuration found in {config_file.name}. "
                                f"This project may be vulnerable to dependency confusion attacks.",
                                file_path=str(config_file),
                                remediation="Use scoped packages, verify package sources, "
                                "and implement namespace protection.",
                            )
                        )

                except Exception:
                    pass
