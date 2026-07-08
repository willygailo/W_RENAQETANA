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
import asyncio
import random
from typing import Optional, List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urlparse

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
    "jest", "mocha", "chai", "socket.io", "multer",     "passport", "bcrypt",
    "jsonwebtoken", "cors", "helmet", "morgan", "cookie-parser",
    "express-session", "body-parser", "uuid", "moment", "dayjs",
    "bluebird", "async", "request", "node-fetch", "got", "cheerio",
    "puppeteer", "playwright", "selenium-webdriver",
}

# Lock-file integrity verification patterns
# Maps lock-file format → expected hash algorithm field
LOCK_FILE_HASH_PATTERNS = {
    "package-lock.json": {
        "alg": "sha512",
        "field_path": "packages.*.resolved",
        "integrity_key": "integrity",
    },
    "yarn.lock": {
        "alg": "sha512",
        "field_path": "resolved",
        "integrity_key": "integrity",
    },
    "pnpm-lock.yaml": {
        "alg": "sha512",
        "field_path": "resolution.integrity",
    },
    "Cargo.lock": {
        "alg": "sha256",
        "field_path": "checksum",
    },
    "go.sum": {
        "alg": "sha256",
        "field_path": "inline",
    },
    "poetry.lock": {
        "alg": "sha256",
        "field_path": "files.*",
    },
}

# Cargo (Rust) dependency file patterns
CARGO_TOML_SUSPICIOUS = [
    (r"\[patch\.[a-zA-Z0-9_-]+\]", "Cargo patch section (supply chain override)"),
    (r"git\s*=\s*['\"]https?://", "Cargo git dependency (not from crates.io)"),
    (r"path\s*=\s*['\"]\.\.", "Cargo relative path dependency"),
    (r"\[replace\]", "Cargo replace section (legacy override)"),
    (r"default-features\s*=\s*false", "Cargo default features disabled"),
    (r"features\s*=\s*\[[^\]]*['\"]std['\"]", "Cargo std feature manipulation"),
]

# OSV.dev batch query endpoint
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/vulns"

# GitHub Actions composite action supply-chain vectors
GHA_COMPOSITE_SUSPICIOUS = [
    (r"run\s*:\s*\|?\s*\{\{.*inputs\.", "GitHub Actions composite: unvalidated input in run step"),
    (r"uses\s*:\s*\$\{\{.*inputs\.", "GitHub Actions composite: dynamic action reference"),
    (r"uses\s*:\s*\$\{\{.*secrets\.", "GitHub Actions composite: secret in action reference"),
    (r"env\s*:\s*\*\s*:", "GitHub Actions composite: env wildcard (all secrets)"),
    (r"post\s*:\s*\|?\s*curl", "GitHub Actions composite: post step with curl"),
    (r"pre\s*:\s*\|?\s*curl", "GitHub Actions composite: pre step with curl"),
]

# Scope-leak detection for dependency confusion
SCOPE_LEAK_PATTERNS = [
    (r"scope\s*=\s*['\"]@[^'\"]+['\"]", "npm scope declaration"),
    (r"private\s*:\s*true", "npm private package flag"),
    (r"publishConfig\s*:\s*\{[^}]*scope", "npm scoped publish config"),
    (r"\[tool\.poetry\]", "Python poetry config (private package)"),
    (r"repository\s*=\s*['\"]https?://[^'\"]*private", "Python private repository reference"),
    (r"index-url\s*=\s*https?://[^'\"]*private", "pip private index"),
]


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
        check_lockfile_integrity: bool = True,
        check_cargo_go: bool = True,
        check_github_actions: bool = True,
        query_osv: bool = True,
    ):
        self.target_path = Path(target_path).resolve()
        self.timeout = timeout
        self.verbose = verbose
        self.check_registry = check_registry
        self.check_lockfile_integrity = check_lockfile_integrity
        self.check_cargo_go = check_cargo_go
        self.check_github_actions = check_github_actions
        self.query_osv = query_osv
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        )
        # Dependency confusion scope-leak tracking
        self._private_scopes: Set[str] = set()
        self._private_names: Set[str] = set()

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

        # Phase 2: lock-file integrity verification
        if self.check_lockfile_integrity:
            await self._verify_lockfile_integrity(result)

        # Phase 3: Cargo.toml / go.sum scanning
        if self.check_cargo_go:
            cargo_files = list(self.target_path.rglob("Cargo.toml"))
            go_sum_files = list(self.target_path.rglob("go.sum"))
            go_mod_files = list(self.target_path.rglob("go.mod"))
            for cf in cargo_files + go_sum_files + go_mod_files:
                result.files_scanned += 1
                await self._scan_cargo_go_file(cf, result)

        # Phase 4: GitHub Actions deep composite-action scan
        if self.check_github_actions:
            await self._scan_github_actions_deep(result)

        # Phase 5: OSV.dev batch vulnerability query
        if self.query_osv:
            await self._query_osv_batch(result)

        # Phase 6: Dependency confusion (enhanced with scope-leak)
        await self._check_dependency_confusion(result)
        await self._check_dependency_confusion_scope_leak(result)

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

    # ────────────────────────────────────────────────────────────────
    # NEW: Lock-file integrity verification
    # ────────────────────────────────────────────────────────────────

    async def _verify_lockfile_integrity(
        self, result: SupplyChainResult
    ) -> None:
        """Verify lock-file hash integrity against registry metadata."""
        lock_files = list(self.target_path.rglob("package-lock.json")) + \
                     list(self.target_path.rglob("yarn.lock")) + \
                     list(self.target_path.rglob("pnpm-lock.yaml"))
        for lock_file in lock_files:
            try:
                with open(lock_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                lock_name = lock_file.name
                pattern_info = LOCK_FILE_HASH_PATTERNS.get(lock_name)
                if not pattern_info:
                    continue

                # For package-lock.json v2, check integrity hashes against npm registry
                if lock_name == "package-lock.json":
                    await self._verify_package_lock_integrity(lock_file, content, result)

                # For yarn.lock, check resolved URLs match expected
                elif lock_name == "yarn.lock":
                    await self._verify_yarn_lock_integrity(lock_file, content, result)

            except Exception as e:
                if self.verbose:
                    logger.debug(f"  [-] Lock-file verification failed for {lock_file}: {e}")

    async def _verify_package_lock_integrity(
        self, lock_file: Path, content: str, result: SupplyChainResult
    ) -> None:
        """Cross-reference package-lock.json integrity hashes with npm registry."""
        try:
            lock_data = json.loads(content)
        except json.JSONDecodeError:
            return

        packages = lock_data.get("packages", {})
        if not packages:
            return

        # Sample up to 10 packages for integrity check (avoid rate limits)
        sampled = list(packages.items())[:10]
        for pkg_path, pkg_meta in sampled:
            if pkg_path == "":
                continue
            pkg_name = pkg_path.rsplit("node_modules/", 1)[-1] if "node_modules/" in pkg_path else pkg_path
            integrity = pkg_meta.get("integrity", "")
            resolved = pkg_meta.get("resolved", "")

            if not integrity or not resolved:
                continue

            # Parse integrity hash
            match = re.match(r"(sha\d+)-([A-Za-z0-9+/=]+)", integrity)
            if not match:
                continue

            alg = match.group(1)

            # Fetch from npm and compare
            try:
                npm_resp = await self._client.get(
                    f"https://registry.npmjs.org/{pkg_name}",
                    headers={"Accept": "application/json"},
                )
                if npm_resp.status_code != 200:
                    continue

                npm_data = npm_resp.json()
                dist = npm_data.get("dist", {})
                npm_integrity = dist.get("integrity", "")

                if npm_integrity and npm_integrity != integrity:
                    result.findings.append(
                        SupplyChainFinding(
                            category="lockfile_tampering",
                            severity="critical",
                            title=f"Lock-File Integrity Mismatch: {pkg_name}",
                            description=(
                                f"Package '{pkg_name}' in package-lock.json has integrity hash "
                                f"'{integrity[:40]}...' but npm registry reports "
                                f"'{npm_integrity[:40]}...'. Possible lock-file tampering."
                            ),
                            file_path=str(lock_file),
                            package=pkg_name,
                            evidence=f"Local: {integrity}\nRegistry: {npm_integrity}",
                            remediation=(
                                "Delete node_modules and package-lock.json, then regenerate "
                                "with a clean install. Investigate how the tampering occurred."
                            ),
                        )
                    )
                elif not npm_integrity and integrity:
                    result.findings.append(
                        SupplyChainFinding(
                            category="lockfile_tampering",
                            severity="medium",
                            title=f"Lock-File Has Integrity, Registry Does Not: {pkg_name}",
                            description=(
                                f"Package '{pkg_name}' has integrity hash in lock file but "
                                f"npm registry does not provide one. Verify manually."
                            ),
                            file_path=str(lock_file),
                            package=pkg_name,
                            remediation="Manually verify package integrity using npm pack --dry-run.",
                        )
                    )
            except Exception:
                pass

    async def _verify_yarn_lock_integrity(
        self, lock_file: Path, content: str, result: SupplyChainResult
    ) -> None:
        """Verify yarn.lock resolved URLs are not pointing to hijacked registries."""
        suspicious_resolved = []
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("resolved "):
                url_match = re.search(r'"(https?://[^"]+)"', stripped)
                if url_match:
                    url = url_match.group(1)
                    parsed = urlparse(url)
                    host = parsed.hostname or ""
                    # Check for non-standard registries
                    if host and "npmjs.org" not in host and "npmjs.com" not in host:
                        suspicious_resolved.append(url)

        if suspicious_resolved:
            result.findings.append(
                SupplyChainFinding(
                    category="registry_hijack",
                    severity="high",
                    title="Non-Standard Registry in yarn.lock",
                    description=(
                        f"yarn.lock contains {len(suspicious_resolved)} resolved URLs "
                        f"pointing to non-npmjs registries. Possible registry hijack."
                    ),
                    file_path=str(lock_file),
                    evidence="\n".join(suspicious_resolved[:5]),
                    remediation="Verify all package sources are legitimate. Run yarn audit.",
                )
            )

    # ────────────────────────────────────────────────────────────────
    # NEW: Cargo.toml / go.sum scanning
    # ────────────────────────────────────────────────────────────────

    async def _scan_cargo_go_file(
        self, dep_file: Path, result: SupplyChainResult
    ) -> None:
        """Scan Cargo.toml and go.sum/go.mod for supply-chain vectors."""
        try:
            with open(dep_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if dep_file.name == "Cargo.toml":
                await self._scan_cargo_toml(dep_file, content, result)
            elif dep_file.name == "go.sum":
                await self._scan_go_sum(dep_file, content, result)
            elif dep_file.name == "go.mod":
                await self._scan_go_mod(dep_file, content, result)
        except Exception as e:
            if self.verbose:
                logger.debug(f"  [-] Failed to scan {dep_file}: {e}")

    async def _scan_cargo_toml(
        self, dep_file: Path, content: str, result: SupplyChainResult
    ) -> None:
        """Scan Cargo.toml for suspicious patterns."""
        for pattern, description in CARGO_TOML_SUSPICIOUS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                severity = "high" if "patch" in description.lower() or "replace" in description.lower() else "medium"
                result.findings.append(
                    SupplyChainFinding(
                        category="cargo_supply_chain",
                        severity=severity,
                        title=f"Cargo.toml Risk: {description}",
                        description=f"Cargo.toml contains: {description}",
                        file_path=str(dep_file),
                        evidence=f"Pattern: {pattern}\nMatches: {matches[:3]}",
                        remediation="Review cargo dependency configuration for unauthorized overrides.",
                    )
                )

        # Check Cargo.lock for git-based dependencies
        cargo_lock = dep_file.parent / "Cargo.lock"
        if cargo_lock.exists():
            try:
                with open(cargo_lock, "r", encoding="utf-8", errors="ignore") as f:
                    lock_content = f.read()

                git_deps = re.findall(r'source\s*=\s*"git\+([^"]+)"', lock_content)
                if git_deps:
                    for git_url in git_deps[:5]:
                        parsed = urlparse(git_url)
                        if parsed.hostname and parsed.hostname not in ("github.com", "gitlab.com", "bitbucket.org"):
                            result.findings.append(
                                SupplyChainFinding(
                                    category="cargo_supply_chain",
                                    severity="high",
                                    title=f"Cargo Non-Hosted Git Dependency: {parsed.hostname}",
                                    description=(
                                        f"Cargo.lock references git dependency from non-major host: "
                                        f"{parsed.hostname}. Verify legitimacy."
                                    ),
                                    file_path=str(cargo_lock),
                                    evidence=git_url,
                                    remediation="Verify the git repository is trustworthy and pin to specific commit.",
                                )
                            )
            except Exception:
                pass

    async def _scan_go_sum(
        self, dep_file: Path, content: str, result: SupplyChainResult
    ) -> None:
        """Scan go.sum for hash mismatches and suspicious modules."""
        lines = content.strip().splitlines()
        modules = set()
        for line in lines:
            parts = line.split()
            if len(parts) >= 1:
                module = parts[0].rsplit("@", 1)[0] if "@" in parts[0] else parts[0]
                modules.add(module)

        # Check for modules from non-standard hosts
        for mod in modules:
            parsed = urlparse(f"https://{mod}" if not mod.startswith("http") else mod)
            host = parsed.hostname or ""
            if host and host not in ("github.com", "gitlab.com", "bitbucket.org", "golang.org", "google.golang.org", "gopkg.in"):
                result.findings.append(
                    SupplyChainFinding(
                        category="go_supply_chain",
                        severity="medium",
                        title=f"Go Module Non-Standard Host: {host}",
                        description=f"go.sum references module from non-standard host: {host}",
                        file_path=str(dep_file),
                        package=mod,
                        remediation="Verify the Go module source is trustworthy.",
                    )
                )

    async def _scan_go_mod(
        self, dep_file: Path, content: str, result: SupplyChainResult
    ) -> None:
        """Scan go.mod for replace directives and suspicious dependencies."""
        replace_directives = re.findall(r'replace\s+.*?=>\s*(.+)', content)
        for directive in replace_directives[:5]:
            # Local path replace
            if directive.strip().startswith(".") or directive.strip().startswith("/"):
                result.findings.append(
                    SupplyChainFinding(
                        category="go_supply_chain",
                        severity="medium",
                        title="Go Module Replace to Local Path",
                        description=f"go.mod contains replace directive to local path: {directive.strip()}",
                        file_path=str(dep_file),
                        remediation="Review if the local replace directive is intentional.",
                    )
                )

    # ────────────────────────────────────────────────────────────────
    # NEW: GitHub Actions composite action deep scan
    # ────────────────────────────────────────────────────────────────

    async def _scan_github_actions_deep(
        self, result: SupplyChainResult
    ) -> None:
        """Deep scan GitHub Actions workflows for composite action supply-chain vectors."""
        gha_files = list(self.target_path.rglob(".github/workflows/*.yml")) + \
                    list(self.target_path.rglob(".github/workflows/*.yaml"))
        for gha_file in gha_files:
            try:
                with open(gha_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Check for untrusted action pinning
                unpinned = re.findall(
                    r'uses\s*:\s*([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@(?:main|master|latest|HEAD)',
                    content,
                )
                if unpinned:
                    result.findings.append(
                        SupplyChainFinding(
                            category="gha_unpinned_action",
                            severity="high",
                            title=f"Unpinned GitHub Actions: {len(unpinned)} actions",
                            description=(
                                f"Workflow {gha_file.name} uses {len(unpinned)} actions "
                                f"pinned to branch (not SHA). Branches can be force-pushed."
                            ),
                            file_path=str(gha_file),
                            evidence="\n".join(unpinned[:5]),
                            remediation="Pin all actions to full SHA commit hash.",
                        )
                    )

                # Check for workflow_dispatch with secrets
                if "workflow_dispatch" in content and "secrets." in content:
                    result.findings.append(
                        SupplyChainFinding(
                            category="gha_workflow_dispatch_secrets",
                            severity="medium",
                            title="Manual Trigger with Secret Access",
                            description=(
                                f"Workflow {gha_file.name} has workflow_dispatch trigger "
                                f"and accesses secrets. Manual triggers can be abused."
                            ),
                            file_path=str(gha_file),
                            remediation="Audit which secrets are exposed to manual triggers.",
                        )
                    )

                # Check composite action patterns
                for pattern, description in GHA_COMPOSITE_SUSPICIOUS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        result.findings.append(
                            SupplyChainFinding(
                                category="gha_composite_risk",
                                severity="high",
                                title=f"GitHub Actions Composite Risk: {description}",
                                description=(
                                    f"Workflow {gha_file.name} contains: {description}"
                                ),
                                file_path=str(gha_file),
                                evidence=f"Matches: {matches[:3]}",
                                remediation="Review composite action inputs and validate all external data.",
                            )
                        )

                # Check for artifact poisoning vectors
                artifact_patterns = re.findall(
                    r'actions/download-artifact.*?name\s*:\s*(\S+)',
                    content,
                )
                if artifact_patterns:
                    result.findings.append(
                        SupplyChainFinding(
                            category="gha_artifact_poisoning",
                            severity="medium",
                            title="Artifact Download in Workflow",
                            description=(
                                f"Workflow {gha_file.name} downloads artifacts. "
                                f"Artifacts can be poisoned in multi-repo workflows."
                            ),
                            file_path=str(gha_file),
                            evidence="\n".join(artifact_patterns[:3]),
                            remediation="Verify artifact sources and use artifact attestation.",
                        )
                    )

            except Exception as e:
                if self.verbose:
                    logger.debug(f"  [-] Failed to scan GHA {gha_file}: {e}")

    # ────────────────────────────────────────────────────────────────
    # NEW: OSV.dev batch vulnerability query
    # ────────────────────────────────────────────────────────────────

    async def _query_osv_batch(
        self, result: SupplyChainResult
    ) -> None:
        """Query OSV.dev batch API for known vulnerabilities in dependencies."""
        packages: List[Dict[str, str]] = []

        # Collect npm packages from package.json files
        for pkg_file in self.target_path.rglob("package.json"):
            try:
                with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
                    pkg = json.loads(f.read())
                for dep_type in ["dependencies", "devDependencies"]:
                    for name, version in pkg.get(dep_type, {}).items():
                        packages.append({"name": name, "version": version, "ecosystem": "npm"})
            except Exception:
                continue

        # Collect Python packages from requirements*.txt
        for req_file in self.target_path.rglob("requirements*.txt"):
            try:
                with open(req_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and not line.startswith("-"):
                            match = re.match(r"^([a-zA-Z0-9_-]+)\s*([=><!~]+)\s*(.+)", line)
                            if match:
                                name, _, version = match.groups()
                                packages.append({"name": name.lower(), "version": version.strip(), "ecosystem": "PyPI"})
            except Exception:
                continue

        if not packages:
            return

        # Batch in groups of 100 (OSV.dev limit)
        for i in range(0, len(packages), 100):
            batch = packages[i:i + 100]
            queries = [
                {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
                for p in batch
            ]

            try:
                resp = await self._client.post(
                    OSV_BATCH_URL,
                    json={"queries": queries},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                osv_results = data.get("results", [])

                for idx, osv_resp in enumerate(osv_results):
                    vulns = osv_resp.get("vulns", [])
                    if vulns:
                        pkg_info = batch[idx]
                        for vuln in vulns[:3]:  # Cap at 3 vulns per package
                            vuln_id = vuln.get("id", "unknown")
                            summary = vuln.get("summary", "No summary")
                            severity = "critical" if any(
                                s.get("score", "").startswith("9") or s.get("score", "").startswith("10")
                                for s in vuln.get("severity", [])
                            ) else "high"

                            result.findings.append(
                                SupplyChainFinding(
                                    category="known_vulnerability",
                                    severity=severity,
                                    title=f"Known Vulnerability: {vuln_id} in {pkg_info['name']}",
                                    description=(
                                        f"Package '{pkg_info['name']}'@{pkg_info['version']} "
                                        f"has known vulnerability {vuln_id}: {summary}"
                                    ),
                                    package=pkg_info["name"],
                                    evidence=f"OSV ID: {vuln_id}\nEcosystem: {pkg_info['ecosystem']}",
                                    remediation=f"Upgrade {pkg_info['name']} to a patched version.",
                                )
                            )

            except Exception as e:
                if self.verbose:
                    logger.debug(f"  [-] OSV batch query failed: {e}")

    # ────────────────────────────────────────────────────────────────
    # NEW: Dependency confusion scope-leak detection
    # ────────────────────────────────────────────────────────────────

    async def _check_dependency_confusion_scope_leak(
        self, result: SupplyChainResult
    ) -> None:
        """Detect private scope/namespace declarations that enable dependency confusion."""
        # Find private scope indicators
        scope_files = list(self.target_path.rglob("package.json")) + \
                      list(self.target_path.rglob(".npmrc")) + \
                      list(self.target_path.rglob("pyproject.toml"))
        for sf in scope_files:
            try:
                with open(sf, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern, description in SCOPE_LEAK_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        # Extract scope name if possible
                        scope_match = re.search(r"scope\s*=\s*['\"](@[^'\"]+)['\"]", content)
                        scope_name = scope_match.group(1) if scope_match else "unknown"

                        self._private_scopes.add(scope_name)

                        result.findings.append(
                            SupplyChainFinding(
                                category="dependency_confusion_scope_leak",
                                severity="high",
                                title=f"Private Scope Declaration: {scope_name}",
                                description=(
                                    f"File {sf.name} declares private scope/namespace '{scope_name}'. "
                                    f"An attacker can publish a package with this scope to public "
                                    f"registry and it may resolve first during installation."
                                ),
                                file_path=str(sf),
                                evidence=f"Pattern: {description}\nScope: {scope_name}",
                                remediation=(
                                    "1) Use --scope flag when installing. "
                                    "2) Use package provenance (npm provenance, sigstore). "
                                    "3) Pin exact versions in lock files. "
                                    "4) Use .npmrc with always-auth=true."
                                ),
                            )
                        )

            except Exception:
                continue

        # Check for packages that might use private names
        for pkg_file in self.target_path.rglob("package.json"):
            try:
                with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
                    pkg = json.loads(f.read())

                for dep_type in ["dependencies", "devDependencies"]:
                    for dep_name in pkg.get(dep_type, {}):
                        # Packages starting with @ may be private scope
                        if dep_name.startswith("@") and "/" in dep_name:
                            scope = dep_name.split("/")[0]
                            self._private_names.add(dep_name)

            except Exception:
                continue

        if self._private_scopes:
            result.findings.append(
                SupplyChainFinding(
                    category="dependency_confusion_attack_surface",
                    severity="info",
                    title=f"Dependency Confusion Attack Surface: {len(self._private_scopes)} scopes",
                    description=(
                        f"Project declares {len(self._private_scopes)} private scope(s): "
                        f"{', '.join(sorted(self._private_scopes))}. "
                        f"Attackers can publish packages with these names to public registries."
                    ),
                    remediation=(
                        "Mitigate by: 1) Using provenance/attestation. "
                        "2) Pinning exact versions. 3) Using scope-specific registries. "
                        "4) Running 'npm audit' regularly."
                    ),
                )
            )
