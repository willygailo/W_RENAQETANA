"""Patch diffing and vulnerability analysis module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 21:
- Git diff analysis for patch comparison
- Vulnerability pattern detection in diffs
- Commit analysis for security changes
- Semgrep-style static analysis patterns
- Language-specific vulnerability signatures
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from rich.console import Console

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


@dataclass
class VulnPattern:
    """Single vulnerability pattern match."""
    file: str
    line: int
    pattern_id: str
    severity: str
    category: str
    description: str
    code_snippet: str = ""
    fix_suggestion: str = ""
    cwe: str = ""


@dataclass
class DiffAnalysisResult:
    """Aggregated diff analysis result."""
    repo_path: str
    commit_range: str
    files_changed: List[str] = field(default_factory=list)
    vuln_patterns: List[VulnPattern] = field(default_factory=list)
    security_findings: List[dict] = field(default_factory=list)
    risk_score: float = 0.0


# Security-sensitive patterns in diffs
SECURITY_PATTERNS = {
    "authentication": [
        "auth", "login", "password", "credential", "token",
        "session", "cookie", "jwt", "oauth",
    ],
    "authorization": [
        "permission", "role", "access", "privilege", "admin",
        "root", "sudo", "elevated",
    ],
    "input_validation": [
        "sanitize", "escape", "validate", "filter", "whitelist",
        "blacklist", "regex", "pattern",
    ],
    "crypto": [
        "encrypt", "decrypt", "hash", "sign", "verify",
        "ssl", "tls", "certificate", "key",
    ],
    "deserialization": [
        "unserialize", "deserialize", "decode", "parse",
        "marshal", "pickle", "yaml.load",
    ],
    "command_execution": [
        "exec", "system", "popen", "subprocess", "shell",
        "eval", "assert",
    ],
    "file_operation": [
        "open", "read", "write", "delete", "upload",
        "download", "path", "directory",
    ],
    "memory_safety": [
        "buffer", "overflow", "malloc", "free", "memcpy",
        "strcpy", "strcat",
    ],
}

# Semgrep-style vulnerability patterns by language
SEMGREP_PATTERNS = {
    "python": [
        {
            "id": "python-rce-subprocess",
            "severity": "critical",
            "pattern": "subprocess.$METHOD($SHELL=True, ...)",
            "cwe": "CWE-78",
            "description": "OS command injection via subprocess with shell=True",
            "fix": "Use subprocess.run() with a list of arguments instead of shell=True",
        },
        {
            "id": "python-rce-os-system",
            "severity": "critical",
            "pattern": "os.system(...)",
            "cwe": "CWE-78",
            "description": "OS command injection via os.system()",
            "fix": "Use subprocess.run() with shell=False",
        },
        {
            "id": "python-sql-injection",
            "severity": "critical",
            "pattern": "cursor.execute(\"...\" + $VAR)",
            "cwe": "CWE-89",
            "description": "SQL injection via string concatenation",
            "fix": "Use parameterized queries: cursor.execute('SELECT ... WHERE id = ?', (id,))",
        },
        {
            "id": "python-sql-fstring",
            "severity": "critical",
            "pattern": "cursor.execute(f\"...{$VAR}...\")",
            "cwe": "CWE-89",
            "description": "SQL injection via f-string formatting",
            "fix": "Use parameterized queries instead of f-strings",
        },
        {
            "id": "python-yaml-load",
            "severity": "high",
            "pattern": "yaml.load(...)",
            "cwe": "CWE-502",
            "description": "Unsafe YAML deserialization (allows arbitrary code execution)",
            "fix": "Use yaml.safe_load() instead of yaml.load()",
        },
        {
            "id": "python-pickle-load",
            "severity": "critical",
            "pattern": "pickle.loads(...)",
            "cwe": "CWE-502",
            "description": "Unsafe pickle deserialization",
            "fix": "Avoid unpickling untrusted data; use JSON instead",
        },
        {
            "id": "python-eval",
            "severity": "critical",
            "pattern": "eval(...)",
            "cwe": "CWE-95",
            "description": "Dynamic code evaluation via eval()",
            "fix": "Avoid eval(); use ast.literal_eval() for data or safe parsers",
        },
        {
            "id": "python-exec",
            "severity": "critical",
            "pattern": "exec(...)",
            "cwe": "CWE-95",
            "description": "Dynamic code execution via exec()",
            "fix": "Avoid exec(); use importlib or function dispatch instead",
        },
        {
            "id": "python-tempfile-insecure",
            "severity": "medium",
            "pattern": "tempfile.mktemp(...)",
            "cwe": "CWE-377",
            "description": "Insecure temporary file creation (race condition)",
            "fix": "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()",
        },
        {
            "id": "python-assert-guard",
            "severity": "medium",
            "pattern": "assert $EXPR",
            "cwe": "CWE-617",
            "description": "Assertion used for access control (disabled with -O flag)",
            "fix": "Use proper if/raise for authorization checks",
        },
        {
            "id": "python-weak-random",
            "severity": "medium",
            "pattern": "random.randint(...)",
            "cwe": "CWE-330",
            "description": "Weak random number generator for security context",
            "fix": "Use secrets module for cryptographic randomness",
        },
        {
            "id": "python-debug-enabled",
            "severity": "low",
            "pattern": "DEBUG = True",
            "cwe": "CWE-489",
            "description": "Debug mode enabled in production",
            "fix": "Set DEBUG = False for production or use environment variable",
        },
    ],
    "javascript": [
        {
            "id": "js-eval",
            "severity": "critical",
            "pattern": "eval(...)",
            "cwe": "CWE-95",
            "description": "Dynamic code evaluation via eval()",
            "fix": "Avoid eval(); use JSON.parse() for data",
        },
        {
            "id": "js-innerhtml",
            "severity": "high",
            "pattern": "innerHTML = ...",
            "cwe": "CWE-79",
            "description": "DOM XSS via innerHTML assignment",
            "fix": "Use textContent, or sanitize with DOMPurify",
        },
        {
            "id": "js-document-write",
            "severity": "high",
            "pattern": "document.write(...)",
            "cwe": "CWE-79",
            "description": "DOM XSS via document.write()",
            "fix": "Use textContent or safe DOM manipulation methods",
        },
        {
            "id": "js-sql-concat",
            "severity": "critical",
            "pattern": "\"SELECT ... \" + $VAR",
            "cwe": "CWE-89",
            "description": "SQL injection via string concatenation",
            "fix": "Use parameterized queries with ? placeholders",
        },
        {
            "id": "js-dangerouslysethtml",
            "severity": "high",
            "pattern": "dangerouslySetInnerHTML={...}",
            "cwe": "CWE-79",
            "description": "React XSS via dangerouslySetInnerHTML",
            "fix": "Sanitize HTML before using dangerouslySetInnerHTML",
        },
        {
            "id": "js-child-process",
            "severity": "critical",
            "pattern": "child_process.exec(...)",
            "cwe": "CWE-78",
            "description": "OS command injection via child_process.exec()",
            "fix": "Use child_process.execFile() or spawn() with args array",
        },
        {
            "id": "js-unvalidated-redirect",
            "severity": "medium",
            "pattern": "res.redirect(...)",
            "cwe": "CWE-601",
            "description": "Open redirect vulnerability",
            "fix": "Validate redirect URL against whitelist of allowed domains",
        },
        {
            "id": "js-hardcoded-secret",
            "severity": "high",
            "pattern": "password = \"...\"",
            "cwe": "CWE-798",
            "description": "Hardcoded password/secret",
            "fix": "Use environment variables or secrets manager",
        },
    ],
    "java": [
        {
            "id": "java-rce-runtime",
            "severity": "critical",
            "pattern": "Runtime.getRuntime().exec(...)",
            "cwe": "CWE-78",
            "description": "OS command injection via Runtime.exec()",
            "fix": "Use ProcessBuilder with argument list, or avoid shell execution",
        },
        {
            "id": "java-deserialization",
            "severity": "critical",
            "pattern": "ObjectInputStream.readObject(...)",
            "cwe": "CWE-502",
            "description": "Unsafe Java deserialization",
            "fix": "Use readObject with whitelisting, or switch to JSON/protobuf",
        },
        {
            "id": "java-sql-injection",
            "severity": "critical",
            "pattern": "Statement.executeQuery(... + $VAR + ...)",
            "cwe": "CWE-89",
            "description": "SQL injection via Statement.executeQuery()",
            "fix": "Use PreparedStatement with parameterized queries",
        },
        {
            "id": "java-xxe",
            "severity": "high",
            "pattern": "DocumentBuilderFactory.newInstance()",
            "cwe": "CWE-611",
            "description": "XML External Entity (XXE) injection risk",
            "fix": "Disable external entities: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
        },
        {
            "id": "java-directory-traversal",
            "severity": "high",
            "pattern": "new File(... + $VAR)",
            "cwe": "CWE-22",
            "description": "Path traversal via unsanitized file path",
            "fix": "Validate and sanitize file paths; use Path.normalize()",
        },
    ],
    "go": [
        {
            "id": "go-exec-command",
            "severity": "critical",
            "pattern": "exec.Command(...)",
            "cwe": "CWE-78",
            "description": "OS command injection via exec.Command()",
            "fix": "Use exec.Command with separate args, avoid shell interpretation",
        },
        {
            "id": "go-sql-injection",
            "severity": "critical",
            "pattern": "db.Query(\"...\" + $VAR)",
            "cwe": "CWE-89",
            "description": "SQL injection via string concatenation",
            "fix": "Use parameterized queries: db.Query(\"SELECT ... WHERE id = ?\", id)",
        },
        {
            "id": "go-template-xss",
            "severity": "high",
            "pattern": "template.HTML(...)",
            "cwe": "CWE-79",
            "description": "XSS via raw HTML template injection",
            "fix": "Avoid template.HTML() for user input; use escaped templates",
        },
        {
            "id": "go-http-redirect",
            "severity": "medium",
            "pattern": "http.Redirect(..., $URL, ...)",
            "cwe": "CWE-601",
            "description": "Open redirect via unsanitized URL",
            "fix": "Validate redirect URL against allowed domains",
        },
    ],
    "php": [
        {
            "id": "php-eval",
            "severity": "critical",
            "pattern": "eval(...)",
            "cwe": "CWE-95",
            "description": "Dynamic code evaluation via eval()",
            "fix": "Avoid eval(); use proper control structures",
        },
        {
            "id": "php-rce-system",
            "severity": "critical",
            "pattern": "system(...)",
            "cwe": "CWE-78",
            "description": "OS command injection via system()",
            "fix": "Use escapeshellcmd() or avoid shell execution",
        },
        {
            "id": "php-sql-injection",
            "severity": "critical",
            "pattern": "mysqli_query(... + $VAR)",
            "cwe": "CWE-89",
            "description": "SQL injection via string concatenation",
            "fix": "Use prepared statements with bind_param()",
        },
        {
            "id": "php-file-include",
            "severity": "critical",
            "pattern": "include(... + $VAR)",
            "cwe": "CWE-98",
            "description": "Remote/Local file inclusion via include()",
            "fix": "Whitelist allowed files; use realpath() to validate path",
        },
        {
            "id": "php-unserialize",
            "severity": "critical",
            "pattern": "unserialize(...)",
            "cwe": "CWE-502",
            "description": "Unsafe PHP deserialization",
            "fix": "Use json_decode() instead of unserialize(); or use allowed_classes=false",
        },
    ],
}

# Language file extension mapping
LANG_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
}

# Severity weights for risk scoring
SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.0,
}


def analyze_git_diff(
    repo_path: str,
    commit1: str = "HEAD~1",
    commit2: str = "HEAD",
    output_dir: str = "./results",
) -> dict:
    """Analyze git diff between two commits with Semgrep-style pattern matching.

    Args:
        repo_path: Path to git repository
        commit1: First commit (older)
        commit2: Second commit (newer)
        output_dir: Output directory
    """
    results = {
        "method": "git_diff_analysis",
        "repo_path": repo_path,
        "commit1": commit1,
        "commit2": commit2,
        "files_changed": [],
        "security_findings": [],
        "semgrep_findings": [],
        "risk_score": 0.0,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Analyzing diff between {commit1} and {commit2}...[/dim]")

    try:
        # Get diff
        cmd = ["git", "diff", f"{commit1}..{commit2}", "--stat"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path)

        if result.returncode != 0:
            console.print(f"  [yellow]Git diff failed: {result.stderr}[/yellow]")
            return results

        # Get full diff
        cmd = ["git", "diff", f"{commit1}..{commit2}"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path)

        if result.returncode != 0:
            console.print(f"  [yellow]Git diff failed: {result.stderr}[/yellow]")
            return results

        diff_content = result.stdout
        results["diff_size"] = len(diff_content)

        # Parse diff for security patterns
        _analyze_diff_content(diff_content, results)

        # Get list of changed files
        cmd = ["git", "diff", "--name-only", f"{commit1}..{commit2}"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path)

        if result.returncode == 0:
            results["files_changed"] = result.stdout.splitlines()

        # Run Semgrep-style pattern matching on added lines
        _run_semgrep_patterns(diff_content, results)

        # Calculate risk score
        results["risk_score"] = _calculate_risk_score(results)

        if results["security_findings"] or results["semgrep_findings"]:
            total = len(results["security_findings"]) + len(results["semgrep_findings"])
            console.print(
                f"  [bold red]Found {total} security-related changes "
                f"(risk score: {results['risk_score']:.1f})[/bold red]"
            )
            for finding in results["security_findings"][:5]:
                console.print(f"    [red]• {finding['category']}: {finding['pattern']}[/red]")
            for finding in results["semgrep_findings"][:5]:
                console.print(
                    f"    [red]• [{finding['severity']}] {finding['pattern_id']}: "
                    f"{finding['description']}[/red]"
                )
        else:
            console.print(f"  [green]✓ No obvious security issues in diff[/green]")

    except FileNotFoundError:
        console.print("  [yellow]Git not available or not a git repository[/yellow]")
    except Exception as e:
        console.print(f"  [yellow]Error: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "git_diff_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def analyze_commits(
    repo_path: str,
    num_commits: int = 10,
    output_dir: str = "./results",
) -> dict:
    """Analyze recent commits for security changes.

    Args:
        repo_path: Path to git repository
        num_commits: Number of recent commits to analyze
        output_dir: Output directory
    """
    results = {
        "method": "commit_analysis",
        "repo_path": repo_path,
        "commits_analyzed": 0,
        "security_commits": [],
        "security_summary": {},
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Analyzing last {num_commits} commits...[/dim]")

    try:
        # Get commit list
        cmd = [
            "git", "log", f"-{num_commits}",
            "--pretty=format:%H|%s|%an|%ad",
            "--date=short",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path)

        if result.returncode != 0:
            console.print(f"  [yellow]Git log failed: {result.stderr}[/yellow]")
            return results

        # Parse commits
        security_keywords = [
            "fix", "vulnerability", "security", "cve", "exploit",
            "patch", "upgrade", "auth", "permission", "injection",
            "xss", "ssrf", "sqli", "rce", "deserializ", "overflow",
            "bypass", "escalat", "privilege", "secret", "credential",
        ]

        for line in result.stdout.splitlines():
            if not line.strip():
                continue

            parts = line.split("|", 3)
            if len(parts) < 4:
                continue

            commit_hash, subject, author, date = parts

            # Check if commit message mentions security
            is_security = False
            matched_keywords = []

            for keyword in security_keywords:
                if keyword.lower() in subject.lower():
                    is_security = True
                    matched_keywords.append(keyword)

            if is_security:
                results["security_commits"].append({
                    "hash": commit_hash[:8],
                    "subject": subject,
                    "author": author,
                    "date": date,
                    "keywords_matched": matched_keywords,
                })

                # Build summary
                for kw in matched_keywords:
                    results["security_summary"][kw] = results["security_summary"].get(kw, 0) + 1

            results["commits_analyzed"] += 1

        console.print(
            f"  [cyan]Analyzed {results['commits_analyzed']} commits, "
            f"{len(results['security_commits'])} security-related[/cyan]"
        )

        if results["security_commits"]:
            console.print(f"  [dim]Top security keywords: {dict(sorted(results['security_summary'].items(), key=lambda x: -x[1])[:5])}[/dim]")

    except FileNotFoundError:
        console.print("  [yellow]Git not available[/yellow]")
    except Exception as e:
        console.print(f"  [yellow]Error: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "commit_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    return results


def scan_semgrep_patterns(
    file_content: str,
    filename: str = "",
) -> List[VulnPattern]:
    """Run Semgrep-style pattern matching on code content.

    Args:
        file_content: Source code to scan
        filename: Optional filename for language detection

    Returns:
        List of vulnerability pattern matches
    """
    # Detect language from filename
    language = ""
    if filename:
        ext = Path(filename).suffix
        language = LANG_EXTENSIONS.get(ext, "")

    if not language:
        # Try to auto-detect
        language = _detect_language(file_content)

    patterns = SEMGREP_PATTERNS.get(language, [])
    findings = []

    for pattern in patterns:
        matches = _match_pattern(pattern, file_content)
        for match in matches:
            findings.append(VulnPattern(
                file=filename,
                line=match.get("line", 0),
                pattern_id=pattern["id"],
                severity=pattern["severity"],
                category=pattern["id"].split("-")[1] if "-" in pattern["id"] else "unknown",
                description=pattern["description"],
                code_snippet=match.get("snippet", ""),
                fix_suggestion=pattern.get("fix", ""),
                cwe=pattern.get("cwe", ""),
            ))

    return findings


def _analyze_diff_content(diff_content: str, results: dict):
    """Analyze diff content for security patterns."""
    lines = diff_content.splitlines()

    for i, line in enumerate(lines):
        # Skip diff metadata
        if line.startswith("diff --git") or line.startswith("---") or line.startswith("+++"):
            continue

        # Only analyze added/removed lines
        if not (line.startswith("+") or line.startswith("-")):
            continue

        content = line[1:].strip()
        if not content:
            continue

        # Check for security patterns
        for category, patterns in SECURITY_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in content.lower():
                    results["security_findings"].append({
                        "line": i + 1,
                        "category": category,
                        "pattern": pattern,
                        "content": content[:100],
                        "type": "added" if line.startswith("+") else "removed",
                    })
                    break  # Only report first match per line


def _run_semgrep_patterns(diff_content: str, results: dict):
    """Run Semgrep-style patterns on added lines of a diff."""
    lines = diff_content.splitlines()
    current_file = ""

    for i, line in enumerate(lines):
        # Track current file
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        # Only analyze added lines
        if not line.startswith("+"):
            continue

        content = line[1:]
        if not content.strip():
            continue

        # Detect language from file
        ext = Path(current_file).suffix if current_file else ""
        language = LANG_EXTENSIONS.get(ext, "")

        if not language:
            continue

        # Check patterns for this language
        patterns = SEMGREP_PATTERNS.get(language, [])
        for pattern in patterns:
            if _matches_semgrep_pattern(pattern["pattern"], content):
                results["semgrep_findings"].append({
                    "file": current_file,
                    "line": i + 1,
                    "pattern_id": pattern["id"],
                    "severity": pattern["severity"],
                    "cwe": pattern.get("cwe", ""),
                    "description": pattern["description"],
                    "fix": pattern.get("fix", ""),
                    "snippet": content.strip()[:100],
                })
                break  # One finding per line


def _matches_semgrep_pattern(pattern: str, code: str) -> bool:
    """Check if a Semgrep-style pattern matches code."""
    # Normalize both pattern and code
    pattern_clean = pattern.strip()
    code_clean = code.strip()

    # Convert Semgrep pattern elements to regex
    # $VAR matches any identifier, ... matches anything
    regex = re.escape(pattern_clean)

    # Handle $VAR placeholders
    regex = re.sub(r'\\\$(\w+)', r'[a-zA-Z_]\w*', regex)

    # Handle ... (anything)
    regex = regex.replace(r'\.\.\.', '.*')

    # Handle $SHELL etc.
    regex = re.sub(r'\\\$(\w+)', r'[a-zA-Z_]\w*', regex)

    try:
        return bool(re.search(regex, code_clean))
    except re.error:
        # Fallback to substring matching
        core_tokens = re.findall(r'[a-zA-Z_]\w*', pattern_clean)
        return all(token in code_clean for token in core_tokens if len(token) > 2)


def _match_pattern(pattern: dict, content: str) -> list:
    """Match a Semgrep pattern against code content."""
    matches = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        if _matches_semgrep_pattern(pattern["pattern"], line):
            # Get surrounding context
            start = max(0, i - 1)
            end = min(len(lines), i + 2)
            snippet = "\n".join(lines[start:end])

            matches.append({
                "line": i + 1,
                "snippet": snippet,
            })

    return matches


def _detect_language(content: str) -> str:
    """Detect programming language from code content."""
    indicators = {
        "python": ["def ", "import ", "from ", "class ", "__init__"],
        "javascript": ["function ", "const ", "let ", "var ", "=>", "require("],
        "java": ["public class", "private ", "protected ", "import java"],
        "go": ["func ", "package ", "import (", "fmt.Println"],
        "php": ["<?php", "function ", "echo ", "$"],
    }

    scores = {}
    for lang, keywords in indicators.items():
        score = sum(1 for kw in keywords if kw in content)
        if score > 0:
            scores[lang] = score

    if scores:
        return max(scores, key=scores.get)
    return ""


def _calculate_risk_score(results: dict) -> float:
    """Calculate a risk score from findings."""
    score = 0.0

    for finding in results.get("security_findings", []):
        # Basic scoring for security pattern matches
        score += 1.0

    for finding in results.get("semgrep_findings", []):
        severity = finding.get("severity", "low")
        score += SEVERITY_WEIGHTS.get(severity, 0.0)

    # Cap at 100
    return min(score, 100.0)
