"""Patch diffing and vulnerability analysis module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 21:
- Git diff analysis for patch comparison
- Vulnerability pattern detection in diffs
- Commit analysis for security changes
"""

import json
import os
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

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


def analyze_git_diff(
    repo_path: str,
    commit1: str = "HEAD~1",
    commit2: str = "HEAD",
    output_dir: str = "./results",
) -> dict:
    """Analyze git diff between two commits.

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

        if results["security_findings"]:
            console.print(
                f"  [bold red]⚠ Found {len(results['security_findings'])} security-related changes[/bold red]"
            )
            for finding in results["security_findings"][:10]:
                console.print(f"    [red]• {finding['category']}: {finding['pattern']}[/red]")
        else:
            console.print(f"  [green]✓ No obvious security issues in diff[/green]")

    except FileNotFoundError:
        console.print("  [yellow]Git not available or not a git repository[/yellow]")
    except Exception as e:
        console.print(f"  [yellow]Error: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "git_diff_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

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
        for line in result.stdout.splitlines():
            if not line.strip():
                continue

            parts = line.split("|", 3)
            if len(parts) < 4:
                continue

            commit_hash, subject, author, date = parts

            # Check if commit message mentions security
            is_security = False
            security_keywords = [
                "fix", "vulnerability", "security", "cve", "exploit",
                "patch", "upgrade", "auth", "permission", "injection",
            ]

            for keyword in security_keywords:
                if keyword.lower() in subject.lower():
                    is_security = True
                    break

            if is_security:
                results["security_commits"].append({
                    "hash": commit_hash[:8],
                    "subject": subject,
                    "author": author,
                    "date": date,
                })

            results["commits_analyzed"] += 1

        console.print(
            f"  [cyan]Analyzed {results['commits_analyzed']} commits, "
            f"{len(results['security_commits'])} security-related[/cyan]"
        )

    except FileNotFoundError:
        console.print("  [yellow]Git not available[/yellow]")
    except Exception as e:
        console.print(f"  [yellow]Error: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "commit_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


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
