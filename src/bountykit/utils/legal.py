"""Cryptographic scope engine, granular rule enforcement, and tamper-proof audit trail."""

import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import yaml
from rich.console import Console
from rich.panel import Panel

console = Console()

AUDIT_LOG_DIR = Path.home() / ".bountykit" / "audit"
DEFAULT_CONFIG_DIR = Path.home() / ".bountykit"

_CRYPTO_AVAILABLE = False
try:
    from cryptography.hazmat.primitives import serialization, hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_AVAILABLE = True
except ImportError:
    pass


class TechniqueClass(str, Enum):
    INFO = "info"
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"
    DESTRUCTIVE = "destructive"

    def __lt__(self, other):
        order = [t.value for t in TechniqueClass]
        return order.index(self.value) < order.index(other.value)


TECHNIQUE_CLASSIFICATION: dict[str, TechniqueClass] = {
    # info — no packets sent to target
    "whois": TechniqueClass.INFO,
    "dns_lookup": TechniqueClass.INFO,
    "certificate_search": TechniqueClass.INFO,
    # passive — public sources, no direct contact
    "crt_sh": TechniqueClass.PASSIVE,
    "wayback": TechniqueClass.PASSIVE,
    "github_dork": TechniqueClass.PASSIVE,
    "chaos": TechniqueClass.PASSIVE,
    "shodan": TechniqueClass.PASSIVE,
    "censys": TechniqueClass.PASSIVE,
    # active — direct contact, safe probes
    "port_scan": TechniqueClass.ACTIVE,
    "dns_bruteforce": TechniqueClass.ACTIVE,
    "http_probe": TechniqueClass.ACTIVE,
    "dir_bruteforce": TechniqueClass.ACTIVE,
    "js_analysis": TechniqueClass.ACTIVE,
    "crawl": TechniqueClass.ACTIVE,
    "header_audit": TechniqueClass.ACTIVE,
    "waf_detection": TechniqueClass.ACTIVE,
    # aggressive — may cause minor disruption
    "sqli": TechniqueClass.AGGRESSIVE,
    "xss": TechniqueClass.AGGRESSIVE,
    "ssrf": TechniqueClass.AGGRESSIVE,
    "ssti": TechniqueClass.AGGRESSIVE,
    "lfi": TechniqueClass.AGGRESSIVE,
    "open_redirect": TechniqueClass.AGGRESSIVE,
    "idor": TechniqueClass.AGGRESSIVE,
    "jwt_crack": TechniqueClass.AGGRESSIVE,
    "oauth": TechniqueClass.AGGRESSIVE,
    "api_fuzz": TechniqueClass.AGGRESSIVE,
    "graphql": TechniqueClass.AGGRESSIVE,
    "smuggle": TechniqueClass.AGGRESSIVE,
    "race_condition": TechniqueClass.AGGRESSIVE,
    "deserialization": TechniqueClass.AGGRESSIVE,
    "template_injection": TechniqueClass.AGGRESSIVE,
    "cloud_enum": TechniqueClass.AGGRESSIVE,
    "supply_chain": TechniqueClass.AGGRESSIVE,
    "llm_injection": TechniqueClass.AGGRESSIVE,
    # destructive — may cause significant harm
    "rce": TechniqueClass.DESTRUCTIVE,
    "command_injection": TechniqueClass.DESTRUCTIVE,
    "dos": TechniqueClass.DESTRUCTIVE,
    "data_exfil": TechniqueClass.DESTRUCTIVE,
    "privilege_escalation": TechniqueClass.DESTRUCTIVE,
    "container_escape": TechniqueClass.DESTRUCTIVE,
    "credential_theft": TechniqueClass.DESTRUCTIVE,
    "pwdump": TechniqueClass.DESTRUCTIVE,
    "webshell": TechniqueClass.DESTRUCTIVE,
}

DISCLAIMER = f"""
[bold red]LEGAL DISCLAIMER[/bold red]

This tool is for [bold]authorized penetration testing and bug bounty programs[/bold] only.

By using bountykit, you agree:
  1. You have [bold]written authorization[/bold] to test the target
  2. You will stay [bold]within scope[/bold] defined by the program
  3. You will [bold]never[/bold] test without permission
  4. You will follow [bold]coordinated disclosure[/bold] timelines
  5. You will not cause [bold]damage or disruption[/bold] to services

[bold red]Unauthorized access is illegal.[/bold red]
"""


# ─── Scope File Model ───────────────────────────────────────────────────────


class ScopeRule:
    def __init__(self, rule_type: str, value: Any):
        self.rule_type = rule_type
        self.value = value

    def matches(self, target: str, port: Optional[int] = None) -> bool:
        if self.rule_type == "domain":
            return _match_domain(target, self.value)
        if self.rule_type == "cidr":
            ip = _resolve_target_ip(target)
            if ip:
                return _match_cidr(ip, self.value)
            return False
        if self.rule_type == "ports":
            return port is not None and port in self.value
        if self.rule_type == "technique":
            technique_class = TECHNIQUE_CLASSIFICATION.get(self.value)
            if technique_class:
                return technique_class == TechniqueClass(self.value)
            return False
        return False


class ScopeFile:
    def __init__(
        self,
        target: str,
        valid_from: str,
        valid_until: str,
        allow: Optional[list[dict]] = None,
        deny: Optional[list[dict]] = None,
        max_requests_per_second: int = 10,
        auth_id: str = "",
        authorized_by: str = "",
        signature: str = "",
    ):
        self.target = target
        self.valid_from = _parse_iso(valid_from) if valid_from else datetime.min.replace(tzinfo=timezone.utc)
        self.valid_until = _parse_iso(valid_until) if valid_until else datetime.max.replace(tzinfo=timezone.utc)
        self.allow_rules = [_parse_scope_rule(r) for r in (allow or [])]
        self.deny_rules = [_parse_scope_rule(r) for r in (deny or [])]
        self.max_requests_per_second = max_requests_per_second
        self.auth_id = auth_id
        self.authorized_by = authorized_by
        self.signature = signature

    @property
    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        return now < self.valid_from or now > self.valid_until

    def allows(self, target: str, port: Optional[int] = None, technique: Optional[str] = None) -> tuple[bool, str]:
        if self.is_expired:
            return False, "Scope authorization has expired"

        if technique:
            technique_class = TECHNIQUE_CLASSIFICATION.get(technique, TechniqueClass.ACTIVE)
            for rule in self.deny_rules:
                if rule.rule_type == "technique" and rule.value == technique_class.value:
                    return False, f"Technique '{technique}' is denied by scope"
            for rule in self.deny_rules:
                if rule.rule_type == "technique" and technique_class <= TechniqueClass(rule.value):
                    return False, f"Technique class '{technique_class.value}' exceeds allowed '{rule.value}'"

        for rule in self.deny_rules:
            if rule.matches(target, port):
                return False, f"Target {target} matches deny rule: {rule.rule_type}={rule.value}"

        if not self.allow_rules:
            return True, "No allow rules — all targets permitted"

        for rule in self.allow_rules:
            if rule.matches(target, port):
                return True, f"Target matches allow rule: {rule.rule_type}={rule.value}"

        return False, f"Target {target} does not match any allow rule"

    def to_dict(self) -> dict:
        return {
            "scope": {
                "target": self.target,
                "valid_from": self.valid_from.isoformat(),
                "valid_until": self.valid_until.isoformat(),
                "allow": [{"domain": r.value} if r.rule_type == "domain" else
                          {"cidr": r.value} if r.rule_type == "cidr" else
                          {"ports": r.value} if r.rule_type == "ports" else
                          {"technique": r.value} for r in self.allow_rules] if self.allow_rules else [],
                "deny": [{"cidr": r.value} if r.rule_type == "cidr" else
                          {"technique": r.value} for r in self.deny_rules] if self.deny_rules else [],
                "max_requests_per_second": self.max_requests_per_second,
                "auth_id": self.auth_id,
                "authorized_by": self.authorized_by,
            },
            "signature": self.signature,
        }

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)

    def save(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(self.to_yaml())

    @classmethod
    def load(cls, path: str | Path) -> "ScopeFile":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Scope file not found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        scope_data = data.get("scope", data)
        allow = scope_data.get("allow", [])
        deny = scope_data.get("deny", [])
        return cls(
            target=scope_data.get("target", ""),
            valid_from=scope_data.get("valid_from", ""),
            valid_until=scope_data.get("valid_until", ""),
            allow=allow,
            deny=deny,
            max_requests_per_second=scope_data.get("max_requests_per_second", 10),
            auth_id=scope_data.get("auth_id", ""),
            authorized_by=scope_data.get("authorized_by", ""),
            signature=data.get("signature", ""),
        )


# ─── Signing ────────────────────────────────────────────────────────────────


def generate_keypair() -> tuple[bytes, bytes]:
    if not _CRYPTO_AVAILABLE:
        raise ImportError("cryptography package required for key generation. Install: pip install cryptography")
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def save_keypair(private_path: str | Path, public_path: str | Path):
    priv, pub = generate_keypair()
    Path(private_path).write_bytes(priv)
    Path(public_path).write_bytes(pub)
    Path(private_path).chmod(0o600)
    console.print(f"[green]✓ Private key → {private_path}[/green]")
    console.print(f"[green]✓ Public key  → {public_path}[/green]")


def sign_scope(scope_dict: dict, private_key_path: str | Path) -> str:
    private_bytes = Path(private_key_path).read_bytes()
    if len(private_bytes) == 32 and _CRYPTO_AVAILABLE:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        scope_content = yaml.dump(scope_dict, default_flow_style=False, sort_keys=False)
        signature = private_key.sign(scope_content.encode())
        import base64
        return base64.b64encode(signature).decode()
    scope_content = yaml.dump(scope_dict, default_flow_style=False, sort_keys=False)
    return hmac.new(private_bytes, scope_content.encode(), hashlib.sha256).hexdigest()


def verify_scope(scope_file: str | Path, public_key_path: Optional[str | Path] = None) -> tuple[bool, str]:
    path = Path(scope_file)
    if not path.exists():
        return False, "Scope file not found"
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    signature = data.get("signature", "")
    if not signature:
        return False, "No signature found in scope file"
    scope_data = {k: v for k, v in data.items() if k != "signature"}
    scope_content = yaml.dump(scope_data, default_flow_style=False, sort_keys=False)
    if public_key_path and _CRYPTO_AVAILABLE:
        try:
            public_bytes = Path(public_key_path).read_bytes()
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            import base64
            public_key.verify(base64.b64decode(signature), scope_content.encode())
            return True, "Ed25519 signature verified"
        except (InvalidSignature, Exception):
            return False, "Ed25519 signature invalid"
    expected = hmac.new(b"bountykit-default-key", scope_content.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(signature, expected):
        return True, "HMAC signature verified (insecure — provide public key for Ed25519)"
    return False, "Signature mismatch"


# ─── Matching Utilities ─────────────────────────────────────────────────────


def _match_domain(target: str, pattern: str) -> bool:
    target = target.strip().lower()
    pattern = pattern.strip().lower()
    if pattern == target:
        return True
    if pattern.startswith("*."):
        return target.endswith(pattern[1:]) or target == pattern[2:]
    if target.endswith("." + pattern):
        return True
    if target == pattern:
        return True
    return False


def _match_cidr(ip_str: str, cidr_str: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        ip = ipaddress.ip_address(ip_str)
        return ip in network
    except ValueError:
        return False


def _resolve_target_ip(target: str) -> Optional[str]:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        import socket
        return socket.gethostbyname(target)
    except Exception:
        return None


def _parse_iso(s: str) -> datetime:
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s)


def _parse_scope_rule(rule: dict) -> ScopeRule:
    if "domain" in rule:
        return ScopeRule("domain", rule["domain"])
    if "cidr" in rule:
        return ScopeRule("cidr", rule["cidr"])
    if "ports" in rule:
        return ScopeRule("ports", rule["ports"])
    if "technique" in rule:
        return ScopeRule("technique", rule["technique"])
    return ScopeRule("domain", str(rule.get("", "")))


# ─── Authorization Check ────────────────────────────────────────────────────


def check_authorization(
    target: str,
    scope_file: Optional[str] = None,
    technique: Optional[str] = None,
    port: Optional[int] = None,
    require_interactive: bool = True,
) -> bool:
    console.print(DISCLAIMER)

    if scope_file:
        scope = ScopeFile.load(scope_file)
        ok, reason = scope.allows(target, port=port, technique=technique)
        if ok:
            console.print(f"[green]✓ Scope check passed: {reason}[/green]")
            return True
        console.print(f"[red]✗ Scope check failed: {reason}[/red]")
        return False

    if _check_legacy_scope_file(target):
        return True

    if require_interactive:
        return _interactive_confirm(target)
    return False


def _check_legacy_scope_file(target: str) -> bool:
    path = DEFAULT_CONFIG_DIR / "scope.txt"
    if not path.exists():
        return False
    with open(path) as f:
        entries = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    for entry in entries:
        if entry == target:
            return True
        if entry.startswith("*.") and target.endswith(entry[1:]):
            return True
        if target.endswith(entry):
            return True
    return False


def _interactive_confirm(target: str) -> bool:
    console.print(f"[bold]Target:[/bold] {target}")
    response = input("\nDo you have [written authorization] to test this target? (yes/no): ")
    if response.lower() in ("yes", "y"):
        console.print("[green]Authorization confirmed.[/green]\n")
        return True
    console.print("[red]Authorization denied. Exiting.[/red]")
    return False


# ─── Technique Safety ───────────────────────────────────────────────────────


def resolve_technique_class(technique: str) -> TechniqueClass:
    return TECHNIQUE_CLASSIFICATION.get(technique.lower(), TechniqueClass.ACTIVE)


def get_safe_mode_level(safe_mode: str = "active") -> TechniqueClass:
    return TechniqueClass(safe_mode.lower())


def is_technique_allowed(
    technique: str,
    safe_mode: str = "active",
    scope_override: Optional[TechniqueClass] = None,
) -> bool:
    technique_class = resolve_technique_class(technique)
    max_allowed = scope_override or get_safe_mode_level(safe_mode)
    return technique_class <= max_allowed


# ─── Tamper-Proof Audit Log (Hash Chain) ────────────────────────────────────


class AuditLog:
    def __init__(self, log_dir: str | Path | None = None):
        self.log_dir = Path(log_dir) if log_dir else AUDIT_LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _current_log(self) -> Path:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.log_dir / f"{today}.jsonl"

    def append(
        self,
        action: str,
        target: str,
        status: str,
        metadata: Optional[dict] = None,
        signing_key: Optional[bytes] = None,
    ) -> dict:
        log_path = self._current_log()

        prev_hash = "0" * 64
        if log_path.exists():
            with open(log_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        prev_entry = json.loads(line)
                        prev_hash = prev_entry.get("entry_hash", prev_hash)

        timestamp = datetime.now(timezone.utc).isoformat()
        entry_payload = {
            "timestamp": timestamp,
            "action": action,
            "target": target,
            "status": status,
            "metadata": metadata or {},
            "prev_hash": prev_hash,
        }

        payload_str = json.dumps(entry_payload, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(payload_str.encode()).hexdigest()
        entry_payload["entry_hash"] = entry_hash

        if signing_key:
            entry_payload["signature"] = hmac.new(
                signing_key, payload_str.encode(), hashlib.sha256
            ).hexdigest()

        with open(log_path, "a") as f:
            f.write(json.dumps(entry_payload) + "\n")

        return entry_payload

    def verify_chain(self, log_path: str | Path) -> list[dict]:
        log_path = Path(log_path)
        if not log_path.exists():
            return [{"error": f"Log file not found: {log_path}"}]

        results = []
        prev_hash = "0" * 64

        with open(log_path) as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    results.append({"line": i, "error": f"Invalid JSON: {e}"})
                    continue

                stored_hash = entry.get("entry_hash", "")
                stored_prev = entry.get("prev_hash", "")

                if stored_prev != prev_hash:
                    results.append({
                        "line": i,
                        "error": f"Chain break: expected prev_hash={prev_hash}, got {stored_prev}",
                        "entry": entry,
                    })
                    return results

                verify_payload = {k: v for k, v in entry.items() if k not in ("entry_hash", "signature")}
                payload_str = json.dumps(verify_payload, sort_keys=True, separators=(",", ":"))
                expected_hash = hashlib.sha256(payload_str.encode()).hexdigest()

                if stored_hash != expected_hash:
                    results.append({
                        "line": i,
                        "error": f"Hash mismatch: entry tampered (line {i})",
                        "entry": entry,
                    })
                    return results

                prev_hash = stored_hash
                results.append({"line": i, "status": "ok", "entry": entry})

        return results

    def get_session(self, session_id: str) -> list[dict]:
        entries = []
        for log_file in sorted(self.log_dir.glob("*.jsonl")):
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    meta = entry.get("metadata", {})
                    if meta.get("session_id") == session_id or entry.get("target") == session_id:
                        entries.append(entry)
        return entries

    def get_target_history(self, target: str) -> list[dict]:
        entries = []
        for log_file in sorted(self.log_dir.glob("*.jsonl")):
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    if target in entry.get("target", ""):
                        entries.append(entry)
        return entries


# ─── Bug Bounty Platform Integration ────────────────────────────────────────


def fetch_hackerone_program(program_handle: str, username: str) -> Optional[ScopeFile]:
    console.print(f"[yellow]HackerOne: fetching scope for @{program_handle} as {username}[/yellow]")
    console.print("[dim]HackerOne API requires authentication token.[/dim]")
    console.print("[dim]Set HACKERONE_API_TOKEN environment variable.[/dim]")
    return None


def fetch_bugcrowd_program(program_code: str, username: str) -> Optional[ScopeFile]:
    console.print(f"[yellow]Bugcrowd: fetching scope for {program_code} as {username}[/yellow]")
    console.print("[dim]Bugcrowd API requires authentication token.[/dim]")
    console.print("[dim]Set BUGGROWD_API_TOKEN environment variable.[/dim]")
    return None


# ─── Compliance Report ──────────────────────────────────────────────────────


def generate_compliance_report(
    target: str,
    scope: ScopeFile,
    audit_entries: list[dict],
    findings: Optional[list[dict]] = None,
    output_path: Optional[str] = None,
) -> str:
    report = {
        "report_type": "bountykit legal compliance report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scope": {
            "valid_from": scope.valid_from.isoformat(),
            "valid_until": scope.valid_until.isoformat(),
            "auth_id": scope.auth_id,
            "authorized_by": scope.authorized_by,
            "allow_rules": len(scope.allow_rules),
            "deny_rules": len(scope.deny_rules),
            "is_expired": scope.is_expired,
        },
        "audit_trail": {
            "total_entries": len(audit_entries),
            "hash_chain_intact": _verify_audit_chain(audit_entries),
            "entries": audit_entries[-50:] if audit_entries else [],
        },
        "findings": {"total": len(findings) if findings else 0, "items": findings or []},
    }

    report_yaml = yaml.dump(report, default_flow_style=False, sort_keys=False)

    if output_path:
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            f.write(report_yaml)
        console.print(f"[green]✓ Compliance report → {out_path}[/green]")

    return report_yaml


def _verify_audit_chain(entries: list[dict]) -> bool:
    if not entries:
        return True
    prev_hash = "0" * 64
    for entry in entries:
        stored_prev = entry.get("prev_hash", "")
        if stored_prev != prev_hash:
            return False
        verify_payload = {k: v for k, v in entry.items() if k not in ("entry_hash", "signature")}
        payload_str = json.dumps(verify_payload, sort_keys=True, separators=(",", ":"))
        expected_hash = hashlib.sha256(payload_str.encode()).hexdigest()
        if entry.get("entry_hash", "") != expected_hash:
            return False
        prev_hash = entry["entry_hash"]
    return True


# ─── CLI Helpers ────────────────────────────────────────────────────────────


def get_technique_tree() -> str:
    lines = [
        "[bold]Technique Classification (safe → dangerous)[/bold]",
        "",
        "[dim]INFO[/dim]       whois, dns_lookup, certificate_search",
        "[dim]PASSIVE[/dim]    crt_sh, wayback, github_dork, chaos, shodan, censys",
        "[green]ACTIVE[/green]     port_scan, dns_bruteforce, http_probe, dir_bruteforce,",
        "               js_analysis, crawl, header_audit, waf_detection",
        "[yellow]AGGRESSIVE[/yellow] sqli, xss, ssrf, ssti, lfi, open_redirect, idor,",
        "               jwt_crack, oauth, api_fuzz, graphql, smuggle,",
        "               race_condition, deserialization, cloud_enum,",
        "               supply_chain, llm_injection",
        "[red]DESTRUCTIVE[/red]  rce, command_injection, dos, data_exfil,",
        "               privilege_escalation, container_escape,",
        "               credential_theft, pwdump, webshell",
    ]
    return "\n".join(lines)
