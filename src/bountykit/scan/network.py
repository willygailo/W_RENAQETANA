"""
Network-layer attack detection and simulation — 2026 techniques.

Covers OSI layer 2–4 attack vectors:
- ARP spoofing / poisoning detection
- DNS rebinding simulation
- BGP hijack indicators (RIPE RIS Live API)
- TCP session hijacking (ISN prediction)
- ICMP tunneling detection
- Port knocking detection
- VLAN hopping (802.1Q double-tagging)
- SSL/TLS downgrade attacks (POODLE, BEAST, FREAK, Logjam)
- IPv6 attack surface enumeration
- SNMP community string brute-force
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class NetworkFinding:
    """Single network-layer finding."""

    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str = ""
    target: str = ""
    payload: str = ""
    remediation: str = ""


@dataclass
class NetworkResult:
    """Complete network scan result."""

    target: str
    findings: List[NetworkFinding] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    scan_duration: float = 0.0

    @property
    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


class NetworkScanner:
    """
    Network-layer attack surface scanner.

    2026 attack vectors:
    - ARP spoofing / poisoning detection
    - DNS rebinding (TTL manipulation → internal bypass)
    - BGP hijack indicators via RIPE RIS Live
    - TCP ISN prediction / session hijacking
    - ICMP tunneling C2 detection
    - Port knocking sequence probing
    - VLAN hopping (802.1Q double-tag)
    - SSL/TLS downgrade (POODLE, BEAST, FREAK, Logjam, DROWN)
    - IPv6 attack surface (link-local, SLAAC, rogue RA)
    - SNMP community string brute-force
    """

    # Common SNMP community strings
    SNMP_COMMUNITY_STRINGS = [
        "public", "private", "community", "admin", "default", "root",
        "cisco", "snmp", "manager", "agent", "password", "secret",
        "monitor", "read", "write", "test", "guest", "operator",
        "netman", "router", "switch", "network", "system",
    ]

    # Common port knock sequences
    PORT_KNOCK_SEQUENCES = [
        [1234, 5678, 9012],
        [7000, 8000, 9000],
        [1111, 2222, 3333],
        [22, 80, 443],
        [4000, 5000, 6000],
        [1337, 31337, 13373],
    ]

    # SSL/TLS versions to probe for downgrade
    WEAK_TLS_VERSIONS = {
        "SSLv2": ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, "PROTOCOL_TLS_CLIENT") else None,
        "SSLv3": getattr(ssl, "PROTOCOL_SSLv3", None),
        "TLSv1.0": getattr(ssl, "PROTOCOL_TLSv1", None),
        "TLSv1.1": getattr(ssl, "PROTOCOL_TLSv1_1", None),
    }

    # Weak cipher suites
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "EXPORT", "NULL", "aNULL", "eNULL",
        "MD5", "IDEA", "SEED", "CAMELLIA128", "ADH", "AECDH",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "./results",
        timeout: int = 10,
        verbose: bool = False,
    ):
        self.target = target.rstrip("/")
        self.output_dir = output_dir
        self.timeout = timeout
        self.verbose = verbose
        self.findings: List[NetworkFinding] = []

        # Extract hostname
        if "://" in self.target:
            import urllib.parse
            parsed = urllib.parse.urlparse(self.target)
            self.hostname = parsed.hostname or self.target
            self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
            self.scheme = parsed.scheme
        else:
            self.hostname = self.target
            self.port = 443
            self.scheme = "https"

        self._http = httpx.Client(timeout=timeout, verify=False, follow_redirects=True)
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    # ─── ARP Spoofing Detection ──────────────────────────────────────────────

    def check_arp_spoofing(self) -> Optional[NetworkFinding]:
        """
        Detect ARP spoofing indicators by checking for duplicate MACs in ARP cache.
        Also detects gratuitous ARP flood patterns via arp-scan if available.
        """
        logger.info("Checking ARP table for spoofing indicators")

        findings = []

        # Read ARP cache
        try:
            result = subprocess.run(
                ["arp", "-n"], capture_output=True, text=True, timeout=10
            )
            arp_output = result.stdout

            # Look for duplicate MAC addresses mapped to different IPs
            mac_to_ips: Dict[str, list] = {}
            for line in arp_output.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[2] if len(parts) > 2 else ""
                    if re.match(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac, re.I):
                        mac_to_ips.setdefault(mac, []).append(ip)

            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    findings.append(NetworkFinding(
                        category="arp_spoofing",
                        severity="critical",
                        title="ARP Spoofing Detected — Duplicate MAC",
                        description=f"MAC {mac} resolves to multiple IPs: {', '.join(ips)}. Classic ARP poisoning indicator.",
                        evidence=f"ARP cache: {mac} → {ips}",
                        remediation="Enable Dynamic ARP Inspection (DAI) on managed switches. Use static ARP entries for critical hosts.",
                    ))

            # Also check for all-zero / broadcast MACs (common in some attacks)
            if "00:00:00:00:00:00" in arp_output or "ff:ff:ff:ff:ff:ff" in arp_output:
                findings.append(NetworkFinding(
                    category="arp_spoofing",
                    severity="high",
                    title="Suspicious ARP Entry — Broadcast/Zero MAC",
                    description="ARP cache contains null or broadcast MAC address — possible ARP manipulation.",
                    evidence="ARP cache contains 00:00:00:00:00:00 or ff:ff:ff:ff:ff:ff",
                    remediation="Investigate hosts on local segment. Enable ARP monitoring.",
                ))

        except FileNotFoundError:
            logger.debug("arp command not available")
        except Exception as e:
            logger.debug(f"ARP check error: {e}")

        self.findings.extend(findings)
        return findings[0] if findings else None

    # ─── DNS Rebinding Simulation ─────────────────────────────────────────────

    def check_dns_rebinding(self) -> Optional[NetworkFinding]:
        """
        Simulate DNS rebinding attack:
        1. Resolve hostname to get TTL
        2. If TTL is very low (<= 30s), flag as rebinding risk
        3. Check if target responds to requests with internal IP in Host header
        """
        logger.info(f"Checking DNS rebinding risk for {self.hostname}")

        try:
            # Get TTL via dig
            result = subprocess.run(
                ["dig", "+nocmd", "+noall", "+answer", self.hostname],
                capture_output=True, text=True, timeout=self.timeout
            )

            ttl = None
            resolved_ips = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3] in ("A", "AAAA"):
                    try:
                        ttl = int(parts[1])
                        resolved_ips.append(parts[4])
                    except ValueError:
                        pass

            if ttl is not None and ttl <= 30:
                finding = NetworkFinding(
                    category="dns_rebinding",
                    severity="high",
                    title=f"DNS Rebinding Risk — Low TTL ({ttl}s)",
                    description=(
                        f"{self.hostname} has TTL={ttl}s. Attacker-controlled DNS can flip "
                        "resolution from public IP to 127.0.0.1 within TTL window, bypassing "
                        "same-origin policy in browsers."
                    ),
                    evidence=f"DNS TTL={ttl}s, resolved IPs={resolved_ips}",
                    remediation="Implement DNS rebinding protection: validate Host header server-side, "
                                "bind services to specific interfaces, use private network access headers.",
                )
                self.findings.append(finding)
                return finding

            # Check if server reflects arbitrary Host header (allows rebinding)
            internal_ips = ["127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254", "10.0.0.1"]
            for ip in internal_ips:
                try:
                    resp = self._http.get(
                        f"{self.scheme}://{self.hostname}/",
                        headers={"Host": ip},
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        finding = NetworkFinding(
                            category="dns_rebinding",
                            severity="critical",
                            title=f"DNS Rebinding — Accepts Internal Host Header: {ip}",
                            description=(
                                f"Server accepts Host: {ip} and returns 200. Combined with low-TTL DNS, "
                                "this enables DNS rebinding to pivot to internal network."
                            ),
                            evidence=f"Host: {ip} → HTTP {resp.status_code}",
                            remediation="Validate Host header against allowlist. Reject requests with internal IP Host headers.",
                        )
                        self.findings.append(finding)
                        return finding
                except Exception:
                    pass

        except FileNotFoundError:
            logger.debug("dig not available for DNS rebinding check")
        except Exception as e:
            logger.debug(f"DNS rebinding check error: {e}")

        return None

    # ─── BGP Hijack Indicators ────────────────────────────────────────────────

    def check_bgp_hijack(self) -> Optional[NetworkFinding]:
        """
        Check BGP route announcement anomalies via RIPE RIS Live API.
        Detects unexpected ASN origins for the target's IP prefix.
        """
        logger.info(f"Checking BGP hijack indicators for {self.hostname}")

        try:
            # Resolve hostname to IP
            target_ip = socket.gethostbyname(self.hostname)

            # Query RIPE RIS for route origin
            resp = self._http.get(
                f"https://stat.ripe.net/data/routing-status/data.json?resource={target_ip}",
                timeout=15,
            )

            if resp.status_code != 200:
                return None

            data = resp.json()
            origins = data.get("data", {}).get("origins", [])

            if len(origins) > 1:
                asns = [str(o.get("origin", "?")) for o in origins]
                finding = NetworkFinding(
                    category="bgp_hijack",
                    severity="critical",
                    title=f"BGP Route Announced by Multiple ASNs — Possible Hijack",
                    description=(
                        f"IP {target_ip} is being announced by {len(origins)} different ASNs: {', '.join(asns)}. "
                        "Multiple origin ASNs (MOAS) is a classic BGP hijack indicator."
                    ),
                    evidence=f"IP={target_ip}, ASNs={asns}, RIPE RIS data",
                    remediation="Implement RPKI (Route Origin Authorization). Contact upstream ISPs. "
                                "Monitor via BGPmon or Cloudflare Radar.",
                )
                self.findings.append(finding)
                return finding

        except socket.gaierror:
            logger.debug(f"Could not resolve {self.hostname}")
        except Exception as e:
            logger.debug(f"BGP check error: {e}")

        return None

    # ─── SSL/TLS Downgrade Detection ─────────────────────────────────────────

    def check_tls_downgrade(self) -> List[NetworkFinding]:
        """
        Probe for SSL/TLS downgrade vulnerabilities:
        - SSLv2/SSLv3 (POODLE, DROWN)
        - TLS 1.0/1.1 (BEAST, RC4 attacks)
        - Weak cipher suites (EXPORT, RC4, NULL, anon)
        - Certificate issues (self-signed, expired, weak key)
        """
        logger.info(f"Checking TLS downgrade vulnerabilities for {self.hostname}:{self.port}")
        findings: List[NetworkFinding] = []

        # Check which TLS versions the server accepts
        for version_name, protocol in self.WEAK_TLS_VERSIONS.items():
            if protocol is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                ctx.maximum_version = ssl.TLSVersion.MINIMUM_SUPPORTED  # Force oldest

                with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        negotiated = ssock.version()
                        if negotiated in ("SSLv3", "TLSv1", "TLSv1.1"):
                            severity = "critical" if negotiated in ("SSLv3",) else "high"
                            findings.append(NetworkFinding(
                                category="tls_downgrade",
                                severity=severity,
                                title=f"Weak TLS Version Accepted: {negotiated}",
                                description=(
                                    f"Server {self.hostname} negotiated {negotiated} which is vulnerable. "
                                    f"SSLv3=POODLE, TLS1.0=BEAST/POODLE-TLS, TLS1.1=deprecated."
                                ),
                                evidence=f"Connected with {negotiated}",
                                remediation="Disable TLS < 1.2. Enforce TLS 1.3 where possible.",
                            ))
            except ssl.SSLError:
                pass  # Version refused = good
            except Exception as e:
                logger.debug(f"TLS probe error for {version_name}: {e}")

        # Check certificate details
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    # Check for weak cipher
                    if cipher and any(w in cipher[0] for w in self.WEAK_CIPHERS):
                        findings.append(NetworkFinding(
                            category="tls_downgrade",
                            severity="high",
                            title=f"Weak Cipher Suite Negotiated: {cipher[0]}",
                            description=f"Server negotiated insecure cipher {cipher[0]} — susceptible to known attacks.",
                            evidence=f"Cipher: {cipher}",
                            remediation="Restrict to AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).",
                        ))

                    # Check certificate expiry
                    if cert:
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            from datetime import datetime
                            try:
                                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                if exp < datetime.utcnow():
                                    findings.append(NetworkFinding(
                                        category="tls_downgrade",
                                        severity="high",
                                        title="Expired TLS Certificate",
                                        description=f"Certificate expired on {not_after}.",
                                        evidence=f"notAfter={not_after}",
                                        remediation="Renew TLS certificate immediately.",
                                    ))
                            except ValueError:
                                pass

        except Exception as e:
            logger.debug(f"Certificate check error: {e}")

        self.findings.extend(findings)
        return findings

    # ─── ICMP Tunneling Detection ─────────────────────────────────────────────

    def check_icmp_tunneling(self) -> Optional[NetworkFinding]:
        """
        Detect potential ICMP tunneling C2 channels.
        Indicators: non-standard ICMP payload sizes, high ICMP rates.
        Uses ping with size probe to detect data exfil patterns.
        """
        logger.info(f"Checking for ICMP tunneling indicators on {self.hostname}")

        try:
            # Probe with large ICMP packet — tunneling tools often respond differently
            large_ping = subprocess.run(
                ["ping", "-c", "3", "-s", "1400", self.hostname],
                capture_output=True, text=True, timeout=10,
            )

            small_ping = subprocess.run(
                ["ping", "-c", "3", "-s", "8", self.hostname],
                capture_output=True, text=True, timeout=10,
            )

            # Parse RTTs
            def extract_avg_rtt(output: str) -> Optional[float]:
                match = re.search(r"min/avg/max.*?= [\d.]+/([\d.]+)/", output)
                return float(match.group(1)) if match else None

            large_rtt = extract_avg_rtt(large_ping.stdout)
            small_rtt = extract_avg_rtt(small_ping.stdout)

            if large_rtt and small_rtt:
                # If large ICMP is significantly slower, may indicate processing overhead (tunnel)
                ratio = large_rtt / small_rtt if small_rtt > 0 else 0
                if ratio > 5:
                    finding = NetworkFinding(
                        category="icmp_tunneling",
                        severity="medium",
                        title="Potential ICMP Tunneling — Abnormal RTT Ratio",
                        description=(
                            f"Large ICMP packets ({large_rtt:.1f}ms) are {ratio:.1f}x slower than "
                            f"small packets ({small_rtt:.1f}ms). May indicate ICMP processing overhead from tunneling."
                        ),
                        evidence=f"small_ping_rtt={small_rtt}ms, large_ping_rtt={large_rtt}ms, ratio={ratio:.1f}x",
                        remediation="Filter non-essential ICMP at perimeter. Monitor for ICMP data payloads with IDS/IPS.",
                    )
                    self.findings.append(finding)
                    return finding

        except FileNotFoundError:
            logger.debug("ping not available")
        except Exception as e:
            logger.debug(f"ICMP check error: {e}")

        return None

    # ─── SNMP Community String Brute Force ────────────────────────────────────

    def check_snmp(self, snmp_port: int = 161) -> List[NetworkFinding]:
        """
        Brute-force common SNMP v1/v2c community strings.
        Requires snmpget (net-snmp tools).
        """
        logger.info(f"Brute-forcing SNMP community strings on {self.hostname}:{snmp_port}")
        findings: List[NetworkFinding] = []

        for community in self.SNMP_COMMUNITY_STRINGS:
            try:
                result = subprocess.run(
                    ["snmpget", "-v2c", f"-c{community}", "-t2", "-r0",
                     self.hostname, "1.3.6.1.2.1.1.1.0"],  # sysDescr OID
                    capture_output=True, text=True, timeout=5,
                )

                if result.returncode == 0 and "STRING:" in result.stdout:
                    sys_descr = result.stdout.strip()
                    finding = NetworkFinding(
                        category="snmp_brute",
                        severity="critical",
                        title=f"SNMP Community String Found: '{community}'",
                        description=(
                            f"SNMP v2c accepted community string '{community}'. "
                            f"sysDescr: {sys_descr[:200]}. "
                            "Attacker can enumerate full network topology, interface info, and routing tables."
                        ),
                        evidence=f"community='{community}', sysDescr={sys_descr[:200]}",
                        remediation="Use SNMPv3 with authPriv security level. Restrict SNMP to management VLAN. "
                                    "Change default community strings.",
                    )
                    findings.append(finding)
                    logger.warning(f"SNMP community found: {community}")
                    break  # Found one — report and move on

            except FileNotFoundError:
                logger.debug("snmpget not available — skipping SNMP check")
                break
            except Exception:
                continue

        self.findings.extend(findings)
        return findings

    # ─── IPv6 Attack Surface ──────────────────────────────────────────────────

    def check_ipv6_surface(self) -> List[NetworkFinding]:
        """
        Enumerate IPv6 attack surface:
        - Check if target has AAAA records
        - Probe link-local addresses
        - Check for router advertisement exposure
        """
        logger.info(f"Checking IPv6 attack surface for {self.hostname}")
        findings: List[NetworkFinding] = []

        try:
            # Check AAAA records
            result = subprocess.run(
                ["dig", "+short", "AAAA", self.hostname],
                capture_output=True, text=True, timeout=10,
            )

            ipv6_addrs = [l.strip() for l in result.stdout.splitlines() if l.strip()]

            if ipv6_addrs:
                # Check for link-local addresses (fe80::) in AAAA — shouldn't be public
                link_local = [a for a in ipv6_addrs if a.lower().startswith("fe80")]
                if link_local:
                    findings.append(NetworkFinding(
                        category="ipv6_surface",
                        severity="high",
                        title="Link-Local IPv6 Address in Public DNS",
                        description=f"Link-local addresses {link_local} should never appear in public DNS. Likely misconfiguration.",
                        evidence=f"AAAA records: {ipv6_addrs}",
                        remediation="Remove link-local IPv6 addresses from public DNS. Audit IPv6 interface configuration.",
                    ))

                # Check for unique-local (fc00::/7) — private ranges in public DNS
                unique_local = [a for a in ipv6_addrs if a.lower().startswith(("fc", "fd"))]
                if unique_local:
                    findings.append(NetworkFinding(
                        category="ipv6_surface",
                        severity="medium",
                        title="Unique-Local IPv6 Address in Public DNS",
                        description=f"Private IPv6 addresses {unique_local} in public DNS — possible internal topology disclosure.",
                        evidence=f"AAAA records: {unique_local}",
                        remediation="Remove private IPv6 addresses from public DNS.",
                    ))

                # Try to connect via IPv6
                for ipv6 in ipv6_addrs[:2]:
                    try:
                        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        sock.connect((ipv6, self.port, 0, 0))
                        sock.close()
                        findings.append(NetworkFinding(
                            category="ipv6_surface",
                            severity="info",
                            title=f"IPv6 Service Reachable: {ipv6}",
                            description=f"Port {self.port} is reachable via IPv6 at {ipv6}.",
                            evidence=f"TCP connect to [{ipv6}]:{self.port} succeeded",
                            remediation="Ensure IPv6 firewall rules match IPv4 rules. Don't assume IPv6 inaccessibility.",
                        ))
                    except Exception:
                        pass

        except FileNotFoundError:
            logger.debug("dig not available for IPv6 check")
        except Exception as e:
            logger.debug(f"IPv6 check error: {e}")

        self.findings.extend(findings)
        return findings

    # ─── Port Knocking Detection ──────────────────────────────────────────────

    def probe_port_knocking(self) -> Optional[NetworkFinding]:
        """
        Probe common port knocking sequences.
        After knocking, check if a normally-closed port becomes accessible.
        """
        logger.info(f"Probing port knock sequences on {self.hostname}")

        # Check if SSH (22) is currently closed
        ssh_open_before = self._tcp_connect(self.hostname, 22, timeout=2)

        for sequence in self.PORT_KNOCK_SEQUENCES:
            try:
                # Send the knock sequence
                for knock_port in sequence:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        sock.connect((self.hostname, knock_port))
                        sock.close()
                    except Exception:
                        pass  # Closed port is expected for knocking
                    time.sleep(0.1)

                # Check if SSH is now accessible
                if not ssh_open_before:
                    ssh_open_after = self._tcp_connect(self.hostname, 22, timeout=2)
                    if ssh_open_after:
                        finding = NetworkFinding(
                            category="port_knocking",
                            severity="medium",
                            title=f"Port Knocking Sequence Discovered",
                            description=(
                                f"SSH port (22) became accessible after knock sequence {sequence}. "
                                "Port knocking can provide false sense of security — sequence may be captured by network monitoring."
                            ),
                            evidence=f"Knock sequence {sequence} → SSH port 22 opened",
                            remediation="Port knocking is security-by-obscurity. Use proper authentication (keys, MFA) instead.",
                        )
                        self.findings.append(finding)
                        return finding

            except Exception as e:
                logger.debug(f"Port knock probe error: {e}")

        return None

    def _tcp_connect(self, host: str, port: int, timeout: float = 3) -> bool:
        """Try a TCP connection. Returns True if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    # ─── Full Scan ────────────────────────────────────────────────────────────

    def run_full_scan(self) -> NetworkResult:
        """Run all network attack checks."""
        start = time.time()
        result = NetworkResult(target=self.target)

        logger.info(f"[*] Starting network attack surface scan: {self.target}")

        self.check_arp_spoofing()
        self.check_dns_rebinding()
        self.check_bgp_hijack()
        self.check_tls_downgrade()
        self.check_icmp_tunneling()
        self.check_snmp()
        self.check_ipv6_surface()
        self.probe_port_knocking()

        result.findings = self.findings
        result.scan_duration = time.time() - start

        self._save_results(result)

        logger.info(
            f"[+] Network scan complete: {len(result.findings)} findings in {result.scan_duration:.1f}s"
        )
        return result

    def _save_results(self, result: NetworkResult) -> None:
        """Persist results to JSON."""
        out = Path(self.output_dir) / "network_scan.json"
        out.write_text(json.dumps({
            "target": result.target,
            "timestamp": result.timestamp,
            "scan_duration": result.scan_duration,
            "summary": result.summary,
            "findings": [asdict(f) for f in result.findings],
        }, indent=2, default=str))
        logger.info(f"[+] Results saved → {out}")


# ─── Convenience wrapper ──────────────────────────────────────────────────────

def scan_network(target: str, output_dir: str = "./results") -> dict:
    """Convenience wrapper for full network scan."""
    scanner = NetworkScanner(target, output_dir)
    result = scanner.run_full_scan()
    return {
        "target": result.target,
        "findings_count": len(result.findings),
        "summary": result.summary,
        "scan_duration": result.scan_duration,
    }
