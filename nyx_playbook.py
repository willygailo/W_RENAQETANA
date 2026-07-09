#!/usr/bin/env python3
# Copyright 2026 Willy Carnasa Gailo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Nyx: Authorized Security Testing Playbook (2026)
Interactive banner + confirmation gate before playbook display.

See LEGAL.md for full legal notice, jurisdiction warnings, and liability
disclaimer. See NOTICE for third-party attributions.
"""
import os
import sys
import json
import platform
import hashlib
from datetime import datetime

BANNER = r"""
===============================================================================
              AUTHORIZED SECURITY TESTING NOTICE  (v2.0)
===============================================================================
This tool performs active security scanning, vulnerability detection, and/or
exploitation techniques against computer systems and networks.

BY PROCEEDING, YOU CONFIRM THAT:
  1. You own the target system(s), OR you have obtained EXPLICIT WRITTEN
     AUTHORIZATION from the system owner to test it.
  2. Your testing activity falls within the defined SCOPE of that
     authorization (specific domains, IPs, or assets -- not "anything you
     can find").
  3. You understand that unauthorized access to computer systems is a
     criminal offense under:
        - Republic Act No. 10175 (Cybercrime Prevention Act of 2012), Philippines
        - Computer Fraud and Abuse Act (18 U.S.C. 1030), United States
        - Computer Misuse Act 1990, United Kingdom
        - Directive 2013/40/EU, European Union
        - Criminal Code Act 1995 Div 477-478, Australia
        - Computer Misuse Act (Cap. 50A), Singapore
        - UU ITE No. 11/2008, Indonesia
        - Information Technology Act 2000, India
        - Criminal Code S.342.1, Canada
        - Marco Civil da Internet (Lei 12.965/2014), Brazil
        - and equivalent computer-crime laws in most other jurisdictions.
  4. You have READ and UNDERSTOOD the full legal notice in LEGAL.md,
     including the liability disclaimer, prohibited uses, and indemnification
     clause.
  5. You will follow responsible / coordinated disclosure practices for any
     vulnerability found, and will not exploit findings beyond what is
     necessary to demonstrate and report the issue.
  6. The developer(s) and contributor(s) of this tool accept NO LIABILITY
     for misuse. This tool is provided for EDUCATIONAL PURPOSES and
     AUTHORIZED SECURITY RESEARCH only, AS-IS, WITHOUT WARRANTY.
  7. You agree to INDEMNIFY and hold harmless the authors from any claims,
     damages, or legal costs arising from your use or misuse of this tool.

Build: DeepSeek V4 Flash Free | License: Apache 2.0
--------------------------------------------------------------------------------
This session will be logged locally for accountability purposes:
    Timestamp : {timestamp}
    Target    : {target}
    User      : {user}
    Host      : {host}
    PID       : {pid}
    Session ID: {session_id}
--------------------------------------------------------------------------------
If you cannot truthfully agree to ALL of the statements above, exit now by
pressing Ctrl+C or typing "no" below.
--------------------------------------------------------------------------------
To continue, type the following exactly and press Enter:
    I CONFIRM I HAVE AUTHORIZATION
================================================================================
"""

PLAYBOOK = """
Nyx: All Advanced Tactics, Logic, Bug Bounty Methods & CVE Exploitation Playbook (2026 Update)

Comprehensive coverage delivered. Structured for immediate research application in controlled environments. Includes recon-to-RCE chains, modern surfaces (AI/LLM, Cloud/K8s), and high-impact 2025-2026 CVEs with exploitation patterns.

### 1. Core Tactical Logic Framework (OODA + Attack Surface Expansion)
**Mindset**: Recon (90%) -> Hypothesis Generation -> Targeted Testing -> Chaining -> Impact Proof.

- **Phase 0: Program/Scope Analysis** -- Map in-scope assets, exclusions, bounty tiers. Prioritize auth, payments, admin, APIs, cloud.
- **Phase 1: Recon & Asset Discovery**:
  - Passive: `crt.sh`, `Chaos`, GitHub dorks, `waybackurls`.
  - Active: `subfinder + amass + httpx`, port scanning (`naabu`), tech detection (`nuclei`, `wappalyzer`).
  - Cloud: `cloud_enum`, S3/GCP bucket brute, IAM misconfigs.
  - JS Analysis: Extract endpoints/secrets with `jsleak` or custom scripts.
  - AI/LLM: Test prompt injection vectors in chat interfaces.
- **Phase 2: Vulnerability Discovery (Ebb & Flow)**:
  - Cluster hunt: One bug signals siblings (IDOR read -> write -> mass exfil).
  - Use AI-augmented hypothesis: Feed Burp/ZAP traffic to LLMs for vuln suggestions.
  - Graph-based chaining tools map attack paths automatically.

**A->B->C Signal Method**:
- IDOR -> Mass assignment / PII leak -> ATO.
- Open Redirect -> OAuth code/token theft -> Full takeover.
- SSRF -> Cloud metadata -> Credential theft / RCE.
- XSS -> CSRF bypass / Cookie theft (via service workers for persistence).
- Prototype Pollution -> DOM XSS / RCE gadgets (Node.js).
- GraphQL Introspection -> BFLA (Broken Function Level Auth) -> Data exfil.

**2026 Modern Surfaces**:
- **AI/LLM**: Direct/Indirect prompt injection -> SSRF via tool calling -> Cloud compromise.
- **WebAuthn/SAML**: Bypass via CORS, XML external entities for key theft.
- **WebSockets/GraphQL**: Message flooding, unauthorized mutations.
- **Containers/K8s**: Pod escapes, misconfigs in DaemonSets, GitOps (Argo CD).

### 2. High-Impact Bug Bounty Tactics & Methods
**Recon Automation Pipeline** (Bash skeleton):
```
subfinder -d target.com | httpx -silent -tech-detect | nuclei -t http/ -o findings.txt
# Chain with custom fuzzer for params
```

**Key Playbooks**:
- **Auth & Access Control**: Test JWT weak secrets (`jwt_tool`), session fixation, weak password reset (IDOR on tokens).
- **Injection & RCE**: SSTI (`{{7*7}}`, Jinja/Twig), Command injection via backups/imports.
- **File Uploads**: Path traversal + polyglots, unrestricted dangerous types -> webshell.
- **Business Logic**: Race conditions (`race-the-web`), logic bypass via param pollution.
- **API Abuse**: Rate limit bypass (header rotation), BOLA/IDOR at scale.
- **Evasion**: WAF bypass collections, encoding chains, living-off-the-land (certutil, mshta).

**Chaining for Critical Impact** (Report as single high-value issue):
- Low + Low -> Critical multiplier (10-20x bounty).
- Examples: CORS + Open Redirect = OAuth ATO; File Upload + SSRF = RCE.

**Post-Exploitation Research**:
- Persistence: Malicious DaemonSets, service workers, shadow API servers.
- Exfil: DNS tunneling, stego in images.
- Cleanup: Timestomp, log wiping.

**Reporting**: Clear impact title + precise PoC (curl/video) + business risk + remediation.

### 3. CVE Exploitation Methods (2025-2026 Focus)
**Workflow**: Lab repro -> Fuzz/variant research -> PoC dev (Python/C++/Go) -> Chain -> Evasion.

**Standout 2025-2026 CVEs & Patterns**:
- **CVE-2025-55182 (React2Shell, CVSS 10)**: Unauthenticated RCE via unsafe deserialization in React Server Components. Public exploits exploded (236+). Pattern: Malicious Flight protocol payload -> code exec in web apps/K8s workloads. Chain to cloud creds theft.
- **Microsoft SharePoint Cluster (CVE-2025-49704, etc.)**: Code injection + improper auth. In-the-wild mass exploitation. Exploit via crafted requests to on-prem instances.
- **Adobe ColdFusion CVE-2026-48282 (CVSS 10)**: Unauth path traversal in RDS FILEIO -> arbitrary file write/RCE. Actively exploited fast.
- **JoomShaper SP Page Builder CVE-2026-48908**: Unauth file upload -> PHP webshell/RCE. 194k+ exposed.
- **Container/K8s Escapes**:
  - **CVE-2026-31431 (Copy-Fail)**: Page-cache corruption via shared image layers -> unprivileged pod to node RCE. PoCs available for EKS/GKE/ACK. Use with DaemonSet sharing layers.
  - containerd CVEs (2026-50195 etc.): Checkpoint/image poisoning -> cross-pod execution, host command exec.
  - CDK/ctrsploit toolkits for runc, cgroup, dirty pipe variants.
- **Browser**: Multiple Chrome V8 use-after-free / OOB (e.g., CVE-2026-11645 series). Sandbox escapes.
- **Others**: Ivanti, Fortinet, SAP NetWeaver file uploads, Oracle EBS auth bypass.

**Generic Exploit Skeleton**:
```python
# Example SSRF to RCE skeleton (adapt per CVE)
import requests
payload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Chain to command injection or deserialization gadget (ysoserial, phpggc)
```

For binary/memory: `pwntools` ROP, Frida for mobile/browser.

**Advanced Evasion**:
- Obfuscation, sandbox escape (kernel bugs like CVE-2026-31431).
- LOLBins + living off the land in containers.
- Anti-forensics for research persistence.

**Full Toolchains**:
- **Containers**: CDK, ctrsploit for escapes.
- **Cloud**: Pacu, custom IAM assumption scripts.
- **Automation**: Nuclei templates, Burp extensions, LLM-augmented fuzzers.
"""


def log_detailed(target, confirmed, session_id):
    log_path = os.path.expanduser("~/.nyx_access.log")
    record = {
        "timestamp": datetime.now().isoformat(),
        "session_id": session_id,
        "user": os.getlogin(),
        "host": platform.node(),
        "pid": os.getpid(),
        "target": target,
        "confirmed": confirmed,
        "python_version": sys.version.split()[0],
    }
    entry = json.dumps(record) + "\n"
    with open(log_path, "a") as f:
        f.write(entry)


def main():
    target = os.environ.get("NYX_TARGET", "<user-provided target/scope>")
    user = os.getlogin()
    host = platform.node()
    pid = os.getpid()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw = f"{timestamp}:{user}:{host}:{pid}:{target}"
    session_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    filled_banner = BANNER.format(
        timestamp=timestamp, target=target, user=user, host=host, pid=pid,
        session_id=session_id,
    )
    print(filled_banner)

    try:
        response = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Exiting. No confirmation provided.")
        log_detailed(target, False, session_id)
        sys.exit(1)

    expected = "I CONFIRM I HAVE AUTHORIZATION"
    if response != expected:
        print(f"\n[!] Invalid confirmation. Expected exactly:\n    {expected}")
        log_detailed(target, False, session_id)
        sys.exit(1)

    print("\n[+] Confirmation accepted. Loading playbook...\n")
    log_detailed(target, True, session_id)
    print(PLAYBOOK)


if __name__ == "__main__":
    import sys
    main()
