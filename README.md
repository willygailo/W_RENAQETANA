<div align="center">

<img src="./assets/banner.png" alt="BountyKit" width="100%">

<br>

![Version](https://img.shields.io/badge/version-0.2.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.10+-brightgreen?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-Apache%202.0-red?style=for-the-badge)
![Status](https://img.shields.io/badge/status-production--ready-orange?style=for-the-badge)

<br>

# ⚡ BountyKit

### Advanced Bug Bounty & CVE Research Framework

**One CLI. Every attack. Production-grade. Legally enforced.**

<br>

[![Install](https://img.shields.io/badge/-Install%20Now-blue?style=for-the-badge&logo=terminal)](#-install)
[![Docs](https://img.shields.io/badge/-Documentation-grey?style=for-the-badge)](#-all-commands)
[![License](https://img.shields.io/badge/-Apache%202.0-red?style=for-the-badge)](LICENSE)

<br>

`pip install bountykit` · `docker pull bountykit:latest` · `bountykit --help`

</div>

---

> ⚠️ **Disclaimer:** BountyKit is an authorized security research tool. You **must** have explicit written permission before scanning any target. Unauthorized use is illegal. See [LICENSE](LICENSE) and [LEGAL](LEGAL.md) for full terms.

---

## 🎯 Why BountyKit?

<table>
<tr>
<td width="50%" valign="top">

### 🛡️ 20 Scanners
- XSS, SQLi, SSRF, SSTI, GraphQL, API
- WAF bypass, HTTP smuggling, race conditions
- Supply chain, LLM/AI injection, WebSocket

</td>
<td width="50%" valign="top">

### 🔍 CVE Intelligence
- Real-world exploit chains
- Graph-based attack path engine
- CVSS scoring & patch diff analysis

</td>
</tr>
<tr>
<td width="50%" valign="top">

### ☁️ Multi-Cloud Security
- AWS, Azure, GCP
- S3, IAM, Lambda, GCS, Blob, K8s
- Metadata endpoint enumeration

</td>
<td width="50%" valign="top">

### ⚙️ Pipeline Engine
- Phase-based orchestration
- Async concurrency (cap 5)
- Resume from crash with state file

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔐 Legal Compliance
- Cryptographic scope engine (Ed25519)
- Tamper-proof hash-chain audit log
- Bug bounty platform API integration

</td>
<td width="50%" valign="top">

### 📊 Reports
- JSON, Markdown, HTML
- Risk scoring & severity summary
- Executive-ready output

</td>
</tr>
</table>

---

## 🚀 Install

<details open>
<summary><b>📦 PyPI</b></summary>

```bash
pip install bountykit
```
</details>

<details>
<summary><b>🔧 From Source</b></summary>

```bash
git clone https://github.com/willygailo/bountykit.git
cd bountykit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```
</details>

<details>
<summary><b>🔐 Crypto (optional — for Ed25519 signing)</b></summary>

```bash
pip install bountykit[crypto]
```
</details>

<details>
<summary><b>🐳 Docker</b></summary>

```bash
docker build -t bountykit .
docker run --rm bountykit version
```
</details>

---

## ⚡ Quick Start

```bash
# 🔍 Full recon & scan
bountykit pipeline --target https://example.com --scan-type full

# 🎯 Scan for a specific vuln
bountykit scan ssti --target https://example.com

# 🔎 Monitor CVEs for a technology
bountykit cve monitor --tech nginx

# ☁️ Check cloud misconfig
bountykit cloud aws --metadata

# 🔐 Authorize & audit
bountykit legal authorize --target example.com
bountykit legal audit
```

---

## 🗂️ All Commands

### 🎯 Scanners

| Command | Description |
|---------|-------------|
| `scan xss` | Reflected, stored, and DOM-based XSS detection |
| `scan sqli` | SQL injection with time-based, boolean, error-based payloads |
| `scan ssrf` | Server-side request forgery with DNS rebinding |
| `scan ssti` | SSTI detection — 20+ engines, polyglot probes, RCE chains |
| `scan graphql` | GraphQL security — introspection, batching, complexity |
| `scan api` | API security — REST, GraphQL, OWASP Top 10 |
| `scan oauth` | OAuth/JWT — redirect URI, token theft, JWT analysis |
| `scan network` | Network-layer — ARP spoof, DNS rebinding, TLS downgrade |
| `scan headers` | Security header and cookie audit |
| `scan deserialization` | Java, PHP, .NET deserialization detection |
| `scan takeover` | Subdomain takeover across 72 services with DoH fallback |
| `scan smuggle` | HTTP smuggling — CL.TE, TE.CL, cache poisoning |
| `scan race` | Race conditions — H2 single-packet, JWT race, Turbo Intruder |
| `scan waf` | WAF detection + 15 bypass techniques |
| `scan supply-chain` | Supply chain — malicious packages, typosquatting, CI/CD |
| `scan llm` | LLM/AI — prompt injection, RAG poisoning, tool hijack |
| `scan websocket` | WebSocket — CSWSH, injection, DoS, auth bypass |
| `scan cloud-misconfig` | Cloud misconfig — S3, GCS, Azure Blob, K8s, Firebase |
| `scan nuclei` | Nuclei scanner — severity filter, template selection |
| `scan template` | Generate Nuclei templates for specific vulnerabilities |

---

### 🔎 Reconnaissance

| Command | Description |
|---------|-------------|
| `recon passive` | Passive DNS — crt.sh, DNS lookup |
| `recon active` | Active probing — httpx, naabu, nmap |
| `recon subdomains` | Subdomain enumeration — subfinder + DNS brute-force |
| `recon js` | JavaScript analysis — secrets, DOM XSS, endpoints |
| `recon endpoints` | Endpoint discovery — Wayback, Arjun, ParamSpider |
| `recon crawl` | Deep crawler with JavaScript rendering |
| `recon iot` | IoT discovery — Shodan, Censys |
| `recon mobile` | Mobile app analysis (APK/IPA, secrets, endpoints) |
| `recon full` | Full recon pipeline — combines all modules |

---

### 🧠 CVE Intelligence

| Command | Description |
|---------|-------------|
| `cve search` | Search CVEs by keyword, year, severity, or CPE (`--keyword`, `--year`, `--severity`, `--cpe`) |
| `cve monitor` | Monitor technologies for new CVEs (`--tech`, `--notify`) |
| `cve pocs` | Fetch known PoCs for a CVE ID (`--cve-id`) |
| `cve chain` | Build exploit chains with graph engine and CVSS scoring (`--cve-ids`, `--target`) |
| `cve patchdiff` | Patch diff analysis to find introduced vulnerabilities (`--repo`, `--old`, `--new`) |

---

### ☁️ Cloud Security

| Command | Description |
|---------|-------------|
| `cloud aws` | Test AWS misconfigurations (SSRF to metadata, S3 bucket enumeration) |

---

### 🔐 Legal Compliance

| Command | Description |
|---------|-------------|
| `legal authorize` | Check authorization for a target against scope |
| `legal scope` | Manage signed scope files (show, verify, generate keys) |
| `legal audit` | View tamper-proof audit trail with chain verification |
| `legal platform` | Fetch scope from HackerOne / Bugcrowd APIs |
| `legal report` | Generate compliance report from audit trail |
| `legal techniques` | Show technique classification tree (info → destructive) |

---

### 🚀 Pipeline Engine

| Flag | Description |
|------|-------------|
| `--target` / `-t` | Target URL (required) |
| `--output` / `-o` | Output directory (default: `./results`) |
| `--scan-type` | `full`, `quick`, `recon`, `scan`, `cve`, `advanced` |
| `--no-parallel` | Disable parallel execution |
| `--resume` | Resume a crashed run from state file |

---

### 🛠️ Utility Commands

| Command | Description |
|---------|-------------|
| `setup` | Install and verify all external tools |
| `version` | Show version and check external tools |
| `config show` | View current configuration |
| `config set <key> <value>` | Set config value (e.g., `scan.threads 20`) |
| `report` / `report-generate` | Generate report (markdown / json / html) |
| `validate-license` | Verify LICENSE file and legal gate |
| `check-updates` | Check PyPI for new version |

---

## 🔐 Legal Compliance System

BountyKit features a cryptographic scope engine designed for authorized testing:

```bash
# Generate Ed25519 keypair
bountykit legal scope --generate-keys

# Sign a scope file
bountykit legal scope --sign --scope scope.yaml

# Check authorization
bountykit legal authorize --target example.com

# Verify audit log integrity
bountykit legal audit --verify

# Fetch scope from bug bounty platform
bountykit legal platform --platform hackerone --program myprogram --user myhandle

# Generate compliance report
bountykit legal report --target example.com
```

### Audit Trail

Every action is logged to a signed hash-chain. Use `--verify` to detect tampering:

```bash
bountykit legal audit                    # View last 7 days
bountykit legal audit --target example.com  # Filter by target
bountykit legal audit --verify             # Verify chain integrity
```

### Technique Classification

Techniques are ranked from safe to dangerous:

| Class | Examples |
|-------|----------|
| `INFO` | whois, dns_lookup, certificate_search |
| `PASSIVE` | crt_sh, wayback, github_dork, shodan |
| `ACTIVE` | port_scan, http_probe, crawl, waf_detection |
| `AGGRESSIVE` | sqli, xss, ssrf, llm_injection, supply_chain |
| `DESTRUCTIVE` | rce, dos, webshell, privilege_escalation |

---

## 📊 Reports

```bash
bountykit report-generate --input ./results --format markdown --output report.md
bountykit report-generate --input ./results --format html     --output report.html
bountykit report-generate --input ./results --format json     --output report.json
```

---

## ⚙️ Configuration

```bash
bountykit config show                    # View current config
bountykit config set scan.threads 20     # Scanning threads
bountykit config set scan.timeout 30     # Request timeout (seconds)
bountykit config set legal.safe_mode on  # Aggressive techniques blocked
```

---

## 🧪 Development

<details open>
<summary><b>Setup</b></summary>

```bash
git clone https://github.com/willygailo/bountykit.git
cd bountykit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```
</details>

<details>
<summary><b>Lint & Test</b></summary>

```bash
ruff check src/
pytest tests/ -v
```
</details>

### 📁 Project Layout

```
src/bountykit/
├── cli.py              CLI entry point (23 commands)
├── config.py           Pydantic configuration model
├── pipeline.py         Async dependency-graph pipeline
├── scan/               20 vulnerability scanners
├── cve/                CVE monitoring, chaining, patch diff
├── cloud/              AWS + multi-cloud security
├── recon/              9 reconnaissance modules
├── report/             Markdown report generation
├── utils/
│   ├── legal.py        Cryptographic scope engine + audit log
│   ├── report.py       HTML/JSON/Markdown report builder
│   ├── logger.py       Rich logging setup
│   ├── validator.py    Target, URL, severity validation
│   └── installer.py    External tool dependency installer
└── data/               Package data
```

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `click` | CLI framework |
| `rich` | Terminal output & progress |
| `httpx` | Async HTTP client with HTTP/2 |
| `pydantic` | Data validation |
| `pydantic-settings` | Env-based config |
| `pyyaml` | Config parsing |
| `jinja2` | Report templates |
| `websockets` | WebSocket security testing |
| **`cryptography`** `[crypto]` | Ed25519 scope signing *(optional)* |

---

## 📜 License

**Apache License 2.0** — see [LICENSE](LICENSE).

---

<div align="center">

**Built with ❤️ by [Willy Carnasa Gailo](https://www.facebook.com/https.willy.jr.carnasa.gailo2026.2027)**

[![GitHub](https://img.shields.io/badge/GitHub-willygailo-grey?style=for-the-badge&logo=github)](https://github.com/willygailo)

<br>

*If this tool helped you find a bug, consider buying me a coffee ☕*

</div>