<div align="center">

<img src="https://raw.githubusercontent.com/willygailo/bountykit/main/assets/banner.png" alt="BountyKit" width="100%">

<br>

![Version](https://img.shields.io/badge/version-0.2.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.10+-brightgreen?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-Apache%202.0-red?style=for-the-badge)
![Status](https://img.shields.io/badge/status-production--ready-orange?style=for-the-badge)

<br>

# ⚡ BountyKit

### Advanced Bug Bounty & CVE Research Framework

**One CLI. Every attack. Production-grade.**

<br>

[![Install](https://img.shields.io/badge/-Install%20Now-blue?style=for-the-badge&logo=terminal)](#-install)
[![Docs](https://img.shields.io/badge/-Documentation-grey?style=for-the-badge)](#-all-commands)
[![License](https://img.shields.io/badge/-Apache%202.0-red?style=for-the-badge)](LICENSE)

<br>

`pip install bountykit` · `docker pull bountykit:latest` · `bountykit --help`

</div>

---

> ⚠️ **Disclaimer:** BountyKit is an authorized security research tool. You **must** have explicit written permission before scanning any target. Unauthorized use is illegal and punishable under computer crime laws. See [LICENSE](LICENSE) and [LEGAL](LEGAL.md) for full terms.

---

## 🎯 Why BountyKit?

<table>
<tr>
<td width="50%" valign="top">

### 🛡️ Security
- **19 scanner modules**
- Network, Cloud, LLM, Supply Chain
- SSTI, Race Conditions, WAF Bypass

</td>
<td width="50%" valign="top">

### 🔍 CVE Intelligence
- Real-world exploit chains
- Graph-based engine
- CVSS scoring & patch diff

</td>
</tr>
<tr>
<td width="50%" valign="top">

### ☁️ Cloud Security
- AWS, Azure, GCP, Kubernetes
- Firebase, Lambda, Docker
- Multi-provider scanning

</td>
<td width="50%" valign="top">

### ⚙️ Pipeline Engine
- Phase-based pipeline
- Async concurrency
- Resume from crash

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🚦 Rate Limiting
- Configurable requests/second
- Per-target throttling
- DoH fallback support

</td>
<td width="50%" valign="top">

### 📊 Reports
- JSON, Markdown, HTML
- Executive summary
- Structured output

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
<summary><b>🐳 Docker</b></summary>

```bash
# Start Docker daemon (if not running)
sudo systemctl start docker
sudo systemctl status docker

# Build & run
docker build -t bountykit .
docker run --rm bountykit version

# Scan with Docker (results persist to ./results on your host)
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit scan xss --url https://example.com
```

> 💡 **Tip:** Add your user to the `docker` group to avoid `sudo`:
> ```bash
> sudo usermod -aG docker $USER
> newgrp docker
> ```
</details>

<details>
<summary><b>🔬 Nuclei Integration (optional)</b></summary>

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```
</details>

---

## ⚡ Quick Start

```bash
# 🔍 Full recon & scan
bountykit pipeline --target https://example.com --scan-type full

# 🎯 Scan for specific vuln
bountykit scan ssti --target https://example.com

# 🔎 Monitor CVEs for a technology
bountykit cve monitor --tech "nginx"

# ☁️ Check cloud misconfig
bountykit cloud aws --metadata

# 📊 Generate report
bountykit report --format html --input ./results
```

---

## 📋 Copy-Paste Commands

Ready-to-run one-liners. Just copy, paste, and replace `https://example.com` with your authorized target.

<details open>
<summary><b>🎯 Scanners</b></summary>

```bash
bountykit scan xss  --url https://example.com
bountykit scan sqli --url https://example.com
bountykit scan ssrf --target https://example.com
bountykit scan ssti --target https://example.com
bountykit scan graphql --target https://example.com
bountykit scan api --target https://example.com
bountykit scan oauth --target https://example.com
bountykit scan ssrf --target https://example.com --techniques dns_rebinding
bountykit scan race --target https://example.com
bountykit scan waf --target https://example.com
bountykit scan takeover --target https://example.com
bountykit scan llm --target https://example.com
```
</details>

<details>
<summary><b>🔎 Reconnaissance</b></summary>

```bash
bountykit recon passive --target example.com
bountykit recon active --target example.com
bountykit recon subdomains --target example.com
bountykit recon js --target https://example.com
bountykit recon endpoints --target https://example.com
bountykit recon crawl --target https://example.com
bountykit recon iot --target example.com
bountykit recon mobile --apk ./app.apk
bountykit recon full --target example.com
```
</details>

<details>
<summary><b>🧠 CVE Intelligence</b></summary>

```bash
bountykit cve monitor --tech "apache"
bountykit cve chain --cve-ids CVE-2024-1234 --target https://example.com
bountykit cve patchdiff --repo https://github.com/owner/repo --old v1.0 --new v1.1
```
</details>

<details>
<summary><b>☁️ Cloud Security</b></summary>

```bash
bountykit cloud aws --metadata
bountykit cloud aws --bucket my-bucket-name
bountykit scan cloud-misconfig -p aws
bountykit advanced cloud -p aws
```
</details>

<details>
<summary><b>🚀 Pipeline & Reports</b></summary>

```bash
bountykit pipeline --target https://example.com --scan-type full
bountykit pipeline --target https://example.com --scan-type quick
bountykit pipeline --target https://example.com --scan-type advanced --no-parallel
bountykit pipeline --target https://example.com --resume

bountykit report --format json     --input ./results --output report.json
bountykit report --format html     --input ./results --output report.html
bountykit report --format markdown --input ./results --output report.md
```
</details>

<details>
<summary><b>🛠️ Utility & Legal</b></summary>

```bash
bountykit setup                 # Install & verify external tools
bountykit version               # Show version & tool status
bountykit config show          # View current config
bountykit config set scan.threads 20
bountykit legal --target https://example.com   # Check authorization
bountykit check-updates        # Check PyPI for new version
```
</details>

<details>
<summary><b>🐳 Docker — Advanced Attack Tactics</b></summary>

> 💡 **Why the extra flags?** `--rm` deletes the container (and any results inside it) when done. `-v "$PWD/results:/app/results"` mounts your local folder so JSON reports survive. `-u "$(id -u):$(id -g)"` writes files as your user (not root), and `-e HOME=/tmp` gives the tool a writable place for its config — without it you get `PermissionError: /.bountykit`.

```bash
# Build the image
docker build -t bountykit .

# SSTI — 20+ engines, polyglot probes, RCE chains
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit scan ssti --target https://example.com

# HTTP smuggling — CL.TE, TE.CL, cache poisoning
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit scan smuggle --target https://example.com

# Race conditions — H2 single-packet, JWT race
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit scan race --target https://example.com

# WAF detection + 15 bypass techniques
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit scan waf --target https://example.com

# Supply chain — malicious packages, typosquatting, GHA hijack
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit scan supply-chain --target https://example.com

# LLM/AI — prompt injection, RAG poisoning, tool hijack
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit scan llm --target https://example.com

# Advanced module: race condition & business logic
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit advanced race --target https://example.com

# Advanced module: multi-cloud (AWS/GCP/Azure)
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit advanced cloud -p aws

# Advanced module: HTTP smuggling & cache poisoning
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit advanced smuggle --target https://example.com

# Full advanced pipeline (no parallelism)
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit pipeline --target https://example.com --scan-type advanced --no-parallel

# Generate HTML report from results
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/results:/app/results" \
  bountykit report --format html --input /app/results --output /app/results/report.html
```
</details>

---

## 🗂️ All Commands

### 🎯 Scanners

<table>
<tr><td>

| Command | Description |
|---------|-------------|
| `scan xss` | Reflected, stored, and DOM-based XSS detection |
| `scan sqli` | SQL injection with time-based, boolean, and error-based payloads |
| `scan ssrf` | Server-side request forgery with DNS rebinding |
| `scan ssti` | SSTI detection — 20+ engines, polyglot probes, RCE chains |

</td><td>

| Command | Description |
|---------|-------------|
| `scan graphql` | GraphQL security — introspection, batching, query complexity |
| `scan api` | Test API security — REST, GraphQL, OWASP Top 10 |
| `scan oauth` | OAuth/JWT security — redirect URI, token theft, JWT analysis |
| `scan network` | Network-layer attacks — ARP spoof, DNS rebinding, TLS downgrade, BGP hijack, SNMP |

</td></tr>
<tr><td>

| Command | Description |
|---------|-------------|
| `scan headers` | Security header and cookie audit |
| `scan deserialization` | Deserialization vulnerabilities — Java, PHP, .NET |
| `scan takeover` | Subdomain takeover across 72 services with DoH fallback |
| `scan smuggle` | HTTP smuggling — CL.TE, TE.CL, TE.TE, cache poisoning, host injection |

</td><td>

| Command | Description |
|---------|-------------|
| `scan race` | Race conditions — H2 single-packet, JWT race, Turbo Intruder |
| `scan waf` | WAF detection + 15 bypass techniques |
| `scan supply-chain` | Supply chain — malicious packages, typosquatting, GHA hijack |
| `scan llm` | LLM/AI security — prompt injection, RAG poisoning, tool hijack |

</td></tr>
<tr><td colspan="2">

| Command | Description |
|---------|-------------|
| `scan cloud-misconfig` | Cloud misconfig — S3, GCS, Azure Blob, K8s, Firebase, Lambda, EC2 |
| `scan nuclei` | Nuclei scanner — severity filter, template selection |
| `scan template` | Generate Nuclei templates for specific vulnerabilities |

</td></tr>
</table>

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
| `recon full` | Full recon — combines all recon modules |

---

### 🧠 CVE Intelligence

| Command | Description |
|---------|-------------|
| `cve monitor` | Monitor technologies for new CVEs (`--tech`, `--notify`) |
| `cve chain` | Build exploit chains with graph engine and CVSS scoring (`--cve-ids`, `--target`) |
| `cve patchdiff` | Patch diff analysis to find introduced vulnerabilities (`--repo`, `--old`, `--new`) |

---

### ☁️ Cloud Security

| Command | Description |
|---------|-------------|
| `cloud aws` | Test AWS misconfigurations (SSRF to metadata, S3 bucket enumeration) |

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

### ⚡ Advanced Testing

| Command | Description |
|---------|-------------|
| `advanced llm` | LLM/AI security — prompt injection, SSRF, skill poisoning |
| `advanced supplychain` | Supply chain — malicious packages, typosquatting, CI/CD |
| `advanced race` | Race condition & business logic testing |
| `advanced smuggle` | HTTP smuggling & cache poisoning |
| `advanced ssti` | SSTI — 20+ template engines |
| `advanced cloud` | Multi-cloud security — AWS, GCP, Azure |

---

### 🛠️ Utility Commands

| Command | Description |
|---------|-------------|
| `setup` | Install and verify all external tools |
| `version` | Show version and check external tools |
| `config show` | View current configuration |
| `config set <key> <value>` | Set config value (e.g., `scan.threads 20`) |
| `report` | Generate report (markdown / json / html) |
| `report-generate` | Alias for report generation |
| `legal` | Check legal authorization for a target |
| `validate-license` | Verify LICENSE file and legal gate |
| `check-updates` | Check PyPI for new version |

---

## 📊 Reports

```bash
bountykit report --format json     --input ./results --output report.json
bountykit report --format markdown --input ./results --output report.md
bountykit report --format html     --input ./results --output report.html
```

---

## ⚙️ Configuration

```bash
bountykit config show                    # 👁️ View current config
bountykit config set scan.threads 20     # 🔧 Scanning threads
bountykit config set scan.timeout 30     # ⏱️ Request timeout (seconds)
bountykit config set legal.rate_limit 5  # 🚦 Requests per second
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
<summary><b>Run Tests</b></summary>

```bash
pytest tests/ -v
```
</details>

### 📁 Project Layout

```
bountykit/
├── 📄 cli.py        — CLI entry point
├── 📄 config.py     — Configuration management
├── 📄 pipeline.py   — Pipeline orchestrator
├── 📁 scan/         — 🔍 Vulnerability scanners
├── 📁 cve/          — 🧠 CVE intelligence
├── 📁 cloud/        — ☁️ Cloud misconfiguration
├── 📁 recon/        — 🎯 Reconnaissance
└── 📁 utils/        — 🛠️ Reports, logging, legal
```

---

## 📦 Dependencies

<table>
<tr><td>

| Package | Purpose |
|---------|---------|
| `httpx` | Async HTTP client with HTTP/2 |
| `click` | CLI framework |
| `rich` | Terminal output & progress |
| `pydantic` | Data validation |

</td><td>

| Package | Purpose |
|---------|---------|
| `pydantic-settings` | Env-based config |
| `tenacity` | Retry with backoff |
| `pyyaml` | Config parsing |
| `jinja2` | Report templates |

</td><td>

| Package | Purpose |
|---------|---------|
| `networkx` | CVE chain graph *(optional)* |
| `h2` | HTTP/2 smuggling *(optional)* |

</td></tr>
</table>

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
