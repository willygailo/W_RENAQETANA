<div align="center">

<br>

```
██████   ██████  ██    ██ ███    ██ ████████ ██    ██ ██   ██ ██ ████████
██   ██ ██    ██ ██    ██ ████   ██    ██    ██    ██ ██  ██  ██    ██
██████  ██    ██ ██    ██ ██ ██  ██    ██    ██    ██ █████   ██    ██
██   ██ ██    ██ ██    ██ ██  ██ ██    ██    ██    ██ ██  ██  ██    ██
██████   ██████   ██████  ██   ████    ██     ██████  ██   ██ ██    ██
```

<br>

# 🛡️ **BOUNTYKIT**

## **Advanced Bug Bounty & CVE Research CLI — 2026 Edition**

<br>

[![Version](https://img.shields.io/badge/version-0.2.0-1e1e2e?style=for-the-badge&labelColor=45475a)](https://github.com/willygailo/W_RENAQETANA)
[![Python](https://img.shields.io/badge/Python-3.10%2B-cba6f7?style=for-the-badge&logo=python&logoColor=white&labelColor=45475a)]()
[![License](https://img.shields.io/badge/license-MIT-a6e3a1?style=for-the-badge&labelColor=45475a)]()
[![Platform](https://img.shields.io/badge/Linux-f2cdcd?style=for-the-badge&logo=linux&logoColor=black&labelColor=45475a)]()
[![Status](https://img.shields.io/badge/Active-a6e3a1?style=for-the-badge&labelColor=45475a)]()
[![Modules](https://img.shields.io/badge/30%2B%20Modules-fab387?style=for-the-badge&labelColor=45475a)]()

<br>

**Recon · Scan · CVE · Cloud · Advanced · Report**

**One CLI to rule them all.**

[Install](#-installation) • [Quick Start](#-quick-start) • [Commands](#-commands-reference) • [Examples](#-usage-examples)

<br>

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

</div>

<br>

## 📑 **TABLE OF CONTENTS**

<table>
<tr>
<td width="50%">

- [📖 About](#-about)
- [✨ Features](#-features)
- [🚀 Installation](#-installation)
- [🎮 Quick Start](#-quick-start)

</td>
<td width="50%">

- [📋 Commands Reference](#-commands-reference)
- [💡 Usage Examples](#-usage-examples)
- [⚖️ Disclaimer](#️-disclaimer)
- [👤 Author](#-author)

</td>
</tr>
</table>

<br>

<div align="center">

## 📖 **ABOUT**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

</div>

<br>

**BountyKit** is a comprehensive, open-source CLI tool built for Linux-based bug bounty hunters and CVE researchers. It unifies **30+ modules** covering every phase of a security engagement — from passive reconnaissance to vulnerability scanning, CVE research, cloud security, and advanced 2026 attack vectors — all through a single, powerful command-line interface.

> **⚠️ BountyKit is built for authorized security research only.** Always obtain written permission before testing any target.

<br>

<div align="center">

### **What You Can Do**

`passive` **·** `active` **·** `subdomains` **·** `js` **·** `endpoints` **·** `crawl` **·** `iot` **·** `mobile`

`nuclei` **·** `sqli` **·** `xss` **·** `ssrf` **·** `api` **·** `graphql` **·** `oauth`

`cve search` **·** `cve monitor` **·** `cve pocs` **·** `chain` **·** `patchdiff`

`aws` **·** `cloud` **·** `llm` **·** `supplychain` **·** `race` **·** `smuggle` **·** `ssti`

</div>

<br>

<div align="center">

## ✨ **FEATURES**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

</div>

<br>

### 🔍 **Reconnaissance**

<table>
<tr><th width="140">Module</th><th>Description</th><th width="80">Status</th></tr>
<tr><td><code>passive</code></td><td>Passive DNS enumeration via crt.sh, DoH, CT logs</td><td align="center">✅ 2026</td></tr>
<tr><td><code>subdomains</code></td><td>Subdomain discovery with Subfinder + DNS brute-force</td><td align="center">✅</td></tr>
<tr><td><code>active</code></td><td>Host probing with HTTP/2 fingerprinting & tech detection</td><td align="center">✅ 2026</td></tr>
<tr><td><code>js</code></td><td>JavaScript file analysis — secrets, DOM XSS, endpoints</td><td align="center">✅</td></tr>
<tr><td><code>endpoints</code></td><td>Endpoint discovery — Waybackurls, Arjun, ParamSpider</td><td align="center">✅</td></tr>
<tr><td><code>crawl</code></td><td>Deep crawling — Katana + Gospider</td><td align="center">✅</td></tr>
<tr><td><code>iot</code></td><td>IoT/infrastructure discovery — Shodan, Censys</td><td align="center">✅</td></tr>
<tr><td><code>mobile</code></td><td>Mobile app recon — APK/IPA analysis</td><td align="center">✅</td></tr>
</table>

### 🎯 **Vulnerability Scanning**

<table>
<tr><th width="140">Module</th><th>Description</th><th width="80">Status</th></tr>
<tr><td><code>nuclei</code></td><td>Nuclei template-based scanning</td><td align="center">✅</td></tr>
<tr><td><code>sqli</code></td><td>SQLMap wrapper with WAF bypass techniques</td><td align="center">✅ 2026</td></tr>
<tr><td><code>xss</code></td><td>Dalfox XSS + DOM XSS, mutation XSS, CSP bypass</td><td align="center">✅ 2026</td></tr>
<tr><td><code>ssrf</code></td><td>SSRF testing with DNS rebinding & IPv6 bypass</td><td align="center">✅ 2026</td></tr>
<tr><td><code>api</code></td><td>OWASP API Top 10 with AI/Agentic API tests</td><td align="center">✅ 2026</td></tr>
<tr><td><code>graphql</code></td><td>GraphQL introspection, batching, DoS</td><td align="center">✅</td></tr>
<tr><td><code>oauth</code></td><td>OAuth redirect manipulation & JWT analysis</td><td align="center">✅</td></tr>
<tr><td><code>deserialization</code></td><td>Java/PHP/.NET deserialization detection</td><td align="center">✅</td></tr>
<tr><td><code>takeover</code></td><td>Subdomain takeover — 50+ service fingerprints</td><td align="center">✅</td></tr>
<tr><td><code>headers</code></td><td>Security headers, cookies, CSP audit</td><td align="center">✅</td></tr>
<tr><td><code>waf</code></td><td>WAF detection & bypass testing</td><td align="center">✅</td></tr>
</table>

### 🔐 **CVE Research**

<table>
<tr><th width="140">Module</th><th>Description</th><th width="80">Status</th></tr>
<tr><td><code>search</code></td><td>NVD API CVE search with exploit intelligence</td><td align="center">✅ 2026</td></tr>
<tr><td><code>monitor</code></td><td>CVE monitoring with webhook notifications</td><td align="center">✅</td></tr>
<tr><td><code>pocs</code></td><td>PoC exploit finder (GitHub + Nuclei)</td><td align="center">✅</td></tr>
<tr><td><code>chain</code></td><td>CVE chain analysis & attack paths</td><td align="center">✅</td></tr>
<tr><td><code>patchdiff</code></td><td>Git diff & commit security analysis</td><td align="center">✅</td></tr>
</table>

### ☁️ **Cloud Security**

<table>
<tr><th width="140">Module</th><th>Description</th><th width="80">Status</th></tr>
<tr><td><code>aws</code></td><td>AWS metadata SSRF, S3 bucket enumeration</td><td align="center">✅</td></tr>
<tr><td><code>cloud</code></td><td>Multi-cloud misconfig testing (AWS/GCP/Azure)</td><td align="center">✅</td></tr>
</table>

### 🚀 **2026 Advanced Security**

<table>
<tr><th width="140">Module</th><th>Description</th><th width="80">Status</th></tr>
<tr><td><code>llm</code></td><td>LLM/AI security testing (prompt injection, SSRF via LLM, skill poisoning)</td><td align="center">✅ 2026</td></tr>
<tr><td><code>supplychain</code></td><td>Supply chain security (TrapDoor, typosquatting, MCP hijack)</td><td align="center">✅ 2026</td></tr>
<tr><td><code>race</code></td><td>Race condition & business logic testing</td><td align="center">✅ 2026</td></tr>
<tr><td><code>smuggle</code></td><td>HTTP smuggling & cache poisoning</td><td align="center">✅ 2026</td></tr>
<tr><td><code>ssti</code></td><td>SSTI detection (20+ engines: Jinja2, Twig, Freemarker, etc.)</td><td align="center">✅ 2026</td></tr>
</table>

<br>

<div align="center">

## 🚀 **INSTALLATION**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

</div>

<br>

### 📋 **Prerequisites**

| Requirement | Version |
|-------------|---------|
| 🐧 **Linux** | Kali, Ubuntu, Debian |
| 🐍 **Python** | 3.10+ |
| 🔧 **Go** | 1.21+ |

### 📦 **Install BountyKit**

```bash
# Clone the repository
git clone https://github.com/willygailo/W_RENAQETANA.git
cd W_RENAQETANA

# Create virtual environment & install
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 🛠️ **Setup External Tools**

```bash
# Install all required external tools (subfinder, nuclei, sqlmap, etc.)
bountykit setup
```

### 🔗 **Make Available Everywhere**

```bash
echo 'export PATH="$HOME/W_RENAQETANA/.venv/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

<br>

<div align="center">

## 🎮 **QUICK START**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

</div>

<br>

```bash
# ═══════════════════════════════════════
# 1. Check legal authorization
# ═══════════════════════════════════════
bountykit legal -t example.com

# ═══════════════════════════════════════
# 2. Full reconnaissance
# ═══════════════════════════════════════
bountykit recon full -t example.com -o ./results

# ═══════════════════════════════════════
# 3. Vulnerability scanning
# ═══════════════════════════════════════
bountykit scan nuclei -t example.com -s critical,high

# ═══════════════════════════════════════
# 4. CVE search
# ═══════════════════════════════════════
bountykit cve search -k "apache log4j"

# ═══════════════════════════════════════
# 5. Automated pipeline
# ═══════════════════════════════════════
bountykit pipeline -t example.com --scan-type full

# ═══════════════════════════════════════
# 6. Generate report
# ═══════════════════════════════════════
bountykit report -i ./results -f markdown -o report.md
```

<br>

<div align="center">

## 📋 **COMMANDS REFERENCE**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

</div>

<br>

```
bountykit
│
├── 🔍 recon                    Reconnaissance
│   ├── passive              Passive DNS (crt.sh, DoH, CT logs)
│   ├── subdomains           Subdomain enumeration via subfinder
│   ├── active               Host probing (httpx/naabu/nmap)
│   ├── js                   JavaScript analysis (secrets, DOM XSS)
│   ├── endpoints            Endpoint discovery (Wayback, Arjun)
│   ├── crawl                Deep crawling (Katana/Gospider)
│   ├── iot                  IoT discovery (Shodan/Censys)
│   ├── mobile               Mobile app recon (APK/IPA)
│   └── full                 Full recon pipeline
│
├── 🎯 scan                     Vulnerability Scanning
│   ├── nuclei               Nuclei template scanner
│   ├── sqli                 SQLMap wrapper
│   ├── xss                  Dalfox XSS scanner
│   ├── ssrf                 SSRF testing
│   ├── api                  API security (OWASP Top 10)
│   ├── graphql              GraphQL security testing
│   ├── oauth                OAuth/JWT testing
│   ├── deserialization      Deserialization detection
│   ├── takeover             Subdomain takeover
│   ├── headers              Security header audit
│   ├── waf                  WAF detection & bypass
│   └── template             Nuclei template generator
│
├── 🔐 cve                      CVE Research
│   ├── search               Search CVE databases
│   ├── monitor              Monitor new CVEs
│   ├── pocs                 Find PoC exploits
│   ├── chain                CVE chain analysis
│   └── patchdiff            Patch diff analysis
│
├── ☁️ cloud                    Cloud Security
│   └── aws                  AWS misconfig testing
│
├── 🚀 advanced                 Advanced (2026)
│   ├── llm                  LLM/AI security testing
│   ├── supplychain          Supply chain security
│   ├── race                 Race condition testing
│   ├── smuggle              HTTP smuggling & cache poisoning
│   ├── ssti                 SSTI detection (20+ engines)
│   └── cloud                Multi-cloud security
│
├── 🤖 pipeline                 Automated Pipeline
├── 📊 report                   Report Generation
├── ⚙️  setup                    Tool Installation
└── ⚖️  legal                    Legal Authorization
```

<br>

<div align="center">

## 💡 **USAGE EXAMPLES**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

</div>

<br>

<details>
<summary><strong>🔍 Reconnaissance Commands</strong> — Click to expand</summary>
<br>

#### 📡 Passive DNS Enumeration
```bash
bountykit recon passive -t example.com
bountykit recon passive -t example.com -o ./results
```

#### 🌐 Active Host Probing
```bash
bountykit recon active -t example.com
bountykit recon active -t example.com --full
```

#### 🔗 Subdomain Enumeration
```bash
bountykit recon subdomains -t example.com
bountykit recon subdomains -t example.com --brute
```

#### 📜 JavaScript Analysis
```bash
bountykit recon js -t example.com
bountykit recon js -t example.com --all
bountykit recon js -t example.com --secrets
bountykit recon js -t example.com --endpoints
bountykit recon js -t example.com --dom-xss
```

#### 🔗 Endpoint Discovery
```bash
bountykit recon endpoints -t example.com
bountykit recon endpoints -t example.com -o ./results
```

#### 🕷️ Deep Crawling
```bash
bountykit recon crawl -t example.com
bountykit recon crawl -t example.com -d 3
bountykit recon crawl -t example.com --javascript
```

#### 📡 IoT Discovery
```bash
bountykit recon iot -t example.com
```

#### 📱 Mobile App Recon
```bash
bountykit recon mobile --apk path/to/target.apk
bountykit recon mobile --apk path/to/target.apk -o ./results
```

#### 📜 Full Recon Pipeline
```bash
bountykit recon full -t example.com -o ./results
bountykit recon full -t example.com -o ./results --brute
bountykit recon full -t example.com -o ./results --brute --full
```
</details>

<details>
<summary><strong>🎯 Scanning Commands</strong> — Click to expand</summary>
<br>

#### 🗄️ SQL Injection Testing
```bash
bountykit scan sqli -u "https://example.com/page?id=1"
bountykit scan sqli -u "https://example.com/search?q=test" -p q
bountykit scan sqli -u "https://example.com/page?id=1" --techniques all
bountykit scan sqli -u "https://example.com/page?id=1" --dbs
```

#### 🔥 XSS Testing
```bash
bountykit scan xss -u "https://example.com/search?q=test" -p q
bountykit scan xss -u "https://example.com/search?q=test" --techniques all
bountykit scan xss -u "https://example.com/search?q=test" --techniques dom
```

#### 🌐 SSRF Testing
```bash
bountykit scan ssrf -t "https://example.com/fetch?url=http://test.com" -p url
bountykit scan ssrf -t "https://example.com/fetch" --techniques all
bountykit scan ssrf -t "https://example.com/fetch" --techniques dns_rebinding
```

#### 🔌 API Security Testing
```bash
bountykit scan api -t https://api.example.com
bountykit scan api -t https://api.example.com --techniques all
```

#### 🛡️ Nuclei Template Scanning
```bash
bountykit scan nuclei -t example.com
bountykit scan nuclei -t example.com -s critical,high
bountykit scan nuclei -t example.com -r 150
bountykit scan nuclei -t example.com --templates ./custom-templates
```

#### 🔐 GraphQL Security Testing
```bash
bountykit scan graphql -t https://example.com/graphql
```

#### 🔑 OAuth/JWT Testing
```bash
bountykit scan oauth -t https://example.com/auth/callback
```

#### 🔄 Deserialization Testing
```bash
bountykit scan deserialization -t https://example.com/api
```

#### 🌍 Subdomain Takeover
```bash
bountykit scan takeover -t example.com
```

#### 📋 Security Headers Audit
```bash
bountykit scan headers -t https://example.com
```

#### 🛡️ WAF Detection & Bypass
```bash
bountykit scan waf -t https://example.com
```
</details>

<details>
<summary><strong>🔐 CVE Research Commands</strong> — Click to expand</summary>
<br>

#### 🔍 Search CVEs
```bash
bountykit cve search -k "apache log4j"
bountykit cve search -k "CVE-2024-1234"
bountykit cve search -k "apache" -s CRITICAL
bountykit cve search -k "log4j" -y 2024
bountykit cve search --cpe "cpe:2.3:a:apache:log4j"
```

#### 📡 Monitor CVEs
```bash
bountykit cve monitor -t apache
bountykit cve monitor -t apache -n https://hooks.slack.com/xxx
```

#### 💥 Find PoC Exploits
```bash
bountykit cve pocs -c CVE-2024-1234
```

#### 🔗 CVE Chain Analysis
```bash
bountykit cve chain -c CVE-2024-1234 -t https://target.com
bountykit cve chain -c CVE-2024-0001 CVE-2024-0002 -t https://target.com
```

#### 📋 Patch Diff Analysis
```bash
bountykit cve patchdiff -r /path/to/repo --old v1.0 --new v2.0
bountykit cve patchdiff -r https://github.com/user/repo --old abc123 --new def456
```
</details>

<details>
<summary><strong>☁️ Cloud Security Commands</strong> — Click to expand</summary>
<br>

#### 🔶 AWS Security Testing
```bash
bountykit cloud aws -b my-bucket
bountykit cloud aws --metadata
```

#### 🌐 Multi-Cloud Scanner
```bash
bountykit advanced cloud -p aws
bountykit advanced cloud -p all
bountykit advanced cloud -p aws --metadata-bypass --credentials
```
</details>

<details>
<summary><strong>🚀 Advanced 2026 Commands</strong> — Click to expand</summary>
<br>

#### 🤖 LLM/AI Security Testing
```bash
bountykit advanced llm -t https://chat.example.com -m gpt-4
bountykit advanced llm -t https://chat.example.com -a prompt_injection
bountykit advanced llm -t https://chat.example.com -a all
```

<table>
<tr><th>Attack</th><th>Description</th></tr>
<tr><td><code>prompt_injection</code></td><td>Direct and indirect prompt injection</td></tr>
<tr><td><code>ssrf_via_llm</code></td><td>SSRF through LLM tool calling</td></tr>
<tr><td><code>tool_hijack</code></td><td>Tool calling hijack exploitation</td></tr>
<tr><td><code>model_extraction</code></td><td>Model extraction attempts</td></tr>
<tr><td><code>skill_poisoning</code></td><td>Agent skill file poisoning</td></tr>
<tr><td><code>all</code></td><td>Run all attacks</td></tr>
</table>

#### 📦 Supply Chain Security
```bash
bountykit advanced supplychain -t https://github.com/user/repo
bountykit advanced supplychain -t https://github.com/user/repo -a typosquatting
bountykit advanced supplychain -t https://github.com/user/repo -a all
```

<table>
<tr><th>Attack</th><th>Description</th></tr>
<tr><td><code>malicious_packages</code></td><td>Scan for malicious dependencies</td></tr>
<tr><td><code>typosquatting</code></td><td>Check for typosquatting packages</td></tr>
<tr><td><code>ci_cd</code></td><td>CI/CD pipeline security</td></tr>
<tr><td><code>mcp_hijack</code></td><td>MCP server hijack</td></tr>
<tr><td><code>skill_poisoning</code></td><td>Agent skill poisoning</td></tr>
<tr><td><code>all</code></td><td>Run all checks</td></tr>
</table>

#### ⏱️ Race Condition Testing
```bash
bountykit advanced race -t https://api.example.com/checkout
bountykit advanced race -t https://api.example.com/checkout --threads 20
```

#### 🚢 HTTP Smuggling & Cache Poisoning
```bash
bountykit advanced smuggle -t https://example.com
bountykit advanced smuggle -t https://example.com -a all
bountykit advanced smuggle -t https://example.com -a cl_te
bountykit advanced smuggle -t https://example.com -a cache_poison
```

<table>
<tr><th>Attack</th><th>Description</th></tr>
<tr><td><code>cl_te</code></td><td>Content-Length / Transfer-Encoding</td></tr>
<tr><td><code>te_cl</code></td><td>Transfer-Encoding / Content-Length</td></tr>
<tr><td><code>te_te</code></td><td>Transfer-Encoding / Transfer-Encoding</td></tr>
<tr><td><code>cache_poison</code></td><td>Web cache poisoning</td></tr>
<tr><td><code>host_injection</code></td><td>Host header injection</td></tr>
<tr><td><code>all</code></td><td>Run all attacks</td></tr>
</table>

#### 🎨 Server-Side Template Injection
```bash
bountykit advanced ssti -t "https://example.com/page?name=test"
bountykit advanced ssti -t "https://example.com/page" -e jinja2
```

<table>
<tr><th>Engine</th><th>Language</th></tr>
<tr><td>Jinja2</td><td>Python</td></tr>
<tr><td>Twig</td><td>PHP</td></tr>
<tr><td>Freemarker</td><td>Java</td></tr>
<tr><td>Velocity</td><td>Java</td></tr>
<tr><td>Mako</td><td>Python</td></tr>
<tr><td>Pug</td><td>Node.js</td></tr>
<tr><td>EJS</td><td>Node.js</td></tr>
<tr><td>Handlebars</td><td>Node.js</td></tr>
<tr><td>Nunjucks</td><td>Node.js</td></tr>
<tr><td>ERB</td><td>Ruby</td></tr>
<tr><td>JSP</td><td>Java</td></tr>
<tr><td>Thymeleaf</td><td>Java</td></tr>
<tr><td>MVEL</td><td>Java</td></tr>
<tr><td>SpEL</td><td>Java</td></tr>
<tr><td>OGNL</td><td>Java</td></tr>
</table>
</details>

<details>
<summary><strong>🤖 Pipeline & Report Commands</strong> — Click to expand</summary>
<br>

#### 🔄 Automated Pipeline
```bash
bountykit pipeline -t example.com --scan-type full
bountykit pipeline -t example.com --scan-type quick
bountykit pipeline -t example.com --scan-type recon
bountykit pipeline -t example.com --scan-type scan
bountykit pipeline -t example.com --scan-type cve
bountykit pipeline -t example.com --scan-type advanced
bountykit pipeline -t example.com --scan-type full --no-parallel
```

<table>
<tr><th>Type</th><th>Description</th></tr>
<tr><td><code>full</code></td><td>Complete scan (recon + scan + CVE)</td></tr>
<tr><td><code>quick</code></td><td>Quick scan (essential checks only)</td></tr>
<tr><td><code>recon</code></td><td>Reconnaissance only</td></tr>
<tr><td><code>scan</code></td><td>Vulnerability scanning only</td></tr>
<tr><td><code>cve</code></td><td>CVE research only</td></tr>
<tr><td><code>advanced</code></td><td>2026 advanced techniques</td></tr>
</table>

#### 📊 Report Generation
```bash
bountykit report -i ./results -f markdown -o report.md
bountykit report -i ./results -f json -o report.json
```
</details>

<details>
<summary><strong>⚙️ Setup & Legal Commands</strong> — Click to expand</summary>
<br>

#### 🛠️ Setup Tools
```bash
bountykit setup
```

#### ⚖️ Legal Authorization
```bash
bountykit legal -t example.com
bountykit legal -t example.com -s ./scope.txt
```
</details>

<br>

### 📊 **Global Options**

<table>
<tr><th>Option</th><th>Description</th></tr>
<tr><td><code>--version</code></td><td>Show version</td></tr>
<tr><td><code>-c, --config PATH</code></td><td>Path to config file</td></tr>
<tr><td><code>-v, --verbose</code></td><td>Enable verbose output</td></tr>
<tr><td><code>-q, --quiet</code></td><td>Suppress non-essential output</td></tr>
<tr><td><code>--help</code></td><td>Show help message</td></tr>
</table>

<br>

<div align="center">

## ⚠️ **DISCLAIMER**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

</div>

<br>

> **🚨 IMPORTANT — READ BEFORE USE**

This tool is provided **"as is"** for **authorized security research and educational purposes only**.

By using **BountyKit**, you agree to the following:

<table>
<tr><th width="40">#</th><th>Rule</th></tr>
<tr><td align="center">1️⃣</td><td><strong>🔍 Authorization Required</strong> — You must have <strong>explicit written permission</strong> from the target system owner before running any scans or tests.</td></tr>
<tr><td align="center">2️⃣</td><td><strong>📋 Bug Bounty Programs Only</strong> — Only test targets listed in official bug bounty programs or under a signed pentesting agreement.</td></tr>
<tr><td align="center">3️⃣</td><td><strong>🚫 No Illegal Use</strong> — Never use for unauthorized access, data theft, disruption, or any illegal activity.</td></tr>
<tr><td align="center">4️⃣</td><td><strong>🛡️ Non-Destructive by Design</strong> — All payloads are read-only. The tool will not modify, delete, or corrupt any data.</td></tr>
<tr><td align="center">5️⃣</td><td><strong>📜 Compliance</strong> — You are responsible for complying with all applicable laws and regulations.</td></tr>
<tr><td align="center">6️⃣</td><td><strong>⚖️ No Liability</strong> — The author assumes <strong>no liability</strong> for misuse. Use at your own risk.</td></tr>
</table>

**If you do not agree to these terms, do not use this tool.**

<br>

<div align="center">

## 👤 **AUTHOR**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

<br>

### **Willy Gailo**

<br>

[![Facebook](https://img.shields.io/badge/Facebook-1877F2?style=for-the-badge&logo=facebook&logoColor=white)](https://www.facebook.com/willygailo)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/willygailo)

<br>

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

<br>

### 🙏 **Thank You**

If you found this tool helpful, consider giving it a ⭐ on GitHub!

### 🤝 **Contributions Welcome**

Feel free to open issues, submit pull requests, or suggest new features.

<br>

**🛡️ Stay Legal. Stay Ethical. Hunt Responsibly. 🛡️**

Made with ❤️ by [Willy Gailo](https://github.com/willygailo)

<br>

*© 2026 BountyKit. MIT License.*

</div>

<br>

<p align="center">
  <sub>
    <code>██████   ██████  ██    ██ ███    ██ ████████ ██    ██ ██   ██ ██ ████████</code><br>
    <code>██   ██ ██    ██ ██    ██ ████   ██    ██    ██    ██ ██  ██  ██    ██</code><br>
    <code>██████  ██    ██ ██    ██ ██ ██  ██    ██    ██    ██ █████   ██    ██</code><br>
    <code>██   ██ ██    ██ ██    ██ ██  ██ ██    ██    ██    ██ ██  ██  ██    ██</code><br>
    <code>██████   ██████   ██████  ██   ████    ██     ██████  ██   ██ ██    ██</code>
  </sub>
</p>
