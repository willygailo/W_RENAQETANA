<<<<<<< HEAD
<div align="center">

# 🛡️ **BOUNTYKIT**

### *Advanced Open-Source Legal CLI for Bug Bounty & CVE Research — 2026 Edition*

---

![Version](https://img.shields.io/badge/version-0.2.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Linux-000000?style=for-the-badge&logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)
![Modules](https://img.shields.io/badge/modules-30+-orange?style=for-the-badge)

---

**One CLI to rule them all.** 🗡️

Recon → Scan → CVE → Cloud → Advanced → Report — everything you need for authorized security research, unified in a single, powerful command-line tool.

---

</div>

## 📑 **TABLE OF CONTENTS**

- [📖 About](#-about)
- [✨ Features](#-features)
- [🚀 Installation](#-installation)
- [🎮 Quick Start](#-quick-start)
- [📋 Commands Reference](#-commands-reference)
- [💡 Usage Examples](#-usage-examples)
- [⚖️ Disclaimer](#️-disclaimer)
- [👤 Author](#-author)

---

<div align="center">

## 📖 **ABOUT**

</div>

**BountyKit** is a comprehensive, open-source CLI tool built for Linux-based bug bounty hunters and CVE researchers. It brings together **30+ modules** covering every phase of a security engagement — from passive reconnaissance to vulnerability scanning, CVE research, cloud security, and advanced 2026 attack vectors.

> ⚠️ **BountyKit is built for authorized security research only.** Always obtain written permission before testing any target.

---

<div align="center">

## ✨ **FEATURES**

</div>

### 🔍 **Reconnaissance**
| Module | Description | Status |
|--------|-------------|--------|
| `passive` | Passive DNS enumeration via crt.sh, DoH, CT logs | ✅ 2026 |
| `subdomains` | Subdomain discovery with Subfinder + DNS brute-force | ✅ |
| `active` | Host probing with HTTP/2 fingerprinting & tech detection | ✅ 2026 |
| `js` | JavaScript file analysis — secrets, DOM XSS, endpoints | ✅ |
| `endpoints` | Endpoint discovery — Waybackurls, Arjun, ParamSpider | ✅ |
| `crawl` | Deep crawling — Katana + Gospider | ✅ |
| `iot` | IoT/infrastructure discovery — Shodan, Censys | ✅ |
| `mobile` | Mobile app recon — APK/IPA analysis | ✅ |

### 🎯 **Vulnerability Scanning**
| Module | Description | Status |
|--------|-------------|--------|
| `nuclei` | Nuclei template-based scanning | ✅ |
| `sqli` | SQLMap wrapper with WAF bypass techniques | ✅ 2026 |
| `xss` | Dalfox XSS + DOM XSS, mutation XSS, CSP bypass | ✅ 2026 |
| `ssrf` | SSRF testing with DNS rebinding & IPv6 bypass | ✅ 2026 |
| `api` | OWASP API 2026 Top 10 with AI/Agentic API tests | ✅ 2026 |
| `graphql` | GraphQL introspection, batching, DoS | ✅ |
| `oauth` | OAuth redirect manipulation & JWT analysis | ✅ |
| `deserialization` | Java/PHP/.NET deserialization detection | ✅ |
| `takeover` | Subdomain takeover — 50+ service fingerprints | ✅ |
| `headers` | Security headers, cookies, CSP audit | ✅ |
| `waf` | WAF detection & bypass testing | ✅ |

### 🔐 **CVE Research**
| Module | Description | Status |
|--------|-------------|--------|
| `search` | NVD API CVE search with exploit intelligence | ✅ 2026 |
| `monitor` | CVE monitoring with webhook notifications | ✅ |
| `pocs` | PoC exploit finder (GitHub + Nuclei) | ✅ |
| `chain` | CVE chain analysis & attack paths | ✅ |
| `patchdiff` | Git diff & commit security analysis | ✅ |

### ☁️ **Cloud Security**
| Module | Description | Status |
|--------|-------------|--------|
| `aws` | AWS metadata SSRF, S3 bucket enumeration | ✅ |
| `cloud` | AWS misconfig testing | ✅ |

### 🚀 **2026 Advanced Security** *(NEW)*
| Module | Description | Status |
|--------|-------------|--------|
| `llm` | LLM/AI security testing (prompt injection, SSRF via LLM, skill poisoning) | ✅ 2026 |
| `supplychain` | Supply chain security (TrapDoor campaign, typosquatting, MCP hijack) | ✅ 2026 |
| `race` | Race condition & business logic testing (double-spend, price manipulation) | ✅ 2026 |
| `smuggle` | HTTP smuggling & cache poisoning (CL.TE, TE.CL, web cache poisoning) | ✅ 2026 |
| `ssti` | Server-Side Template Injection (20+ engines: Jinja2, Twig, Freemarker, etc.) | ✅ 2026 |

---

<div align="center">

## 🚀 **INSTALLATION**

</div>

### 📋 **Prerequisites**
- 🐧 Linux (Kali, Ubuntu, Debian, etc.)
- 🐍 Python 3.10+
- 🔧 Go 1.21+

### 📦 **Install BountyKit**

```bash
# 🔹 Clone the repository
https://github.com/willygailo/W_RENAQETANA.git
cd W_RENAQETANA

# 🔹 Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 🔹 Install in development mode
pip install -e .
```

### 🛠️ **Setup External Tools**

```bash
# 🔹 Install all required external tools (subfinder, nuclei, sqlmap, etc.)
bountykit setup
```

### 🔗 **Make `bountykit` Available Everywhere**

After installing, you have three options to run `bountykit`:

| Option | Command | Best For |
|--------|---------|----------|
| **1️⃣** | `source .venv/bin/activate && bountykit --help` | Isolation |
| **2️⃣** | `./.venv/bin/bountykit --help` | Quick test |
| **3️⃣** | `export PATH="$HOME/bountykit/.venv/bin:$PATH"` | Permanent |

**Option 3 (Permanent):**
```bash
# 🔹 Add to your PATH permanently
echo 'export PATH="$HOME/bountykit/.venv/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

---

<div align="center">

## 🎮 **QUICK START**

</div>

```bash
# 🔹 1. Check legal authorization
bountykit legal -t example.com

# 🔹 2. Run full reconnaissance
bountykit recon full -t example.com -o ./results/recon

# 🔹 3. Scan for vulnerabilities
bountykit scan nuclei -t example.com -o ./results/scan

# 🔹 4. Search for CVEs
bountykit cve search -k "apache"

# 🔹 5. Run automated pipeline
bountykit pipeline -t example.com --scan-type full

# 🔹 6. Generate report
bountykit report -i ./results -f markdown -o report.md
```

---

<div align="center">

## 📋 **COMMANDS REFERENCE**

</div>

### 📊 **Main Commands Overview**

```text
bountykit
├── 📋 recon                    🔍 Reconnaissance commands
│   ├── passive              Passive DNS (crt.sh, DoH, CT logs)
│   ├── subdomains           Subdomain enumeration
│   ├── active               Host probing (httpx/naabu/nmap)
│   ├── js                   JavaScript analysis
│   ├── endpoints            Endpoint discovery
│   ├── crawl                Deep crawling (Katana/Gospider)
│   ├── iot                  IoT discovery (Shodan/Censys)
│   ├── mobile               Mobile app recon
│   └── full                 Full recon pipeline
│
├── 📋 scan                     🎯 Vulnerability scanning
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
├── 📋 cve                      🔐 CVE research
│   ├── search               Search CVE databases
│   ├── monitor              Monitor new CVEs
│   ├── pocs                 Find PoC exploits
│   ├── chain                CVE chain analysis
│   └── patchdiff            Patch diff analysis
│
├── 📋 cloud                    ☁️ Cloud security
│   └── aws                  AWS misconfig testing
│
├── 📋 advanced                 🚀 2026 Advanced security (NEW)
│   ├── llm                  LLM/AI security testing
│   ├── supplychain          Supply chain security
│   ├── race                 Race condition testing
│   ├── smuggle              HTTP smuggling & cache poisoning
│   ├── ssti                 SSTI detection (20+ engines)
│   └── cloud                Multi-cloud security
│
├── 📋 pipeline                 🤖 Automated pipeline
├── 📋 report                   📊 Report generation
├── 📋 setup                    ⚙️  Tool installation
└── 📋 legal                    ⚖️  Legal authorization
```

---

<div align="center">

## 💡 **USAGE EXAMPLES**

</div>

### 🔍 **Reconnaissance Commands**

#### 📡 Passive DNS Enumeration
```bash
# 🔹 Basic passive DNS scan
bountykit recon passive -t example.com

# 🔹 With custom output directory
bountykit recon passive -t example.com -o ./results/recon

# 🔹 Help
bountykit recon passive --help
```

**Output:**
```
📡 Starting passive DNS on example.com
  🔍 Querying CT logs...
  ✓ Found 15 subdomains from CT logs
  🔍 Querying DoH providers...
  ✓ Found 12 subdomains via DoH
  🧠 AI discovery found 50 potential subdomains
  💾 Results saved to ./results/recon/example.com_passive_dns.json
```

#### 🌐 Active Host Probing
```bash
# 🔹 Probe live hosts
bountykit recon active -t example.com

# 🔹 Help
bountykit recon active --help
```

#### 🔗 Subdomain Enumeration
```bash
# 🔹 Enumerate subdomains
bountykit recon subdomains -t example.com

# 🔹 Help
bountykit recon subdomains --help
```

#### 📜 Full Recon Pipeline
```bash
# 🔹 Run all recon modules
bountykit recon full -t example.com -o ./results/recon

# 🔹 Help
bountykit recon full --help
```

---

### 🎯 **Scanning Commands**

#### 🗄️ SQL Injection Testing
```bash
# 🔹 Test with SQLMap
bountykit scan sqli -u "https://example.com/page?id=1"

# 🔹 Test specific parameter
bountykit scan sqli -u "https://example.com/search?q=test" -p q

# 🔹 With advanced techniques (time-based, union, error-based, WAF bypass)
bountykit scan sqli -u "https://example.com/page?id=1" --techniques all

# 🔹 Help
bountykit scan sqli --help
```

#### 🔥 XSS Testing
```bash
# 🔹 Test with Dalfox
bountykit scan xss -u "https://example.com/search?q=test" -p q

# 🔹 With advanced techniques (DOM, mutation, CSP bypass)
bountykit scan xss -u "https://example.com/search?q=test" --techniques all

# 🔹 Help
bountykit scan xss --help
```

#### 🌐 SSRF Testing
```bash
# 🔹 Test for SSRF
bountykit scan ssrf -t "https://example.com/fetch?url=http://example.com" -p url

# 🔹 With 2026 techniques (DNS rebinding, IPv6 bypass, LLM-triggered)
bountykit scan ssrf -t "https://example.com/fetch?url=test" --techniques all

# 🔹 Help
bountykit scan ssrf --help
```

#### 🔌 API Security Testing
```bash
# 🔹 Test OWASP API Top 10
bountykit scan api -t https://api.example.com

# 🔹 With AI/Agentic API tests
bountykit scan api -t https://api.example.com --techniques all

# 🔹 Help
bountykit scan api --help
```

#### 🛡️ Nuclei Template Scanning
```bash
# 🔹 Scan with all templates
bountykit scan nuclei -t example.com

# 🔹 Scan with specific severity
bountykit scan nuclei -t example.com --severity critical,high

# 🔹 Help
bountykit scan nuclei --help
```

#### 🔐 GraphQL Security Testing
```bash
# 🔹 Test GraphQL endpoint
bountykit scan graphql -t https://example.com/graphql

# 🔹 Help
bountykit scan graphql --help
```

#### 🔑 OAuth/JWT Testing
```bash
# 🔹 Test OAuth flow
bountykit scan oauth -t https://example.com/auth/callback

# 🔹 Help
bountykit scan oauth --help
```

#### 🔄 Deserialization Testing
```bash
# 🔹 Test for deserialization
bountykit scan deserialization -t https://example.com/api

# 🔹 Help
bountykit scan deserialization --help
```

#### 🌍 Subdomain Takeover
```bash
# 🔹 Check for takeover
bountykit scan takeover -t example.com

# 🔹 Help
bountykit scan takeover --help
```

#### 📋 Security Headers Audit
```bash
# 🔹 Check security headers
bountykit scan headers -t https://example.com

# 🔹 Help
bountykit scan headers --help
```

#### 🛡️ WAF Detection & Bypass
```bash
# 🔹 Detect WAF
bountykit scan waf -t https://example.com

# 🔹 Help
bountykit scan waf --help
```

---

### 🔐 **CVE Research Commands**

#### 🔍 Search CVEs
```bash
# 🔹 Search by keyword
bountykit cve search -k "apache"

# 🔹 Search by CVE ID
bountykit cve search -k "CVE-2024-1234"

# 🔹 Search with exploit check
bountykit cve search -k "log4j" --exploits

# 🔹 Help
bountykit cve search --help
```

#### 📡 Monitor CVEs
```bash
# 🔹 Monitor new CVEs
bountykit cve monitor -k "apache" --webhook https://hooks.slack.com/xxx

# 🔹 Help
bountykit cve monitor --help
```

#### 💥 Find PoC Exploits
```bash
# 🔹 Find PoCs for CVE
bountykit cve pocs -k "CVE-2024-1234"

# 🔹 Help
bountykit cve pocs --help
```

---

### ☁️ **Cloud Security Commands**

#### 🔶 AWS Security Testing
```bash
# 🔹 Test AWS misconfigurations
bountykit cloud aws -t https://example.com

# 🔹 Help
bountykit cloud aws --help
```

#### 🌐 Multi-Cloud Scanner
```bash
# 🔹 Scan all clouds (AWS/GCP/Azure)
bountykit advanced cloud -t https://example.com

# 🔹 Help
bountykit advanced cloud --help
```

---

### 🚀 **2026 Advanced Commands** *(NEW)*

#### 🤖 LLM/AI Security Testing
```bash
# 🔹 Test LLM security
bountykit advanced llm -t https://chat.example.com -m gpt-4

# 🔹 Test specific attack
bountykit advanced llm -t https://chat.example.com -a prompt_injection

# 🔹 Test all attacks
bountykit advanced llm -t https://chat.example.com -a all

# 🔹 Help
bountykit advanced llm --help
```

**Attack Types:**
| Attack | Description |
|--------|-------------|
| `prompt_injection` | Direct and indirect prompt injection |
| `ssrf_via_llm` | SSRF through LLM tool calling |
| `tool_hijack` | Tool calling hijack exploitation |
| `model_extraction` | Model extraction attempts |
| `skill_poisoning` | Agent skill file poisoning |
| `all` | Run all attacks |

#### 📦 Supply Chain Security
```bash
# 🔹 Scan for malicious packages
bountykit advanced supplychain -d ./project

# 🔹 Check for typosquatting
bountykit advanced supplychain -d ./project --typosquatting

# 🔹 Help
bountykit advanced supplychain --help
```

#### ⏱️ Race Condition Testing
```bash
# 🔹 Test race conditions
bountykit advanced race -t https://api.example.com/checkout

# 🔹 Help
bountykit advanced race --help
```

#### 🚢 HTTP Smuggling & Cache Poisoning
```bash
# 🔹 Test HTTP smuggling
bountykit advanced smuggle -t https://example.com

# 🔹 Test cache poisoning
bountykit advanced smuggle -t https://example.com --cache-poisoning

# 🔹 Help
bountykit advanced smuggle --help
```

#### 🎨 Server-Side Template Injection
```bash
# 🔹 Test SSTI
bountykit advanced ssti -t https://example.com/page?name=test

# 🔹 Test specific engine
bountykit advanced ssti -t https://example.com/page --engine jinja2

# 🔹 Help
bountykit advanced ssti --help
```

**Supported Template Engines:**
| Engine | Language |
|--------|----------|
| Jinja2 | Python |
| Twig | PHP |
| Freemarker | Java |
| Velocity | Java |
| Mako | Python |
| Pug | Node.js |
| EJS | Node.js |
| Handlebars | Node.js |
| Nunjucks | Node.js |
| ERB | Ruby |
| JSP | Java |
| Thymeleaf | Java |
| MVEL | Java |
| SpEL | Java |
| OGNL | Java |

---

### 🤖 **Pipeline & Report Commands**

#### 🔄 Automated Pipeline
```bash
# 🔹 Run full pipeline
bountykit pipeline -t example.com --scan-type full

# 🔹 Run quick scan
bountykit pipeline -t example.com --scan-type quick

# 🔹 Run recon only
bountykit pipeline -t example.com --scan-type recon

# 🔹 Run scan only
bountykit pipeline -t example.com --scan-type scan

# 🔹 Run advanced scan
bountykit pipeline -t example.com --scan-type advanced

# 🔹 Help
bountykit pipeline --help
```

**Pipeline Scan Types:**
| Type | Description |
|------|-------------|
| `full` | Complete scan (recon + scan + CVE) |
| `quick` | Quick scan (essential checks only) |
| `recon` | Reconnaissance only |
| `scan` | Vulnerability scanning only |
| `cve` | CVE research only |
| `advanced` | 2026 advanced techniques |

#### 📊 Report Generation
```bash
# 🔹 Generate markdown report
bountykit report -i ./results -f markdown -o report.md

# 🔹 Generate JSON report
bountykit report -i ./results -f json -o report.json

# 🔹 Help
bountykit report --help
```

---

### ⚙️ **Setup & Legal Commands**

#### 🛠️ Setup Tools
```bash
# 🔹 Install all external tools
bountykit setup

# 🔹 Help
bountykit setup --help
```

#### ⚖️ Legal Authorization
```bash
# 🔹 Check legal authorization
bountykit legal -t example.com

# 🔹 Help
bountykit legal --help
```

---

### 📊 **Global Options**

| Option | Description |
|--------|-------------|
| `--version` | Show version |
| `-c, --config PATH` | Path to config file |
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Suppress non-essential output |
| `--help` | Show help message |

---

<div align="center">

## ⚠️ **DISCLAIMER**

</div>

> **🚨 IMPORTANT — READ BEFORE USE**

This tool is provided **"as is"** for **authorized security research and educational purposes only**.

By using **BountyKit**, you agree to the following:

| # | Rule |
|---|------|
| 1️⃣ | **🔍 Authorization Required** — You must have **explicit written permission** from the target system owner before running any scans or tests. |
| 2️⃣ | **📋 Bug Bounty Programs Only** — Only test targets that are explicitly listed in official bug bounty programs or under a signed penetration testing agreement. |
| 3️⃣ | **🚫 No Illegal Use** — This tool must **never** be used for unauthorized access, data theft, disruption, or any illegal activity. |
| 4️⃣ | **🛡️ Non-Destructive by Design** — All payloads are non-destructive (read-only). The tool will not modify, delete, or corrupt any data. |
| 5️⃣ | **📜 Compliance** — You are responsible for complying with all applicable local, national, and international laws and regulations. |
| 6️⃣ | **⚖️ No Liability** — The author assumes **no liability** for misuse of this tool. Use at your own risk and only against systems you are authorized to test. |

**If you do not agree to these terms, do not use this tool.**

---

<div align="center">

## 👤 **AUTHOR**

</div>

### **Willy Gailo**

<div align="center">

[![Facebook](https://img.shields.io/badge/Facebook-1877F2?style=for-the-badge&logo=facebook&logoColor=white)](https://www.facebook.com/willygailo)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/willygailo)

</div>

---

<div align="center">

## 🙏 **THANK YOU**

Thank you for using **BountyKit**! 🎉

If you found this tool helpful, consider giving it a ⭐ on GitHub — it means a lot!

### 🤝 **Contributions Welcome**

Feel free to open issues, submit pull requests, or suggest new features. Every contribution helps make this tool better for the security community.

---

**🛡️ Stay Legal. Stay Ethical. Hunt Responsibly. 🛡️**

Made with ❤️ by [Willy Gailo](https://github.com/willygailo)

---

*© 2026 BountyKit. MIT License.*

</div>
