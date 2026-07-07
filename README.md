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
git clone https://github.com/willygailo/W_RENAQETANA.git
cd W_RENAQETANA
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 🛠️ **Setup External Tools**

```bash
bountykit setup
```

### 🔗 **Make `bountykit` Available Everywhere**

```bash
echo 'export PATH="$HOME/W_RENAQETANA/.venv/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

---

<div align="center">

## 🎮 **QUICK START**

</div>

```bash
# Check legal authorization
bountykit legal -t example.com

# Run full reconnaissance
bountykit recon full -t example.com -o ./results

# Scan for vulnerabilities with Nuclei
bountykit scan nuclei -t example.com -s critical,high

# Search for CVEs
bountykit cve search -k "apache log4j"

# Run automated pipeline
bountykit pipeline -t example.com --scan-type full

# Generate report
bountykit report -i ./results -f markdown -o report.md
```

---

<div align="center">

## 📋 **COMMANDS REFERENCE**

</div>

### 📊 **Main Commands Overview**

```text
bountykit
├── recon                    🔍 Reconnaissance commands
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
├── scan                     🎯 Vulnerability scanning
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
├── cve                      🔐 CVE research
│   ├── search               Search CVE databases
│   ├── monitor              Monitor new CVEs
│   ├── pocs                 Find PoC exploits
│   ├── chain                CVE chain analysis
│   └── patchdiff            Patch diff analysis
│
├── cloud                    ☁️ Cloud security
│   └── aws                  AWS misconfig testing
│
├── advanced                 🚀 Advanced security (2026)
│   ├── llm                  LLM/AI security testing
│   ├── supplychain          Supply chain security
│   ├── race                 Race condition testing
│   ├── smuggle              HTTP smuggling & cache poisoning
│   ├── ssti                 SSTI detection (20+ engines)
│   └── cloud                Multi-cloud security
│
├── pipeline                 🤖 Automated pipeline
├── report                   📊 Report generation
├── setup                    ⚙️  Tool installation
└── legal                    ⚖️  Legal authorization
```

---

<div align="center">

## 💡 **USAGE EXAMPLES**

</div>

### 🔍 **Reconnaissance Commands**

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
bountykit recon mobile -t example.com
```

#### 📜 Full Recon Pipeline
```bash
bountykit recon full -t example.com -o ./results
bountykit recon full -t example.com -o ./results --brute
bountykit recon full -t example.com -o ./results --brute --full
```

---

### 🎯 **Scanning Commands**

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

---

### 🔐 **CVE Research Commands**

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
bountykit cve monitor -k "apache" --webhook https://hooks.slack.com/xxx
```

#### 💥 Find PoC Exploits
```bash
bountykit cve pocs -k "CVE-2024-1234"
```

#### 🔗 CVE Chain Analysis
```bash
bountykit cve chain -k "CVE-2024-1234"
```

#### 📋 Patch Diff Analysis
```bash
bountykit cve patchdiff -k "CVE-2024-1234"
```

---

### ☁️ **Cloud Security Commands**

#### 🔶 AWS Security Testing
```bash
bountykit cloud aws -b my-bucket
bountykit cloud aws --metadata
```

#### 🌐 Multi-Cloud Scanner
```bash
bountykit advanced cloud -t https://example.com
```

---

### 🚀 **2026 Advanced Commands** *(NEW)*

#### 🤖 LLM/AI Security Testing
```bash
bountykit advanced llm -t https://chat.example.com -m gpt-4
bountykit advanced llm -t https://chat.example.com -a prompt_injection
bountykit advanced llm -t https://chat.example.com -a all
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
bountykit advanced supplychain -t https://github.com/user/repo
bountykit advanced supplychain -t https://github.com/user/repo -a typosquatting
bountykit advanced supplychain -t https://github.com/user/repo -a all
```

**Attack Types:**
| Attack | Description |
|--------|-------------|
| `malicious_packages` | Scan for malicious dependencies |
| `typosquatting` | Check for typosquatting packages |
| `ci_cd` | CI/CD pipeline security |
| `mcp_hijack` | MCP server hijack |
| `skill_poisoning` | Agent skill poisoning |
| `all` | Run all checks |

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

**Attack Types:**
| Attack | Description |
|--------|-------------|
| `cl_te` | Content-Length / Transfer-Encoding |
| `te_cl` | Transfer-Encoding / Content-Length |
| `te_te` | Transfer-Encoding / Transfer-Encoding |
| `cache_poison` | Web cache poisoning |
| `host_injection` | Host header injection |
| `all` | Run all attacks |

#### 🎨 Server-Side Template Injection
```bash
bountykit advanced ssti -t "https://example.com/page?name=test"
bountykit advanced ssti -t "https://example.com/page" -e jinja2
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
bountykit pipeline -t example.com --scan-type full
bountykit pipeline -t example.com --scan-type quick
bountykit pipeline -t example.com --scan-type recon
bountykit pipeline -t example.com --scan-type scan
bountykit pipeline -t example.com --scan-type cve
bountykit pipeline -t example.com --scan-type advanced
bountykit pipeline -t example.com --scan-type full --no-parallel
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
bountykit report -i ./results -f markdown -o report.md
bountykit report -i ./results -f json -o report.json
```

---

### ⚙️ **Setup & Legal Commands**

#### 🛠️ Setup Tools
```bash
bountykit setup
```

#### ⚖️ Legal Authorization
```bash
bountykit legal -t example.com
bountykit legal -t example.com -s ./scope.txt
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
