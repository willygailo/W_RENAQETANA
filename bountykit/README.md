<div align="center">

# 🛡️ **BOUNTYKIT**

### *Advanced Open-Source Legal CLI for Bug Bounty & CVE Research*

---

![Version](https://img.shields.io/badge/version-0.1.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Linux-000000?style=for-the-badge&logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)

---

**One CLI to rule them all.** 🗡️

Recon → Scan → CVE → Cloud → Report — everything you need for authorized security research, unified in a single, powerful command-line tool.

---

## 📑 **TABLE OF CONTENTS**

- [About](#-about)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Commands](#-commands)
- [Disclaimer](#-disclaimer)
- [Author](#-author)
- [Thank You](#-thank-you)

---

## 📖 **ABOUT**

**BountyKit** is a comprehensive, open-source CLI tool built for Linux-based bug bounty hunters and CVE researchers. It brings together **20+ modules** covering every phase of a security engagement — from passive reconnaissance to vulnerability scanning, CVE research, and report generation.

> ⚠️ **BountyKit is built for authorized security research only.** Always obtain written permission before testing any target.

---

## ✨ **FEATURES**

### 🔍 **Reconnaissance**
| Module | Description |
|--------|-------------|
| `passive` | Passive DNS enumeration via crt.sh |
| `subdomains` | Subdomain discovery with Subfinder + DNS brute-force |
| `active` | Host probing via httpx, naabu, nmap |
| `js` | JavaScript file analysis — secrets, DOM XSS, endpoints |
| `endpoints` | Endpoint discovery — Waybackurls, Arjun, ParamSpider |
| `crawl` | Deep crawling — Katana + Gospider |
| `iot` | IoT/infrastructure discovery — Shodan, Censys |
| `mobile` | Mobile app recon — APK/IPA analysis |

### 🎯 **Vulnerability Scanning**
| Module | Description |
|--------|-------------|
| `nuclei` | Nuclei template-based scanning |
| `sqli` | SQLMap wrapper for SQL injection |
| `xss` | Dalfox XSS scanner |
| `ssrf` | Server-Side Request Forgery testing |
| `api` | OWASP API Top 10 testing |
| `graphql` | GraphQL introspection, batching, DoS |
| `oauth` | OAuth redirect manipulation & JWT analysis |
| `deserialization` | Java/PHP/.NET deserialization detection |
| `takeover` | Subdomain takeover — 50+ service fingerprints |
| `headers` | Security headers, cookies, CSP audit |
| `waf` | WAF detection & bypass testing |

### 🔐 **CVE Research**
| Module | Description |
|--------|-------------|
| `search` | NVD API CVE search |
| `monitor` | CVE monitoring with webhook notifications |
| `pocs` | PoC exploit finder (GitHub + Nuclei) |
| `chain` | CVE chain analysis & attack paths |
| `patchdiff` | Git diff & commit security analysis |

### ☁️ **Cloud Security**
| Module | Description |
|--------|-------------|
| `aws` | AWS metadata SSRF, S3 bucket enumeration |

---

## 🚀 **INSTALLATION**

### Prerequisites
- Linux (Kali, Ubuntu, Debian, etc.)
- Python 3.10+
- Go 1.21+

### Install

```bash
# Clone the repository
git clone https://github.com/willygailo/bountykit.git
cd bountykit

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e .
```

### Make `bountykit` Available Everywhere

After installing, you have three options to run `bountykit`:

**Option 1:** Activate the virtualenv each time (recommended for isolation):
```bash
cd bountykit
source .venv/bin/activate
bountykit --help
```

**Option 2:** Run directly with the full path:
```bash
./bountykit/.venv/bin/bountykit --help
```

**Option 3:** Add to your PATH permanently (most convenient):
```bash
echo 'export PATH="$HOME/path-to-bountykit/.venv/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```
Replace `$HOME/path-to-bountykit` with the actual path to your bountykit directory.

### Setup External Tools

```bash
# Install all required external tools (subfinder, nuclei, sqlmap, etc.)
bountykit setup
```

---

## 🎮 **QUICK START**

```bash
# 1. Check legal authorization
bountykit legal -t example.com

# 2. Run full reconnaissance
bountykit recon full -t example.com -o ./results/recon

# 3. Scan for vulnerabilities
bountykit scan nuclei -t example.com -o ./results/scan

# 4. Search for CVEs
bountykit cve search -k "apache"

# 5. Run automated pipeline
bountykit pipeline -t example.com --scan-type full

# 6. Generate report
bountykit report -i ./results -f markdown -o report.md
```

---

## 📋 **COMMANDS**

```text
bountykit
├── recon                    🔍 Reconnaissance commands
│   ├── passive              Passive DNS (crt.sh)
│   ├── subdomains           Subdomain enumeration
│   ├── active               Host probing (httpx/naabu/nmap)
│   ├── js                   JavaScript analysis
│   ├── endpoints            Endpoint discovery
│   ├── crawl                Deep crawling (Katana/Gospider)
│   ├── iot                  IoT discovery (Shodan/Censys)
│   ├── mobile               Mobile app recon
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
├── pipeline                 🤖 Automated pipeline
├── report                   📊 Report generation
├── setup                    ⚙️  Tool installation
└── legal                    ⚖️  Legal authorization
```

---

## ⚖️ **DISCLAIMER**

> **IMPORTANT — READ BEFORE USE**

This tool is provided **"as is"** for **authorized security research and educational purposes only**.

By using **BountyKit**, you agree to the following:

1. **🔍 Authorization Required** — You must have **explicit written permission** from the target system owner before running any scans or tests.

2. **📋 Bug Bounty Programs Only** — Only test targets that are explicitly listed in official bug bounty programs or under a signed penetration testing agreement.

3. **🚫 No Illegal Use** — This tool must **never** be used for unauthorized access, data theft, disruption, or any illegal activity.

4. **🛡️ Non-Destructive by Design** — All payloads are non-destructive (read-only). The tool will not modify, delete, or corrupt any data.

5. **📜 Compliance** — You are responsible for complying with all applicable local, national, and international laws and regulations.

6. **⚖️ No Liability** — The author assumes **no liability** for misuse of this tool. Use at your own risk and only against systems you are authorized to test.

**If you do not agree to these terms, do not use this tool.**

---

## 👤 **AUTHOR**

### **Willy Gailo**

![Facebook](https://img.shields.io/badge/Facebook-1877F2?style=for-the-badge&logo=facebook&logoColor=white)
[![Profile](https://img.shields.io/badge//facebook-https.willy.jr.carnasa.gailo2026.2027-1877F2?style=for-the-badge)](https://www.facebook.com/https.willy.jr.carnasa.gailo2026.2027)

![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)
[![Profile](https://img.shields.io/badge/willygailo-100000?style=for-the-badge)](https://github.com/willygailo)

---

## 🙏 **THANK YOU**

Thank you for using **BountyKit**! 🎉

If you found this tool helpful, consider giving it a ⭐ on GitHub — it means a lot!

### 🤝 **Contributions Welcome**

Feel free to open issues, submit pull requests, or suggest new features. Every contribution helps make this tool better for the security community.

### 📬 **Get In Touch**

- **Facebook:** [Willy Gailo](https://www.facebook.com/https.willy.jr.carnasa.gailo2026.2027)
- **GitHub:** [willygailo](https://github.com/willygailo)

---

<div align="center">

**🛡️ Stay Legal. Stay Ethical. Hunt Responsibly. 🛡️**

Made with ❤️ by [Willy Gailo](https://github.com/willygailo)

---

*© 2026 BountyKit. MIT License.*

</div>
