# Plan: Advanced Open-Source Legal CLI for Bug Bounty & CVE Research

## Project Name: `bountykit`

## Overview
A comprehensive, open-source CLI tool for authorized bug bounty hunting and CVE research on Linux. Automates reconnaissance, vulnerability scanning, CVE monitoring, and reporting — all within legal and ethical boundaries.

## Architecture

```
bountykit/
├── bountykit.py              # Main entry point (Python 3.10+)
├── bountykit/
│   ├── __init__.py
│   ├── cli.py                # Click/Typer CLI framework
│   ├── config.py             # Configuration management
│   ├── recon/                # Reconnaissance modules
│   │   ├── __init__.py
│   │   ├── passive.py        # WHOIS, DNS, CT, BGP/ASN
│   │   ├── active.py         # Nmap, masscan wrappers
│   │   ├── subdomain.py      # Subdomain enumeration
│   │   ├── gosint.py         # Google dorking, GitHub secrets
│   │   └── archive.py        # Wayback, GAU, URL collection
│   ├── scan/                 # Vulnerability scanning
│   │   ├── __init__.py
│   │   ├── web.py            # Nuclei, Nikto wrappers
│   │   ├── sqli.py           # SQLMap integration
│   │   ├── xss.py            # Dalfox integration
│   │   ├── ssrf.py           # SSRF testing
│   │   ├── api.py            # API security testing
│   │   └── graphql.py        # GraphQL attacks
│   ├── cve/                  # CVE research
│   │   ├── __init__.py
│   │   ├── monitor.py        # NVD API monitoring
│   │   ├── search.py         # CVE search & filter
│   │   └── exploit_db.py     # Exploit-DB integration
│   ├── cloud/                # Cloud security
│   │   ├── __init__.py
│   │   ├── aws.py            # AWS misconfiguration
│   │   ├── gcp.py            # GCP misconfiguration
│   │   └── azure.py          # Azure misconfiguration
│   ├── report/               # Report generation
│   │   ├── __init__.py
│   │   ├── markdown.py       # Markdown reports
│   │   ├── cvss.py           # CVSS calculator
│   │   └── templates/        # Report templates
│   ├── utils/                # Utilities
│   │   ├── __init__.py
│   │   ├── logger.py         # Logging
│   │   ├── validator.py      # Input validation
│   │   ├── legal.py          # Legal compliance checks
│   │   └── installer.py      # Tool dependency installer
│   └── data/                 # Static data
│       ├── wordlists/        # DNS, directory wordlists
│       ├── nuclei-templates/ # Custom templates
│       └── cve-feeds/        # CVE monitoring configs
├── setup.py
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE                   # MIT License
└── tests/
    ├── test_recon.py
    ├── test_scan.py
    └── test_cve.py
```

## Core Features

### 1. Reconnaissance Module
| Feature | Description | Tools Wrapped |
|---------|-------------|---------------|
| Passive DNS | WHOIS, CT logs, BGP/ASN | whois, dnsx, curl |
| Subdomain Enum | Multi-source passive + brute | subfinder, amass, puredns |
| Host Probing | Live detection + tech fingerprint | httpx, gowitness |
| Port Scanning | Full port + service detection | nmap, naabu, masscan |
| URL Collection | Wayback, CommonCrawl, crawling | gau, katana, hakrawler |
| JS Analysis | Secret extraction, endpoint find | grep, nuclei, linkfinder |

### 2. Vulnerability Scanning Module
| Feature | Description | Tools Wrapped |
|---------|-------------|---------------|
| Web Fuzzing | Directory, file, param fuzzing | ffuf, feroxbuster |
| Template Scanning | CVE, misconfig detection | nuclei |
| SQLi Testing | Automated injection | sqlmap |
| XSS Testing | Reflected, stored, DOM | dalfox |
| SSRF Testing | OOB detection | interactsh, curl |
| API Testing | REST, GraphQL, auth bypass | nuclei, arjun, jwt_tool |

### 3. CVE Research Module
| Feature | Description | Source |
|---------|-------------|--------|
| CVE Monitor | Daily new CVE alerts | NVD API 2.0 |
| CVE Search | Filter by tech, severity, date | NVD, MITRE |
| PoC Finder | GitHub PoC repository search | GitHub API |
| Patch Diff | Source code diff analysis | git |
| Exploit DB | Exploit-DB search | exploit-db.com |

### 4. Cloud Security Module
| Feature | Description | Target |
|---------|-------------|--------|
| S3 Enumeration | Public bucket discovery | AWS S3 |
| Metadata SSRF | Cloud metadata access | AWS/GCP/Azure |
| IAM Enumeration | Role/policy discovery | AWS IAM |
| Storage Scanning | Public bucket content | GCS, Azure Blob |

### 5. Reporting Module
| Feature | Description | Output |
|---------|-------------|--------|
| Auto Reports | Structured vulnerability reports | Markdown |
| CVSS Calculator | CVSS v3.1 score calculation | Terminal |
| PoC Templates | Safe proof-of-concept commands | Markdown |
| Executive Summary | High-level findings overview | Markdown/HTML |

### 6. Legal Compliance
| Feature | Description |
|---------|-------------|
| Scope Checker | Validate target against bug bounty scope |
| Authorization Gate | Require written permission confirmation |
| Safe Payloads | Non-destructive PoC only |
| Audit Logging | Log all actions for accountability |
| Rate Limiting | Respect target rate limits |

## CLI Commands

```bash
# Full recon pipeline
bountykit recon --target example.com --output ./results

# Subdomain enumeration
bountykit recon subdomains --target example.com --brute

# Port scanning
bountykit recon ports --target example.com --full

# Vulnerability scanning
bountykit scan --target https://example.com --severity high,critical

# SQL injection testing
bountykit scan sqli --url "https://example.com?id=1"

# XSS testing
bountykit scan xss --url "https://example.com/search?q=test"

# CVE monitoring
bountykit cve monitor --tech wordpress,apache --notify slack

# CVE search
bountykit cve search --keyword "log4j" --year 2024

# Cloud security
bountykit cloud aws --bucket target-backups

# Generate report
bountykit report --input ./results --format markdown

# Install dependencies
bountykit setup

# Legal compliance check
bountykit legal --scope scope.txt --target example.com
```

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
1. Project scaffolding with pyproject.toml
2. CLI framework with Click/Typer
3. Configuration management (~/.bountykit/config.yaml)
4. Logging and output formatting
5. Legal compliance gate

### Phase 2: Reconnaissance (Week 3-4)
1. Passive DNS module
2. Subdomain enumeration (subfinder, amass, puredns)
3. Host probing (httpx)
4. Port scanning (nmap, naabu)
5. URL collection (gau, katana)

### Phase 3: Vulnerability Scanning (Week 5-6)
1. Nuclei integration
2. SQLMap wrapper
3. Dalfox XSS integration
4. SSRF testing with interactsh
5. API security testing

### Phase 4: CVE Research (Week 7)
1. NVD API 2.0 integration
2. CVE search and filtering
3. GitHub PoC discovery
4. Patch diff analysis

### Phase 5: Cloud & Reporting (Week 8)
1. AWS S3 enumeration
2. Cloud metadata SSRF
3. Report generation (Markdown)
4. CVSS calculator

## Dependencies

### Python Packages
```
click>=8.0
rich>=13.0
pyyaml>=6.0
requests>=2.28
pydantic>=2.0
jinja2>=3.0
```

### External Tools (Auto-installed)
```bash
# Go tools
subfinder, httpx, nuclei, katana, ffuf, dalfox, naabu,
dnsx, gau, anew, interactsh, gowitness, feroxbuster,
waybackurls, qsreplace, hakrawler, kiterunner, arjun

# System tools
nmap, nikto, sqlmap, masscan, wpscan

# Python tools
trufflehog, shodan
```

## Legal & Ethical Safeguards

1. **Authorization Gate**: Every scan requires `--authorized` flag or config confirmation
2. **Scope Validation**: Cross-reference targets against known bug bounty scopes
3. **Safe Payloads**: Only non-destructive PoC commands (id, whoami, sleep)
4. **Rate Limiting**: Built-in delays between requests
5. **Audit Trail**: Log all actions to `~/.bountykit/audit.log`
6. **Disclaimer**: Clear warnings before every scan

## Success Criteria

- [ ] All 24 sections from ADVANCED_BUGBOUNTY_CVE.md accessible via CLI
- [ ] Automated dependency installation
- [ ] Legal compliance checks enforced
- [ ] Structured output (JSON, Markdown)
- [ ] Comprehensive error handling
- [ ] Full test coverage
- [ ] Clean, well-documented code
- [ ] MIT License for open-source distribution
