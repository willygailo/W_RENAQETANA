<p align="center">
  <img src="https://img.shields.io/badge/version-0.2.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-brightgreen" alt="Python">
  <img src="https://img.shields.io/badge/license-Apache%202.0-red" alt="License">
  <img src="https://img.shields.io/badge/status-production--ready-orange" alt="Status">
</p>

<h1 align="center">
  <b>BountyKit</b>
  <br>
  <sub>Advanced Bug Bounty & CVE Research Framework</sub>
</h1>

<p align="center">
  <b>One CLI. Every attack. Production-grade.</b>
</p>

<p align="center">
  <code>pip install bountykit</code> &nbsp;·&nbsp; <code>docker pull bountykit:latest</code> &nbsp;·&nbsp; <code>bountykit --help</code>
</p>

---

> **Disclaimer:** BountyKit is an authorized security research tool. You **must** have explicit written permission before scanning any target. Unauthorized use is illegal and punishable under computer crime laws. See [LICENSE](LICENSE) and [LEGAL](LEGAL.md) for full terms.

---

## Why BountyKit?

| Feature | Other Tools | BountyKit |
|---|---|---|
| Attack surface | 3–5 scanners | **22+ modules** covering network, cloud, LLM, supply chain, smuggling, SSTI, race conditions, WAF bypass |
| CVE intelligence | Basic lookup | **Real-world exploit chains** with graph-based engine and CVSS scoring |
| Cloud security | One provider | **AWS, Azure, GCP, Kubernetes, Firebase** — multi-provider scanning |
| Pipeline engine | Manual runs | **Phase-based pipeline**, async concurrency, resume from crash |
| Rate limiting | Simple delay | **Token bucket + sliding window** per-target with DoH fallback |
| Output | Plain text | **JSON, Markdown, HTML** — structured reports |

---

## Install

```bash
# PyPI
pip install bountykit

# From source
git clone https://github.com/willygailo/bountykit.git
cd bountykit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Docker

```bash
docker build -t bountykit .
docker run bountykit scan xss --target https://example.com

# Run as non-root (default)
docker run --rm bountykit version
```

### Nuclei Integration (optional)

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

---

## Quick Start

```bash
# 1. Run the full pipeline against a target
bountykit pipeline --target https://example.com --scan-type full

# 2. Scan for a specific vulnerability
bountykit scan ssti --target https://example.com

# 3. Search CVEs
bountykit cve search --keyword "nginx" --severity CRITICAL

# 4. Check AWS misconfigurations
bountykit cloud aws --metadata

# 5. Generate a report
bountykit report --format html --input ./results
```

---

## All Commands

### Scanners (`bountykit scan`)

| Command | Description |
|---|---|
| `scan xss` | Reflected, stored, and DOM-based XSS detection |
| `scan sqli` | SQL injection with time-based, boolean, and error-based payloads |
| `scan ssrf` | Server-side request forgery with DNS rebinding |
| `scan ssti` | Server-side template injection — polyglot probes, blind time-delay, RCE confirm |
| `scan graphql` | GraphQL introspection, batching, and injection |
| `scan api` | REST API fuzzing and parameter discovery |
| `scan oauth` | OAuth 2.0 / OIDC misconfiguration and token abuse |
| `scan network` | Port scanning, service enumeration, TLS analysis |
| `scan headers` | Security header audit and missing HSTS/CSP detection |
| `scan deserialization` | Java, Python, PHP, .NET deserialization gadget detection |
| `scan takeover` | Subdomain takeover across 72 services with DoH fallback |
| `scan smuggling` | HTTP/2 smuggling, fat GET, absolute form, differential |
| `scan race` | Race conditions — HTTP/2 single-packet, GraphQL batch, JWT race |
| `scan waf` | WAF detection + 15 bypass techniques |
| `scan supply-chain` | Dependency confusion, typosquatting, GHA composite hijack |
| `scan llm` | Prompt injection, RAG poisoning, tool abuse, multi-turn chains |
| `scan cloud-misconfig` | AWS/Azure/GCP/K8s/Firebase/Lambda/Docker scanning |
| `scan template` | Custom vulnerability template builder |

### CVE Intelligence (`bountykit cve`)

| Command | Description |
|---|---|
| `cve search` | Search CVEs with keyword, severity, vendor, date filters |
| `cve chain` | Build exploit chains with graph engine and CVSS scoring |
| `cve exploit-db` | Pull exploits from Exploit-DB and GitHub |
| `cve diff` | Patch diff analysis to find fixable vulnerabilities |

### Cloud Security (`bountykit cloud`)

| Command | Description |
|---|---|
| `cloud aws` | Test AWS misconfigurations (SSRF to metadata, S3 bucket enumeration) |

### Reconnaissance (`bountykit recon`)

| Command | Description |
|---|---|
| `recon passive` | Passive OSINT — certificate transparency, DNS, WHOIS |
| `recon active` | Active enumeration — subdomains, ports, technologies |
| `recon subdomains` | Subdomain discovery via DoH, wordlists, permutation |
| `recon js` | JavaScript file analysis — endpoint extraction, secret detection |
| `recon endpoints` | API endpoint discovery from JS, robots.txt, sitemap |
| `recon crawl` | Deep crawler with JavaScript rendering |
| `recon iot` | IoT device discovery (UPnP, MQTT, CoAP) |
| `recon mobile` | Mobile app analysis (APK extraction, deeplinks) |
| `recon full` | Full recon — combines all recon modules |

### Pipeline Engine (`bountykit pipeline`)

| Flag | Description |
|---|---|
| `--target` / `-t` | Target URL (required) |
| `--output` / `-o` | Output directory (default: `./results`) |
| `--scan-type` | `full`, `quick`, `recon`, `scan`, `cve`, `advanced` |
| `--no-parallel` | Disable parallel execution |
| `--resume` | Resume a crashed run from state file |

### Advanced Testing (`bountykit advanced`)

| Command | Description |
|---|---|
| `advanced llm` | LLM/AI security — prompt injection, RAG poisoning, tool abuse |
| `advanced supplychain` | Supply chain — dependency confusion, typosquatting, GHA hijack |
| `advanced race` | Race conditions — HTTP/2 single-packet, GraphQL batch |
| `advanced smuggle` | HTTP smuggling — CL.TE, TE.CL, TE.TE, cache poisoning |
| `advanced ssti` | SSTI — polyglot probes, blind time-delay, RCE confirm |
| `advanced cloud` | Cloud misconfig — multi-provider scanner |

### Utility Commands

| Command | Description |
|---|---|
| `setup` | Install and verify all external tools (nuclei, subfinder, nmap) |
| `version` | Show version and check external tools |
| `config show` | View current configuration |
| `config set <key> <value>` | Set config value (e.g., `scan.threads 20`) |
| `report` | Generate report from scan results (markdown/json/html) |
| `report-generate` | Alias for report generation |
| `legal` | Check legal authorization for a target |
| `validate-license` | Verify LICENSE file and legal gate |
| `check-updates` | Check PyPI for new version |

---

## Reports

```bash
bountykit report --format json --input ./results --output report.json
bountykit report --format markdown --input ./results --output report.md
bountykit report --format html --input ./results --output report.html
```

---

## Configuration

```bash
bountykit config show                    # View current config
bountykit config set scan.threads 20     # Scanning threads
bountykit config set scan.timeout 30     # Request timeout (seconds)
bountykit config set legal.rate_limit 5  # Requests per second
```

---

## Development

```bash
git clone https://github.com/willygailo/bountykit.git
cd bountykit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest tests/ -v
```

### Project Layout

```
bountykit/
├── cli.py
├── config.py
├── pipeline.py
├── scan/       # Vulnerability scanners
├── cve/        # CVE intelligence
├── cloud/      # Cloud misconfiguration
├── recon/      # Reconnaissance
└── utils/      # Reports, logging, legal
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `httpx` | Async HTTP client with HTTP/2 support |
| `click` | CLI framework |
| `rich` | Terminal output, progress bars, tables |
| `pydantic` | Data validation and settings |
| `pydantic-settings` | Environment-based configuration |
| `tenacity` | Retry logic with exponential backoff |
| `pyyaml` | Configuration and template parsing |
| `jinja2` | Report template rendering |
| `networkx` | CVE chain graph engine (optional) |
| `h2` | HTTP/2 smuggling and single-packet attack (optional) |

---

## License

**Apache License 2.0** — see [LICENSE](LICENSE).

---

<p align="center">
  Built by <a href="https://www.facebook.com/https.willy.jr.carnasa.gailo2026.2027">Willy Carnasa Gailo</a> ·
  <a href="https://github.com/willygailo">GitHub</a>
</p>
