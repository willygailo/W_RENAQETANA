"""Main CLI entry point for bountykit."""

import asyncio
import sys
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bountykit import __version__
from bountykit.config import Config
from bountykit.utils.logger import setup_logger

console = Console()

BANNER = """[bold red]
 ____  _ _ _  __ _  __ _  ___| |_ __ _ _ __   __ _ 
| __ )| | ' \\/ _` |/ _` |/ _ \\ __/ _` | '_ \\ / _` |
|  _ \\| | | | |_| | (_| |  __/ || (_| | | | | (_| |
|_| \\_\\_|_|_|\\__,_|\\__, |\\___|\\__\\__,_|_| |_|\\__, |
                     |___/                      |___/[/bold red]
[dim]v{version} — Advanced Bug Bounty & CVE Research CLI[/dim]
[dim]For authorized security research only.[/dim]
"""


def _legal_check(cfg, target):
    """Common legal gate check — exits on failure."""
    if not cfg.legal.gate_check(target):
        console.print("[bold red]ERROR: Legal compliance check failed.[/bold red]")
        console.print("[yellow]Ensure you have written authorization to test this target.[/yellow]")
        sys.exit(1)


@click.group()
@click.version_option(__version__, prog_name="bountykit")
@click.option("--config", "-c", type=click.Path(), default=None, help="Path to config file")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
@click.pass_context
def main(ctx, config, verbose, quiet):
    """bountykit — Advanced open-source legal CLI for bug bounty and CVE research.

    For authorized penetration testing and bug bounty programs only.
    Always stay within scope. Never test without written permission.
    """
    ctx.ensure_object(dict)
    ctx.obj["config"] = Config.load(config)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    setup_logger(verbose=verbose, quiet=quiet)

    if not quiet:
        console.print(BANNER.format(version=__version__))


# =============================================================================
# RECON COMMANDS
# =============================================================================

@main.group()
def recon():
    """Reconnaissance commands (passive, active, deep)."""
    pass


@recon.command("passive")
@click.option("--target", "-t", required=True, help="Target domain")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def recon_passive(ctx, target, output):
    """Passive DNS enumeration (crt.sh, DNS lookup)."""
    from bountykit.recon.passive import passive_dns
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Passive DNS: {target}[/bold cyan]\n")
    passive_dns(target, output)


@recon.command("subdomains")
@click.option("--target", "-t", required=True, help="Target domain")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--brute", is_flag=True, help="Include DNS brute-force")
@click.pass_context
def recon_subdomains(ctx, target, output, brute):
    """Subdomain enumeration via subfinder + DNS brute-force."""
    from bountykit.recon.subdomain import enumerate_subdomains
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Subdomain enumeration: {target}[/bold cyan]\n")
    enumerate_subdomains(target, output, brute=brute)


@recon.command("active")
@click.option("--target", "-t", required=True, help="Target domain")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--full", is_flag=True, help="Full port scan (all 65535 ports)")
@click.pass_context
def recon_active(ctx, target, output, full):
    """Active probing (httpx, naabu, nmap)."""
    from bountykit.recon.active import probe_hosts, scan_ports
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Active probing: {target}[/bold cyan]\n")
    probe_hosts(target, output)
    scan_ports(target, output, full=full)


@recon.command("js")
@click.option("--target", "-t", required=True, help="Target domain or URL")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--depth", "-d", default=2, type=int, help="Link-follow depth (0-3)")
@click.option("--secrets", is_flag=True, help="Only run secret extraction")
@click.option("--endpoints", is_flag=True, help="Only run endpoint extraction")
@click.option("--dom-xss", is_flag=True, help="Only run DOM XSS hunting")
@click.option("--all", "run_all", is_flag=True, help="Run all JS analysis tasks")
@click.pass_context
def recon_js(ctx, target, output, depth, secrets, endpoints, dom_xss, run_all):
    """Deep JavaScript analysis (secrets, DOM XSS, endpoints)."""
    from bountykit.recon.js_analysis import discover_js_files, extract_secrets, hunt_dom_xss, extract_endpoints
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]JS Analysis: {target}[/bold cyan]\n")

    discover_js_files(target, output)

    do_all = run_all or (not secrets and not endpoints and not dom_xss)
    if do_all or secrets:
        extract_secrets(target, output)
    if do_all or dom_xss:
        hunt_dom_xss(target, output)
    if do_all or endpoints:
        extract_endpoints(target, output)

    console.print(f"\n[bold green]JS analysis complete![/bold green]\n")


@recon.command("endpoints")
@click.option("--target", "-t", required=True, help="Target domain")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def recon_endpoints(ctx, target, output):
    """Discover endpoints (Wayback, Arjun, ParamSpider)."""
    from bountykit.recon.endpoints import discover_all_endpoints
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Endpoint discovery: {target}[/bold cyan]\n")
    discover_all_endpoints(target, output)


@recon.command("crawl")
@click.option("--target", "-t", required=True, help="Target URL to crawl")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--depth", "-d", default=2, type=int, help="Crawl depth (1-5)")
@click.option("--javascript", is_flag=True, help="Also run Gospider JS-heavy crawl")
@click.pass_context
def recon_crawl(ctx, target, output, depth, javascript):
    """Deep crawling with Katana and Gospider."""
    from bountykit.recon.crawler import crawl_katana, crawl_deep
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Deep crawl: {target}[/bold cyan]\n")
    if javascript:
        crawl_deep(target, depth=depth, output_dir=output)
    else:
        crawl_katana(target, output_dir=output, depth=depth)


@recon.command("iot")
@click.option("--target", "-t", required=True, help="Target IP or domain")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def recon_iot(ctx, target, output):
    """IoT/infrastructure discovery via Shodan and Censys."""
    from bountykit.recon.iot import discover_iot
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]IoT discovery: {target}[/bold cyan]\n")
    discover_iot(target, output)


@recon.command("mobile")
@click.option("--apk", required=True, help="Path to APK file")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def recon_mobile(ctx, apk, output):
    """Mobile app recon (APK/IPA analysis, secrets, endpoints)."""
    from bountykit.recon.mobile import analyze_apk
    console.print(f"\n[bold cyan]Mobile analysis: {apk}[/bold cyan]\n")
    results = analyze_apk(apk, output)
    if results.get("permissions"):
        console.print(f"[cyan]Permissions found: {len(results['permissions'])}[/cyan]")
    if results.get("hardcoded_secrets"):
        console.print(f"[bold red]Hardcoded secrets: {len(results['hardcoded_secrets'])}[/bold red]")


@recon.command("full")
@click.option("--target", "-t", required=True, help="Target domain to enumerate")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--brute", is_flag=True, help="Include DNS brute-force")
@click.option("--full", "full_ports", is_flag=True, help="Full port scan (all 65535 ports)")
@click.pass_context
def recon_full(ctx, target, output, brute, full_ports):
    """Full reconnaissance pipeline (passive + subdomains + active + ports)."""
    from bountykit.recon.passive import passive_dns
    from bountykit.recon.subdomain import enumerate_subdomains
    from bountykit.recon.active import probe_hosts, scan_ports

    cfg = ctx.obj["config"]
    _legal_check(cfg, target)

    console.print(f"\n[bold cyan]Starting full reconnaissance on: {target}[/bold cyan]\n")

    console.print("[bold]Phase 1:[/bold] Passive DNS enumeration...")
    passive_dns(target, output)

    console.print("[bold]Phase 2:[/bold] Subdomain enumeration...")
    enumerate_subdomains(target, output, brute=brute)

    console.print("[bold]Phase 3:[/bold] Probing live hosts...")
    probe_hosts(target, output)

    console.print("[bold]Phase 4:[/bold] Port scanning...")
    scan_ports(target, output, full=full_ports)

    console.print(f"\n[bold green]Recon complete! Results saved to: {output}[/bold green]\n")


# =============================================================================
# SCAN COMMANDS
# =============================================================================

@main.group()
def scan():
    """Vulnerability scanning commands."""
    pass


@scan.command("nuclei")
@click.option("--target", "-t", required=True, help="Target URL to scan")
@click.option("--severity", "-s", default="medium,high,critical", help="Severity filter")
@click.option("--rate-limit", "-r", default=50, type=int, help="Requests per second")
@click.option("--templates", default=None, help="Path to custom nuclei templates directory")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_nuclei(ctx, target, severity, rate_limit, templates, output):
    """Scan target with Nuclei templates."""
    from bountykit.scan.web import run_nuclei
    _legal_check(ctx.obj["config"], target)
    run_nuclei(target, severity=severity, rate_limit=rate_limit, output_dir=output)


@scan.command("sqli")
@click.option("--url", "-u", required=True, help="Target URL with parameter")
@click.option("--param", "-p", default=None, help="Specific parameter to test")
@click.option("--dbs", is_flag=True, help="Enumerate databases")
@click.option("--techniques", default=None, help="SQLMap techniques (BEUSTQ, or 'all')")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_sqli(ctx, url, param, dbs, techniques, output):
    """Test for SQL injection vulnerabilities."""
    from bountykit.scan.sqli import run_sqlmap
    _legal_check(ctx.obj["config"], url)
    run_sqlmap(url, param=param, dbs=dbs, techniques=techniques, output_dir=output)


@scan.command("xss")
@click.option("--url", "-u", required=True, help="Target URL with parameter")
@click.option("--param", "-p", default="q", help="Parameter to test")
@click.option("--techniques", default=None, help="XSS techniques (all, dom, reflected, stored)")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_xss(ctx, url, param, techniques, output):
    """Test for XSS vulnerabilities."""
    from bountykit.scan.xss import run_dalfox
    _legal_check(ctx.obj["config"], url)
    run_dalfox(url, param=param, techniques=techniques, output_dir=output)


@scan.command("ssrf")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--param", "-p", default="url", help="Parameter to test")
@click.option("--techniques", default=None, help="SSRF techniques (dns_rebinding, ipv6_bypass, all)")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_ssrf(ctx, target, param, techniques, output):
    """Test for SSRF vulnerabilities."""
    from bountykit.scan.ssrf import test_ssrf
    _legal_check(ctx.obj["config"], target)
    test_ssrf(target, param=param, techniques=techniques, output_dir=output)


@scan.command("api")
@click.option("--target", "-t", required=True, help="Target API endpoint")
@click.option("--method", "-m", default="GET", help="HTTP method")
@click.option("--techniques", default=None, help="API test techniques or test IDs (all)")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_api(ctx, target, method, techniques, output):
    """Test API security (REST, GraphQL, OWASP Top 10)."""
    from bountykit.scan.api import test_api
    _legal_check(ctx.obj["config"], target)
    test_api(target, method=method, tests=techniques, output_dir=output)


@scan.command("deserialization")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_deser(ctx, target, output):
    """Detect deserialization vulnerabilities (Java, PHP, .NET)."""
    from bountykit.scan.deserialization import scan_all_deserialization
    _legal_check(ctx.obj["config"], target)
    scan_all_deserialization(target, output)


@scan.command("graphql")
@click.option("--target", "-t", required=True, help="GraphQL endpoint URL")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--batch", is_flag=True, help="Test batch query DoS")
@click.option("--depth", is_flag=True, help="Test query complexity depth")
@click.pass_context
def scan_graphql(ctx, target, output, batch, depth):
    """GraphQL security testing (introspection, batching, depth)."""
    from bountykit.scan.graphql import test_introspection, test_batch_queries, test_query_complexity
    _legal_check(ctx.obj["config"], target)

    if batch:
        test_batch_queries(target, output)
    elif depth:
        test_query_complexity(target, output)
    else:
        test_introspection(target, output)


@scan.command("oauth")
@click.option("--target", "-t", required=True, help="OAuth/authorization endpoint URL")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--jwt", default=None, help="JWT token to analyze")
@click.pass_context
def scan_oauth(ctx, target, output, jwt):
    """OAuth/JWT security testing."""
    from bountykit.scan.oauth import test_redirect_uri, test_token_theft, analyze_jwt
    _legal_check(ctx.obj["config"], target)

    if jwt:
        analyze_jwt(jwt, output)
    else:
        test_redirect_uri(target, output)
        test_token_theft(target, output)


@scan.command("takeover")
@click.option("--target", "-t", required=True, help="Target domain")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_takeover(ctx, target, output):
    """Subdomain takeover vulnerability scanning."""
    from bountykit.scan.takeover import scan_takeover
    _legal_check(ctx.obj["config"], target)
    scan_takeover(target, output)


@scan.command("headers")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_headers(ctx, target, output):
    """Security header and cookie audit."""
    from bountykit.scan.headers import analyze_headers
    _legal_check(ctx.obj["config"], target)
    analyze_headers(target, output)


@scan.command("waf")
@click.option("--target", "-t", required=True, help="Target URL or IP")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--bypass", is_flag=True, help="Test WAF bypass techniques")
@click.pass_context
def scan_waf(ctx, target, output, bypass):
    """WAF detection and bypass testing."""
    from bountykit.scan.waf import detect_waf, test_waf_bypass
    _legal_check(ctx.obj["config"], target)
    if bypass:
        detect_waf(target, output)
        test_waf_bypass(target, output)
    else:
        detect_waf(target, output)


@scan.command("ssti")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--engine", "-e", default="auto", help="Template engine (auto, jinja2, twig, etc.)")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_ssti(ctx, target, engine, output):
    """Server-Side Template Injection detection (20+ engines, polyglot probes, RCE chains)."""
    from bountykit.scan.ssti import SSTITester
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]SSTI Detection: {target}[/bold cyan]\n")
    tester = SSTITester(target)
    result = asyncio.run(tester.test_all())
    saved = tester._save_results(result, output)
    table = Table(title="SSTI Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Engine", style="cyan", width=15)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.template_engine, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@scan.command("smuggle")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--attack", "-a", type=click.Choice(
    ["cl_te", "te_cl", "te_te", "cache_poison", "host_injection", "all"]
), default="all", help="Attack type")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_smuggle(ctx, target, attack, output):
    """HTTP request smuggling & cache poisoning testing."""
    from bountykit.scan.smuggling import HTTPSmugglingTester
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]HTTP Smuggling & Cache Poisoning: {target}[/bold cyan]\n")
    tester = HTTPSmugglingTester(target)
    result = asyncio.run(tester.test_all())
    saved = tester._save_results(result, output)
    table = Table(title="Smuggling / Cache Poisoning Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.category, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@scan.command("race")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--param", "-p", default=None, help="Parameter to test")
@click.option("--threads", default=10, type=int, help="Number of concurrent threads")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_race(ctx, target, param, threads, output):
    """Race condition & business logic testing (H2 single-packet, JWT race, Turbo Intruder)."""
    from bountykit.scan.race_condition import RaceConditionTester
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Race Condition Testing: {target}[/bold cyan]\n")
    tester = RaceConditionTester(target, max_concurrent=threads)
    result = asyncio.run(tester.test_all())
    saved = tester._save_results(result, output)
    table = Table(title="Race Condition Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.category, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@scan.command("supply-chain")
@click.option("--target", "-t", required=True, help="Target repository URL or local path")
@click.option("--attack", "-a", type=click.Choice(
    ["malicious_packages", "typosquatting", "ci_cd", "mcp_hijack", "skill_poisoning", "all"]
), default="all", help="Supply chain attack type")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_supply_chain(ctx, target, attack, output):
    """Supply chain security scanning (malicious packages, typosquatting, GHA hijack)."""
    from bountykit.scan.supply_chain import SupplyChainScanner
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Supply Chain Security: {target}[/bold cyan]\n")
    scanner = SupplyChainScanner(target_path=target)
    result = asyncio.run(scanner.scan_project())
    saved = scanner._save_results(result, output)
    table = Table(title="Supply Chain Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.category, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@scan.command("llm")
@click.option("--target", "-t", required=True, help="Target URL or API endpoint")
@click.option("--model", "-m", default=None, help="LLM model to test (e.g., gpt-4)")
@click.option("--attack", "-a", type=click.Choice(
    ["prompt_injection", "ssrf_via_llm", "tool_hijack", "model_extraction", "skill_poisoning", "all"]
), default="all", help="Attack type")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_llm(ctx, target, model, attack, output):
    """LLM/AI security testing (prompt injection, RAG poisoning, tool hijack)."""
    from bountykit.scan.llm import LLMTester
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]LLM/AI Security Testing: {target}[/bold cyan]\n")
    tester = LLMTester(target)
    result = asyncio.run(tester.test_all())
    saved = tester._save_results(result, output)
    table = Table(title="LLM/AI Security Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.category, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@scan.command("cloud-misconfig")
@click.option("--provider", "-p", type=click.Choice(["aws", "gcp", "azure", "kubernetes", "all"]), default="all", help="Cloud provider")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_cloud_misconfig(ctx, provider, output):
    """Cloud misconfiguration scanning (S3, GCS, Azure Blob, K8s, Firebase, Lambda, EC2)."""
    from bountykit.scan.cloud_misconfig import CloudMisconfigurationScanner
    _legal_check(ctx.obj["config"], provider)
    console.print(f"\n[bold cyan]Cloud Misconfiguration Scanning: {provider}[/bold cyan]\n")
    scanner = CloudMisconfigurationScanner(target=provider)
    result = asyncio.run(scanner.scan_all())
    table = Table(title="Cloud Misconfig Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Provider", style="cyan", width=12)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.provider, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings[/green]\n")


@scan.command("network")
@click.option("--target", "-t", required=True, help="Target IP or domain")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--full", is_flag=True, help="Full port scan (all 65535 ports)")
@click.pass_context
def scan_network(ctx, target, output, full):
    """Network-layer attacks (ARP spoof, DNS rebinding, TLS downgrade, BGP hijack, SNMP)."""
    from bountykit.scan.network import scan_network as _scan_network
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Network Attack Scanning: {target}[/bold cyan]\n")
    _scan_network(target, output)


@scan.command("websocket")
@click.option("--target", "-t", required=True, help="Target URL with WebSocket endpoints")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--deep", is_flag=True, default=False,
              help="Enable deep mode: subdomain bruteforce + TLD expansion + full JS crawl")
@click.option("--timeout", default=10, show_default=True,
              help="Per-request / WS handshake timeout in seconds")
@click.option("--no-tld", "no_tld", is_flag=True, default=False,
              help="Skip TLD variant probing (faster, single-domain only)")
@click.pass_context
def scan_websocket(ctx, target, output, deep, timeout, no_tld):
    """WebSocket security testing (CSWSH, injection, DoS, auth bypass, subprotocols).

    Real-world discovery engine:
    \b
    Phase 1  Mine primary page HTML + linked JS files for ws(s):// URLs
    Phase 2  Subdomain prefix bruteforce (api, ws, realtime, chat, …)
    Phase 3  TLD variant probing (.com .org .ph .gov .sg …)
    Phase 4  Async concurrent WS handshake probe on all live origins
    """
    from bountykit.scan.websocket import WebSocketScanner
    _legal_check(ctx.obj["config"], target)

    console.print(f"\n[bold cyan]WebSocket Security: {target}[/bold cyan]")
    if deep:
        console.print("[yellow]⚡ Deep mode: subdomain + TLD expansion + JS crawl enabled[/yellow]")
    if no_tld:
        console.print("[dim]  TLD variant probing disabled[/dim]")
    console.print()

    scanner = WebSocketScanner(target, output_dir=output, timeout=timeout)

    # Patch flags onto scanner so discovery respects CLI options
    scanner._deep_mode = deep
    scanner._skip_tld = no_tld

    with console.status("[bold green]Running discovery + security probes…", spinner="dots"):
        result = scanner.run_full_scan()

    # ── Endpoints discovered ──────────────────────────────────────────────────
    if result.endpoints_discovered > 0:
        ep_table = Table(title="Discovered WebSocket Endpoints", show_lines=True)
        ep_table.add_column("#", style="dim", width=4)
        ep_table.add_column("Endpoint", style="bold cyan")
        for i, ep in enumerate(result.discovered_endpoints, 1):
            ep_table.add_row(str(i), ep)
        console.print(ep_table)
        console.print()

    # ── Security findings ─────────────────────────────────────────────────────
    if result.findings:
        find_table = Table(title="WebSocket Security Findings", show_lines=True)
        find_table.add_column("Severity", style="bold red", width=10)
        find_table.add_column("Type", style="cyan", width=20)
        find_table.add_column("Title", style="white")
        find_table.add_column("Evidence", style="dim", max_width=50)
        sev_color = {"critical": "red", "high": "bright_red",
                     "medium": "yellow", "low": "green"}
        for f in result.findings:
            color = sev_color.get(f.severity, "white")
            find_table.add_row(
                f"[{color}]{f.severity.upper()}[/{color}]",
                f.finding_type,
                f.test_name,
                (f.evidence[:48] + "…") if len(f.evidence) > 48 else f.evidence,
            )
        console.print(find_table)
    else:
        console.print("[dim]No security findings.[/dim]")

    # ── Summary line ─────────────────────────────────────────────────────────
    console.print(
        f"\n[green]✓ {len(result.findings)} findings | "
        f"{result.endpoints_discovered} endpoints discovered | "
        f"scan took {result.scan_duration:.1f}s[/green]\n"
    )



@scan.command("template")
@click.option("--vuln", "-v", required=True, type=click.Choice(
    ["sqli", "xss", "idor", "ssrf", "lfi", "rce"],
), help="Vulnerability type to generate template for")
@click.option("--param", "-p", required=True, help="Parameter name")
@click.option("--path", default="/", help="URL path")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def scan_template(ctx, vuln, param, path, output):
    """Generate Nuclei templates for specific vulnerabilities."""
    from bountykit.scan.template_builder import build_template
    build_template(vuln, param, path, output)


# =============================================================================
# CVE COMMANDS
# =============================================================================

@main.group()
def cve():
    """CVE research, monitoring, and exploitation commands."""
    pass


@cve.command("search")
@click.option("--keyword", "-k", required=True, help="Search keyword")
@click.option("--year", "-y", default=None, help="Filter by year")
@click.option("--severity", "-s", default=None, help="Filter by severity (HIGH, CRITICAL)")
@click.option("--cpe", default=None, help="CPE to search for (e.g., cpe:2.3:a:vendor:product)")
@click.pass_context
def cve_search(ctx, keyword, year, severity, cpe):
    """Search CVE databases (NVD, Google, CISA)."""
    from bountykit.cve.search import search_cve
    results = search_cve(keyword, year=year, severity=severity)
    if results.findings:
        console.print(f"\n[bold green]Found {len(results.findings)} CVEs[/bold green]\n")
        for cve in results.findings:
            console.print(f"  [cyan]{cve.cve_id}[/cyan] — {cve.description[:80]}...")
    else:
        console.print("[yellow]No CVEs found matching your criteria.[/yellow]")


@cve.command("monitor")
@click.option("--tech", "-t", required=True, multiple=True, help="Technologies to monitor")
@click.option("--notify", "-n", default=None, help="Notification webhook URL")
@click.pass_context
def cve_monitor(ctx, tech, notify):
    """Monitor new CVEs for specified technologies."""
    from bountykit.cve.monitor import start_monitor
    start_monitor(list(tech), notify=notify)


@cve.command("pocs")
@click.option("--cve-id", "-c", required=True, help="CVE ID (e.g., CVE-2024-1234)")
@click.pass_context
def cve_pocs(ctx, cve_id):
    """Find PoC exploits for a CVE."""
    from bountykit.cve.exploit_db import find_pocs
    results = find_pocs(cve_id)
    if results:
        console.print(f"\n[bold green]Found {len(results)} PoCs for {cve_id}[/bold green]\n")
        for r in results:
            console.print(f"  [link={r['url']}]{r['name']}[/link]")
            console.print(f"    {r['description'][:100]}")
    else:
        console.print(f"[yellow]No PoCs found for {cve_id}[/yellow]")


@cve.command("chain")
@click.option("--cve-ids", "-c", required=True, multiple=True, help="CVE IDs to chain")
@click.option("--target", "-t", required=True, help="Target URL for validation")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def cve_chain(ctx, cve_ids, target, output):
    """Analyze CVE chain patterns and attack paths."""
    from bountykit.cve.chaining import analyze_chains, build_attack_path
    _legal_check(ctx.obj["config"], target)
    if len(cve_ids) < 2:
        console.print("[red]Provide at least 2 CVE IDs to chain.[/red]")
        return
    results = analyze_chains(list(cve_ids), output_dir=output)
    build_attack_path(target, list(cve_ids), output_dir=output)


@cve.command("patchdiff")
@click.option("--repo", "-r", required=True, help="Git repository URL or local path")
@click.option("--old", required=True, help="Old commit/tag/version")
@click.option("--new", required=True, help="New commit/tag/version")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def cve_patchdiff(ctx, repo, old, new, output):
    """Analyze patch diffs for vulnerability introduction."""
    from bountykit.cve.patchdiff import analyze_git_diff
    analyze_git_diff(repo, commit1=old, commit2=new, output_dir=output)


# =============================================================================
# CLOUD COMMANDS
# =============================================================================

@main.group()
def cloud():
    """Cloud security testing commands."""
    pass


@cloud.command("aws")
@click.option("--bucket", "-b", default=None, help="S3 bucket name to test")
@click.option("--metadata", is_flag=True, help="Test cloud metadata endpoint")
@click.pass_context
def cloud_aws(ctx, bucket, metadata):
    """Test AWS misconfigurations (SSRF to metadata, S3 bucket enumeration)."""
    from bountykit.cloud.aws import test_aws
    test_aws(bucket=bucket, test_metadata=metadata)


# =============================================================================
# NEW 2026 ADVANCED SECURITY COMMANDS
# =============================================================================

@main.group()
def advanced():
    """Advanced 2026 security testing commands (LLM, supply chain, race conditions, smuggling)."""
    pass


@advanced.command("llm")
@click.option("--target", "-t", required=True, help="Target URL or API endpoint")
@click.option("--model", "-m", default=None, help="LLM model to test (e.g., gpt-4)")
@click.option("--attack", "-a", type=click.Choice(
    ["prompt_injection", "ssrf_via_llm", "tool_hijack", "model_extraction", "skill_poisoning", "all"]
), default="all", help="Attack type to test")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def advanced_llm(ctx, target, model, attack, output):
    """LLM/AI security testing (prompt injection, SSRF, skill poisoning)."""
    from bountykit.scan.llm import LLMTester
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]LLM/AI Security Testing: {target}[/bold cyan]\n")
    tester = LLMTester(target)
    result = asyncio.run(tester.test_all())
    saved = tester._save_results(result, output)
    table = Table(title="LLM/AI Security Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.category, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@advanced.command("supplychain")
@click.option("--target", "-t", required=True, help="Target repository URL or package")
@click.option("--attack", "-a", type=click.Choice(
    ["malicious_packages", "typosquatting", "ci_cd", "mcp_hijack", "skill_poisoning", "all"]
), default="all", help="Supply chain attack type")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def advanced_supplychain(ctx, target, attack, output):
    """Supply chain security scanning (malicious packages, typosquatting, CI/CD)."""
    from bountykit.scan.supply_chain import SupplyChainScanner
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Supply Chain Security: {target}[/bold cyan]\n")
    scanner = SupplyChainScanner(target_path=target)
    result = asyncio.run(scanner.scan_project())
    saved = scanner._save_results(result, output)
    table = Table(title="Supply Chain Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.category, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@advanced.command("race")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--param", "-p", default=None, help="Parameter to test")
@click.option("--threads", default=10, type=int, help="Number of concurrent threads")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def advanced_race(ctx, target, param, threads, output):
    """Race condition & business logic testing."""
    from bountykit.scan.race_condition import RaceConditionTester
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]Race Condition Testing: {target}[/bold cyan]\n")
    tester = RaceConditionTester(target, max_concurrent=threads)
    result = asyncio.run(tester.test_all())
    saved = tester._save_results(result, output)
    table = Table(title="Race Condition Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.category, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@advanced.command("smuggle")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--attack", "-a", type=click.Choice(
    ["cl_te", "te_cl", "te_te", "cache_poison", "host_injection", "all"]
), default="all", help="Attack type")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def advanced_smuggle(ctx, target, attack, output):
    """HTTP request smuggling & cache poisoning testing."""
    from bountykit.scan.smuggling import HTTPSmugglingTester
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]HTTP Smuggling & Cache Poisoning: {target}[/bold cyan]\n")
    tester = HTTPSmugglingTester(target)
    result = asyncio.run(tester.test_all())
    saved = tester._save_results(result, output)
    table = Table(title="Smuggling / Cache Poisoning Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.category, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@advanced.command("ssti")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--engine", "-e", default="auto", help="Template engine (auto, jinja2, twig, etc.)")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def advanced_ssti(ctx, target, engine, output):
    """Server-Side Template Injection testing (20+ template engines)."""
    from bountykit.scan.ssti import SSTITester
    _legal_check(ctx.obj["config"], target)
    console.print(f"\n[bold cyan]SSTI Detection: {target}[/bold cyan]\n")
    tester = SSTITester(target)
    result = asyncio.run(tester.test_all())
    saved = tester._save_results(result, output)
    table = Table(title="SSTI Findings", show_lines=True)
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Engine", style="cyan", width=15)
    table.add_column("Title", style="white")
    for f in result.findings:
        color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.template_engine, f.title)
    if result.findings:
        console.print(table)
    console.print(f"\n[green]✓ {len(result.findings)} findings → {saved}[/green]\n")


@advanced.command("cloud")
@click.option("--provider", "-p", type=click.Choice(["aws", "gcp", "azure", "all"]), default="all", help="Cloud provider")
@click.option("--metadata-bypass", is_flag=True, help="Test cloud metadata bypass techniques")
@click.option("--credentials", is_flag=True, help="Test credential theft vectors")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def advanced_cloud(ctx, provider, metadata_bypass, credentials, output):
    """Multi-cloud security testing (AWS, GCP, Azure)."""
    from bountykit.cloud.multi_cloud import MultiCloudScanner
    _legal_check(ctx.obj["config"], provider)
    console.print(f"\n[bold cyan]Multi-Cloud Security Testing: {provider}[/bold cyan]\n")
    providers_list = ["aws", "gcp", "azure"] if provider == "all" else [provider]
    scanner = MultiCloudScanner(target=provider, providers=providers_list)
    asyncio.run(scanner.scan_all())


# =============================================================================
# PIPELINE COMMANDS
# =============================================================================

@main.command()
@click.option("--target", "-t", required=True, help="Target domain or URL")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--scan-type", type=click.Choice(["full", "quick", "recon", "scan", "cve", "advanced"]),
              default="full", help="Type of scan to run")
@click.option("--no-parallel", is_flag=True, help="Disable parallel execution")
@click.option("--resume", is_flag=True, help="Resume from previously completed phases")
@click.pass_context
def pipeline(ctx, target, output, scan_type, no_parallel, resume):
    """Run full automated scanning pipeline."""
    from bountykit.pipeline import run_full_pipeline
    _legal_check(ctx.obj["config"], target)
    run_full_pipeline(target, output, scan_type=scan_type, parallel=not no_parallel, resume=resume)


# =============================================================================
# REPORT COMMAND
# =============================================================================

@main.command()
@click.option("--input", "-i", "input_dir", required=True, help="Results directory")
@click.option("--format", "-f", "fmt", default="markdown",
              type=click.Choice(["markdown", "json", "html"]), help="Output format")
@click.option("--output", "-o", default=None, help="Output file path")
@click.pass_context
def report(ctx, input_dir, fmt, output):
    """Generate report from scan results."""
    from bountykit.utils.report import generate_markdown_report, generate_html_report, generate_json_report

    # Collect findings from results directory
    findings = _collect_findings(input_dir)
    target = _extract_target(input_dir)

    output_path = output or f"./results/report.{fmt if fmt != 'markdown' else 'md'}"

    if fmt == "html":
        generate_html_report(target, findings, output_path=output_path)
    elif fmt == "json":
        generate_json_report(target, findings, output_path=output_path)
    else:
        generate_markdown_report(target, findings, output_path=output_path)


def _collect_findings(input_dir: str) -> list:
    """Collect findings from JSON result files in directory."""
    import json
    from pathlib import Path

    findings = []
    results_path = Path(input_dir)

    if not results_path.exists():
        return findings

    for json_file in results_path.glob("**/*.json"):
        try:
            with open(json_file) as f:
                data = json.load(f)

            # Handle different result formats
            if isinstance(data, dict):
                # Direct findings list
                if "findings" in data:
                    for item in data["findings"]:
                        if isinstance(item, dict):
                            findings.append(_normalize_finding(item))
                # Single finding
                elif "severity" in data:
                    findings.append(_normalize_finding(data))
                # Nested results
                elif "results" in data:
                    for item in data["results"]:
                        if isinstance(item, dict) and "severity" in item:
                            findings.append(_normalize_finding(item))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "severity" in item:
                        findings.append(_normalize_finding(item))
        except (json.JSONDecodeError, KeyError):
            continue

    return findings


def _normalize_finding(item: dict) -> dict:
    """Normalize a finding dict to standard format."""
    return {
        "severity": item.get("severity", item.get("level", "info")).lower(),
        "title": item.get("title", item.get("name", item.get("type", "Finding"))),
        "description": item.get("description", item.get("details", item.get("message", ""))),
        "cwe": item.get("cwe", item.get("cwe_id", "")),
        "url": item.get("url", item.get("endpoint", "")),
        "source": item.get("source", item.get("tool", "")),
        "fix": item.get("fix", item.get("remediation", item.get("solution", ""))),
    }


def _extract_target(input_dir: str) -> str:
    """Extract target from pipeline results or directory name."""
    import json
    from pathlib import Path

    results_path = Path(input_dir)

    # Check pipeline_results.json
    pipeline_file = results_path / "pipeline_results.json"
    if pipeline_file.exists():
        try:
            with open(pipeline_file) as f:
                data = json.load(f)
            return data.get("target", results_path.name)
        except (json.JSONDecodeError, KeyError):
            pass

    return results_path.name


# =============================================================================
# SETUP AND LEGAL
# =============================================================================

@main.command()
def setup():
    """Install and verify all required external tools."""
    from bountykit.utils.installer import run_setup
    run_setup()


@main.command()
@click.option("--target", "-t", required=True, help="Target to verify authorization for")
@click.option("--scope", "-s", default=None, help="Path to scope file")
@click.option("--output", "-o", default=None, type=click.Path(), help="Save authorization record to file")
@click.pass_context
def legal(ctx, target, scope, output):
    """Check legal authorization for a target."""
    import json
    from datetime import datetime
    from pathlib import Path
    from bountykit.utils.legal import check_authorization
    result = check_authorization(target, scope_file=scope)
    if result:
        console.print(f"[bold green]AUTHORIZED: {target} is in scope[/bold green]")
    else:
        console.print(f"[bold red]NOT AUTHORIZED: {target} is out of scope[/bold red]")
    if output:
        record = {
            "target": target,
            "authorized": result,
            "scope_file": scope,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # If output is a directory, write a default filename inside it
        if out_path.is_dir():
            out_path = out_path / "legal_authorization.json"
        with open(out_path, "w") as f:
            json.dump(record, f, indent=2)
        console.print(f"[dim]Authorization record saved → {out_path}[/dim]")


# =============================================================================
# CONFIG COMMANDS
# =============================================================================

@main.group()
def config():
    """View and modify bountykit configuration."""
    pass


@config.command("show")
@click.pass_context
def config_show(ctx):
    """Display current configuration."""
    cfg = ctx.obj["config"]
    table = Table(title="BountyKit Configuration", show_lines=True)
    table.add_column("Section", style="bold cyan", width=20)
    table.add_column("Key", style="white", width=25)
    table.add_column("Value", style="green")
    for section_name, section in cfg.model_dump().items():
        if isinstance(section, dict):
            for key, val in section.items():
                table.add_row(section_name, key, str(val))
        else:
            table.add_row(section_name, "", str(section))
    console.print(table)


@config.command("set")
@click.argument("key", required=True)
@click.argument("value", required=True)
@click.pass_context
def config_set(ctx, key, value):
    """Set a configuration value (e.g., 'config set scan.threads 20')."""
    cfg = ctx.obj["config"]
    parts = key.split(".")
    if len(parts) == 2:
        section, field_name = parts
        section_obj = getattr(cfg, section, None)
        if section_obj and hasattr(section_obj, field_name):
            field_type = type(getattr(section_obj, field_name))
            try:
                setattr(section_obj, field_name, field_type(value))
                cfg.save()
                console.print(f"[green]Set {key} = {value}[/green]")
            except (ValueError, TypeError) as e:
                console.print(f"[red]Invalid value: {e}[/red]")
        else:
            console.print(f"[red]Unknown config key: {key}[/red]")
    else:
        console.print("[red]Key format: section.field (e.g., scan.threads)[/red]")


# =============================================================================
# VERSION COMMAND
# =============================================================================

@main.command()
def version():
    """Show bountykit version and system info."""
    import platform
    console.print(f"\n[bold cyan]BountyKit v{__version__}[/bold cyan]")
    console.print(f"Python: {platform.python_version()}")
    console.print(f"Platform: {platform.platform()}")

    # Check external tools
    tools = {"nuclei": "nuclei -version", "subfinder": "subfinder -version", "nmap": "nmap --version"}
    for name, cmd in tools.items():
        try:
            import subprocess
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            status = "[green]✓[/green]" if result.returncode == 0 else "[red]✗[/red]"
        except Exception:
            status = "[yellow]?[/yellow]"
        console.print(f"  {status} {name}")
    console.print()


# =============================================================================
# REPORT GENERATE COMMAND
# =============================================================================

@main.command("report-generate")
@click.option("--input", "-i", "input_dir", required=True, help="Results directory")
@click.option("--format", "-f", "fmt", default="markdown",
              type=click.Choice(["markdown", "json", "html", "pdf"]), help="Output format")
@click.option("--output", "-o", default=None, help="Output file path")
@click.pass_context
def report_generate(ctx, input_dir, fmt, output):
    """Generate a report from scan results."""
    from bountykit.utils.report import generate_markdown_report, generate_html_report, generate_json_report
    findings = _collect_findings(input_dir)
    target = _extract_target(input_dir)
    output_path = output or f"./results/report.{fmt if fmt != 'markdown' else 'md'}"
    if fmt == "html":
        generate_html_report(target, findings, output_path=output_path)
    elif fmt == "json":
        generate_json_report(target, findings, output_path=output_path)
    else:
        generate_markdown_report(target, findings, output_path=output_path)
    console.print(f"[green]Report generated → {output_path}[/green]")


# =============================================================================
# VALIDATE LICENSE COMMAND
# =============================================================================

@main.command("validate-license")
@click.pass_context
def validate_license(ctx):
    """Validate the bountykit license and configuration."""
    from pathlib import Path
    lic = Path(__file__).parent.parent.parent / "LICENSE"
    if lic.exists():
        console.print(f"[green]✓ LICENSE file found: {lic}[/green]")
    else:
        console.print("[yellow]LICENSE file not found in project root[/yellow]")
    cfg = ctx.obj["config"]
    if cfg.legal.require_auth:
        console.print("[green]✓ Legal gate: ENABLED (auth required before scanning)[/green]")
    else:
        console.print("[red]✗ Legal gate: DISABLED — enable require_auth in config[/red]")


# =============================================================================
# CHECK UPDATES COMMAND
# =============================================================================

@main.command("check-updates")
@click.pass_context
def check_updates(ctx):
    """Check for bountykit updates on PyPI."""
    import requests
    try:
        resp = requests.get("https://pypi.org/pypi/bountykit/json", timeout=10)
        latest = resp.json()["info"]["version"]
        if latest == __version__:
            console.print(f"[green]✓ Up to date (v{__version__})[/green]")
        else:
            console.print(f"[yellow]Update available: v{latest} (current: v{__version__})[/yellow]")
            console.print("[dim]Run: pip install --upgrade bountykit[/dim]")
    except Exception as e:
        console.print(f"[red]Could not check updates: {e}[/red]")


if __name__ == "__main__":
    main()
