"""Main CLI entry point for bountykit."""

import sys
import click
from rich.console import Console
from rich.panel import Panel

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

    discover_js_files(target, output, max_depth=depth)

    do_all = run_all or (not secrets and not endpoints and not dom_xss)
    if do_all or secrets:
        extract_secrets(target, output, max_depth=depth)
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
        crawl_deep(target, output, depth=depth, katana=True, gospider=True)
    else:
        crawl_katana(target, output, depth=depth)


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
@click.pass_context
def scan_nuclei(ctx, target, severity, rate_limit, templates):
    """Scan target with Nuclei templates."""
    from bountykit.scan.web import run_nuclei
    _legal_check(ctx.obj["config"], target)
    run_nuclei(target, severity=severity, rate_limit=rate_limit)


@scan.command("sqli")
@click.option("--url", "-u", required=True, help="Target URL with parameter")
@click.option("--param", "-p", default=None, help="Specific parameter to test")
@click.option("--dbs", is_flag=True, help="Enumerate databases")
@click.pass_context
def scan_sqli(ctx, url, param, dbs):
    """Test for SQL injection vulnerabilities."""
    from bountykit.scan.sqli import run_sqlmap
    _legal_check(ctx.obj["config"], url)
    run_sqlmap(url, param=param, dbs=dbs)


@scan.command("xss")
@click.option("--url", "-u", required=True, help="Target URL with parameter")
@click.option("--param", "-p", default="q", help="Parameter to test")
@click.pass_context
def scan_xss(ctx, url, param):
    """Test for XSS vulnerabilities."""
    from bountykit.scan.xss import run_dalfox
    _legal_check(ctx.obj["config"], url)
    run_dalfox(url, param=param)


@scan.command("ssrf")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--param", "-p", default="url", help="Parameter to test")
@click.pass_context
def scan_ssrf(ctx, target, param):
    """Test for SSRF vulnerabilities."""
    from bountykit.scan.ssrf import test_ssrf
    _legal_check(ctx.obj["config"], target)
    test_ssrf(target, param=param)


@scan.command("api")
@click.option("--target", "-t", required=True, help="Target API endpoint")
@click.option("--method", "-m", default="GET", help="HTTP method")
@click.pass_context
def scan_api(ctx, target, method):
    """Test API security (REST, GraphQL, OWASP Top 10)."""
    from bountykit.scan.api import test_api
    _legal_check(ctx.obj["config"], target)
    test_api(target, method=method)


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
    from bountykit.scan.template_builder import build_sqli_template, build_xss_template, build_idor_template
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
    if results:
        console.print(f"\n[bold green]Found {len(results)} CVEs[/bold green]\n")
        for r in results:
            console.print(f"  [cyan]{r['id']}[/cyan] — {r['description'][:80]}...")
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
    results = analyze_chains(list(cve_ids), target, output)
    build_attack_path(list(cve_ids), target, output)


@cve.command("patchdiff")
@click.option("--repo", "-r", required=True, help="Git repository URL or local path")
@click.option("--old", required=True, help="Old commit/tag/version")
@click.option("--new", required=True, help="New commit/tag/version")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.pass_context
def cve_patchdiff(ctx, repo, old, new, output):
    """Analyze patch diffs for vulnerability introduction."""
    from bountykit.cve.patchdiff import analyze_commits, analyze_git_diff
    analyze_commits(repo, old, new, output)


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
# PIPELINE COMMANDS
# =============================================================================

@main.command()
@click.option("--target", "-t", required=True, help="Target domain or URL")
@click.option("--output", "-o", type=click.Path(), default="./results", help="Output directory")
@click.option("--scan-type", type=click.Choice(["full", "quick", "recon", "scan", "cve"]),
              default="full", help="Type of scan to run")
@click.option("--no-parallel", is_flag=True, help="Disable parallel execution")
@click.pass_context
def pipeline(ctx, target, output, scan_type, no_parallel):
    """Run full automated scanning pipeline."""
    from bountykit.pipeline import run_full_pipeline
    _legal_check(ctx.obj["config"], target)
    run_full_pipeline(target, output, scan_type=scan_type, parallel=not no_parallel)


# =============================================================================
# REPORT COMMAND
# =============================================================================

@main.command()
@click.option("--input", "-i", "input_dir", required=True, help="Results directory")
@click.option("--format", "-f", "fmt", default="markdown",
              type=click.Choice(["markdown", "json"]), help="Output format")
@click.option("--output", "-o", default=None, help="Output file path")
@click.pass_context
def report(ctx, input_dir, fmt, output):
    """Generate report from scan results."""
    from bountykit.report.markdown import generate_report
    generate_report(input_dir, fmt=fmt, output=output)


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
@click.pass_context
def legal(ctx, target, scope):
    """Check legal authorization for a target."""
    from bountykit.utils.legal import check_authorization
    result = check_authorization(target, scope_file=scope)
    if result:
        console.print(f"[bold green]AUTHORIZED: {target} is in scope[/bold green]")
    else:
        console.print(f"[bold red]NOT AUTHORIZED: {target} is out of scope[/bold red]")


if __name__ == "__main__":
    main()
