"""Full automation pipeline module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 19:
- Complete scanning pipeline
- Parallel execution with dependency graph and concurrency cap (5)
- Result aggregation and --resume support
- Rich progress bar with live findings counter
- Report generation
"""

import asyncio
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)

console = Console()

# ─── Dependency Graph ─────────────────────────────────────────────────────────
# Phase dependencies: key depends on value(s) being completed first.
# Phases not listed here have no dependencies and can start immediately.

PHASE_DEPENDENCIES: dict[str, list[str]] = {
    "endpoints": ["recon"],
    "scan": ["endpoints"],
    "advanced": ["scan"],
    "network": ["recon"],
    "headers": ["scan"],
    "waf": ["scan"],
    "cve": ["recon"],
    "cloud": ["recon"],
    "cloud_misconfig": ["recon"],
    "supply_chain": ["scan"],
    "report": [],  # report depends on all non-report phases (handled specially)
}

# Maximum concurrent phases to avoid resource exhaustion
MAX_CONCURRENT_PHASES = 5


def run_full_pipeline(
    target: str,
    output_dir: str = "./results",
    scan_type: str = "full",
    parallel: bool = True,
    resume: bool = False,
) -> dict:
    """Run the full bounty hunting pipeline.

    Args:
        target: Target domain or URL
        output_dir: Output directory
        scan_type: Type of scan (full, quick, recon, scan, cve, advanced)
        parallel: Enable parallel execution with dependency graph
        resume: Resume from previously completed phases
    """
    results = {
        "target": target,
        "scan_type": scan_type,
        "output_dir": output_dir,
        "start_time": time.time(),
        "phases": {},
    }

    os.makedirs(output_dir, exist_ok=True)

    # Load previous results if resuming
    if resume:
        results = _load_resume_state(output_dir, results)

    console.print(Panel(
        f"[bold]Starting bounty pipeline for: {target}[/bold]\n"
        f"Scan type: {scan_type} | Parallel: {parallel} | Resume: {resume}",
        title="BountyKit Pipeline",
        border_style="green",
    ))

    # Define pipeline phases based on scan type
    phases = _get_phases(scan_type)

    if parallel:
        results = _run_parallel(target, phases, output_dir, results)
    else:
        results = _run_sequential(target, phases, output_dir, results)

    results["end_time"] = time.time()
    results["duration"] = results["end_time"] - results["start_time"]

    # Generate summary
    _generate_summary(results)

    # Save final results
    output_file = Path(output_dir) / "pipeline_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"\n[bold green]Pipeline completed in {results['duration']:.1f}s[/bold green]")
    console.print(f"[dim]Full results saved to {output_file}[/dim]")

    return results


def _get_phases(scan_type: str) -> list:
    """Get phases based on scan type."""
    all_phases = [
        {
            "name": "recon",
            "description": "Reconnaissance",
            "tools": ["subdomain", "passive", "active"],
            "priority": 1,
        },
        {
            "name": "endpoints",
            "description": "Endpoint Discovery",
            "tools": ["endpoints", "js_analysis", "crawler"],
            "priority": 2,
        },
        {
            "name": "scan",
            "description": "Vulnerability Scanning",
            "tools": ["web", "sqli", "xss", "ssrf", "api"],
            "priority": 3,
        },
        {
            "name": "advanced",
            "description": "Advanced Testing",
            "tools": ["deserialization", "graphql", "oauth", "takeover", "ssti", "smuggle", "race_condition"],
            "priority": 4,
        },
        {
            "name": "network",
            "description": "Network Attacks",
            "tools": ["takeover", "smuggle", "race_condition"],
            "priority": 4,
        },
        {
            "name": "headers",
            "description": "Security Headers & WAF",
            "tools": ["headers", "waf"],
            "priority": 5,
        },
        {
            "name": "cve",
            "description": "CVE Research",
            "tools": ["search", "monitor"],
            "priority": 6,
        },
        {
            "name": "cloud",
            "description": "Cloud Security (SDK)",
            "tools": ["aws", "multi_cloud"],
            "priority": 7,
        },
        {
            "name": "cloud_misconfig",
            "description": "Cloud Misconfig (Web Probes)",
            "tools": ["cloud_misconfig"],
            "priority": 7,
        },
        {
            "name": "supply_chain",
            "description": "Supply Chain & LLM Security",
            "tools": ["supply_chain", "llm"],
            "priority": 8,
        },
        {
            "name": "report",
            "description": "Report Generation",
            "tools": ["markdown"],
            "priority": 9,
        },
    ]

    if scan_type == "quick":
        return [p for p in all_phases if p["name"] in ["recon", "scan", "report"]]
    elif scan_type == "recon":
        return [p for p in all_phases if p["name"] in ["recon", "endpoints", "report"]]
    elif scan_type == "scan":
        return [p for p in all_phases if p["name"] in ["scan", "advanced", "headers", "report"]]
    elif scan_type == "cve":
        return [p for p in all_phases if p["name"] in ["cve", "report"]]
    elif scan_type == "advanced":
        return [p for p in all_phases if p["name"] in [
            "advanced", "network", "cloud", "cloud_misconfig", "supply_chain", "report",
        ]]
    else:
        return all_phases


def _load_resume_state(output_dir: str, results: dict) -> dict:
    """Load previous pipeline state for resume support."""
    output_file = Path(output_dir) / "pipeline_results.json"
    if output_file.exists():
        try:
            with open(output_file) as f:
                prev = json.load(f)
            if "phases" in prev:
                results["phases"] = prev["phases"]
                completed = list(prev["phases"].keys())
                console.print(f"[yellow]Resuming — {len(completed)} phases already done: {completed}[/yellow]")
        except (json.JSONDecodeError, KeyError):
            pass
    return results


def _get_ready_phases(
    phases: list, completed: set[str], running: set[str]
) -> list:
    """Return phases whose dependencies are satisfied and not yet started."""
    ready = []
    for phase in phases:
        name = phase["name"]
        if name in completed or name in running:
            continue
        deps = PHASE_DEPENDENCIES.get(name, [])
        # For 'report' phase, wait for all non-report phases
        if name == "report":
            non_report = {p["name"] for p in phases if p["name"] != "report"}
            if non_report - completed:
                continue
        elif not all(d in completed for d in deps):
            continue
        ready.append(phase)
    return ready


def _count_findings(output_dir: str) -> dict[str, int]:
    """Count findings by severity across all result files."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    results_path = Path(output_dir)
    for json_file in results_path.rglob("*.json"):
        if json_file.name == "pipeline_results.json":
            continue
        try:
            with open(json_file) as f:
                data = json.load(f)
            for item in _extract_findings(data):
                sev = item.get("severity", "info").lower()
                if sev in counts:
                    counts[sev] += 1
        except (json.JSONDecodeError, KeyError):
            continue
    return counts


def _run_sequential(target: str, phases: list, output_dir: str, results: dict) -> dict:
    """Run pipeline phases sequentially."""
    for phase in phases:
        console.print(f"\n[bold]Phase {phase['priority']}: {phase['description']}[/bold]")
        phase_results = _execute_phase(target, phase, output_dir)
        results["phases"][phase["name"]] = phase_results

    return results


def _run_parallel(target: str, phases: list, output_dir: str, results: dict) -> dict:
    """Run pipeline phases respecting dependency graph with concurrency cap."""
    completed = set(results["phases"].keys())
    running = set()
    total = len(phases)

    # Filter out already-completed phases if resuming
    remaining = [p for p in phases if p["name"] not in completed]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[bold green]Pipeline[/bold green]", total=total)

        # Advance progress for completed phases
        progress.advance(task, advance=len(completed))

        while len(completed) < total and remaining:
            ready = _get_ready_phases(remaining, completed, running)
            if not ready:
                # All remaining phases blocked on dependencies — shouldn't happen
                console.print("[red]Deadlock: no phases ready to run[/red]")
                break

            # Apply concurrency cap: only run up to MAX_CONCURRENT_PHASES at once
            to_launch = ready[: MAX_CONCURRENT_PHASES - len(running)]

            with ThreadPoolExecutor(max_workers=len(to_launch)) as executor:
                futures = {}
                for phase in to_launch:
                    running.add(phase["name"])
                    progress.update(
                        task,
                        description=f"[bold]{phase['description']}[/bold]",
                    )
                    futures[executor.submit(_execute_phase, target, phase, output_dir)] = phase

                for future in as_completed(futures):
                    phase = futures[future]
                    running.discard(phase["name"])
                    try:
                        phase_results = future.result()
                        results["phases"][phase["name"]] = phase_results
                        completed.add(phase["name"])
                        progress.advance(task)
                    except Exception as e:
                        console.print(f"  [red]Phase {phase['name']} failed: {e}[/red]")
                        results["phases"][phase["name"]] = {"error": str(e)}
                        completed.add(phase["name"])
                        progress.advance(task)

                    # Live findings counter
                    fc = _count_findings(output_dir)
                    total_findings = sum(fc.values())
                    progress.update(
                        task,
                        description=(
                            f"[bold]{phase['description']}[/bold] "
                            f"[red]C:{fc['critical']}[/red] "
                            f"[yellow]H:{fc['high']}[/yellow] "
                            f"[cyan]M:{fc['medium']}[/cyan] "
                            f"[dim]L:{fc['low']} I:{fc['info']}[/dim] "
                            f"Total:{total_findings}"
                        ),
                    )

    return results


def _execute_phase(target: str, phase: dict, output_dir: str) -> dict:
    """Execute a single pipeline phase."""
    phase_results = {
        "name": phase["name"],
        "description": phase["description"],
        "tools_run": [],
    }

    phase_output = Path(output_dir) / phase["name"]
    phase_output.mkdir(parents=True, exist_ok=True)

    # Import and run tools dynamically
    try:
        from bountykit.recon import subdomain, passive, active
        from bountykit.recon import endpoints as ep, js_analysis, crawler
        from bountykit.scan import web, sqli, xss, ssrf, api
        from bountykit.scan import deserialization, graphql, oauth, takeover
        from bountykit.scan import headers, waf
        from bountykit.scan import ssti, smuggling, race_condition, llm, supply_chain
        from bountykit.scan import cloud_misconfig
        from bountykit.cve import search, monitor
        from bountykit.cloud import aws, multi_cloud

        tool_map = {
            "subdomain": lambda: subdomain.enumerate_subdomains(target, str(phase_output)),
            "passive": lambda: passive.passive_dns(target, str(phase_output)),
            "active": lambda: active.probe_hosts(target, str(phase_output)),
            "endpoints": lambda: ep.discover_all_endpoints(target, str(phase_output)),
            "js_analysis": lambda: js_analysis.discover_js_files(target, str(phase_output)),
            "crawler": lambda: crawler.crawl_deep(target, output_dir=str(phase_output)),
            "web": lambda: web.run_nuclei(target, output_dir=str(phase_output)),
            "sqli": lambda: sqli.test_sqli(target, output_dir=str(phase_output)),
            "xss": lambda: xss.test_xss(target, output_dir=str(phase_output)),
            "ssrf": lambda: ssrf.test_ssrf(target, str(phase_output)),
            "api": lambda: api.test_api(target, output_dir=str(phase_output)),
            "deserialization": lambda: deserialization.scan_all_deserialization(target, str(phase_output)),
            "graphql": lambda: graphql.scan_graphql(target, str(phase_output)),
            "oauth": lambda: oauth.test_redirect_uri(target, str(phase_output)),
            "takeover": lambda: takeover.scan_takeover(target, str(phase_output)),
            "headers": lambda: headers.analyze_headers(target, str(phase_output)),
            "waf": lambda: asyncio.run(waf.WAFScanner(target).run_full_scan()),
            "network": lambda: asyncio.run(_run_network_attacks(target, phase_output)),
            "ssti": lambda: asyncio.run(ssti.SSTITester(target).test_all()),
            "smuggle": lambda: asyncio.run(smuggling.HTTPSmugglingTester(target).test_all()),
            "race_condition": lambda: asyncio.run(race_condition.RaceConditionTester(target).test_all()),
            "llm": lambda: asyncio.run(llm.LLMTester(target).test_all()),
            "supply_chain": lambda: asyncio.run(supply_chain.SupplyChainScanner(target_path=target).scan_project()),
            "aws": lambda: aws.test_aws(bucket=None, test_metadata=True, output_dir=str(phase_output)),
            "multi_cloud": lambda: asyncio.run(multi_cloud.MultiCloudScanner(target=target).scan_all()),
            "cloud_misconfig": lambda: asyncio.run(cloud_misconfig.CloudMisconfigurationScanner(target=target).scan_all()),
            "search": lambda: _run_cve_search(target, str(phase_output)),
            "monitor": lambda: {"status": "monitoring_configured"},
            "markdown": lambda: _generate_reports(target, output_dir),
            "report": lambda: _generate_reports(target, output_dir),
        }

        for tool_name in phase.get("tools", []):
            if tool_name in tool_map:
                try:
                    result = tool_map[tool_name]()
                    phase_results["tools_run"].append({
                        "tool": tool_name,
                        "status": "success",
                    })
                except Exception as e:
                    phase_results["tools_run"].append({
                        "tool": tool_name,
                        "status": "failed",
                        "error": str(e),
                    })

    except ImportError as e:
        phase_results["error"] = f"Import error: {e}"

    return phase_results


async def _run_network_attacks(target: str, phase_output: Path) -> dict:
    """Run all network attack modules (takeover, smuggling, race condition)."""
    from bountykit.scan import takeover, smuggling, race_condition

    results = {}
    async with takeover.NetworkScanner(target) as scanner:
        results["takeover"] = await scanner.scan_all()

    smuggler = smuggling.HTTPSmugglingTester(target)
    results["smuggling"] = await smuggler.test_all()

    racer = race_condition.RaceConditionTester(target)
    results["race_condition"] = await racer.test_all()

    # Save combined results
    output_file = phase_output / "network_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    return {"status": "success", "file": str(output_file), "modules": list(results.keys())}


def _generate_summary(results: dict):
    """Generate pipeline summary."""
    console.print(Panel(
        _format_summary(results),
        title="Pipeline Summary",
        border_style="green",
    ))


def _format_summary(results: dict) -> str:
    """Format summary for display."""
    lines = []
    lines.append(f"[bold]Target:[/bold] {results['target']}")
    lines.append(f"[bold]Scan Type:[/bold] {results['scan_type']}")
    lines.append(f"[bold]Duration:[/bold] {results.get('duration', 0):.1f}s")

    lines.append("\n[bold]Phases Completed:[/bold]")
    for phase_name, phase_data in results.get("phases", {}).items():
        if isinstance(phase_data, dict) and "error" not in phase_data:
            tools_run = len(phase_data.get("tools_run", []))
            lines.append(f"  ✓ {phase_name}: {tools_run} tools run")
        else:
            lines.append(f"  ✗ {phase_name}: failed")

    # Add findings breakdown if output_dir available
    output_dir = results.get("output_dir", "./results")
    fc = _count_findings(output_dir)
    total = sum(fc.values())
    if total > 0:
        lines.append(f"\n[bold]Findings:[/bold] {total} total")
        if fc["critical"]:
            lines.append(f"  [red]Critical: {fc['critical']}[/red]")
        if fc["high"]:
            lines.append(f"  [yellow]High: {fc['high']}[/yellow]")
        if fc["medium"]:
            lines.append(f"  [cyan]Medium: {fc['medium']}[/cyan]")
        if fc["low"]:
            lines.append(f"  Low: {fc['low']}")
        if fc["info"]:
            lines.append(f"  Info: {fc['info']}")

    return "\n".join(lines)


def _generate_reports(target: str, output_dir: str) -> dict:
    """Generate markdown, HTML, and JSON reports from findings.

    Args:
        target: Target that was scanned
        output_dir: Directory containing result files

    Returns:
        Report generation status
    """
    from bountykit.utils.report import (
        generate_markdown_report,
        generate_html_report,
        generate_json_report,
    )

    findings = []
    results_path = Path(output_dir)

    # Collect findings from all JSON result files (including subdirectories)
    for json_file in results_path.rglob("*.json"):
        if json_file.name == "pipeline_results.json":
            continue
        try:
            with open(json_file) as f:
                data = json.load(f)
            findings.extend(_extract_findings(data))
        except (json.JSONDecodeError, KeyError):
            continue

    # Generate reports in all formats
    if findings:
        generate_markdown_report(target, findings, output_path=f"{output_dir}/report.md")
        generate_html_report(target, findings, output_path=f"{output_dir}/report.html")
        generate_json_report(target, findings, output_path=f"{output_dir}/report.json")
        return {"status": "reports_generated", "findings": len(findings), "formats": ["md", "html", "json"]}

    return {"status": "no_findings", "findings": 0}


def _extract_findings(data: dict) -> list:
    """Extract findings from various result formats."""
    findings = []
    if isinstance(data, dict):
        if "findings" in data:
            for item in data["findings"]:
                if isinstance(item, dict):
                    findings.append(_normalize_finding(item))
        elif "severity" in data:
            findings.append(_normalize_finding(data))
        elif "results" in data:
            for item in data["results"]:
                if isinstance(item, dict) and "severity" in item:
                    findings.append(_normalize_finding(item))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "severity" in item:
                findings.append(_normalize_finding(item))
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


def _run_cve_search(target: str, output_dir: str) -> dict:
    """Run CVE search and save results to file."""
    from bountykit.cve import search

    result = search.search_cve(keyword=target)

    # Convert findings to dict format and save
    findings = []
    for f in result.findings:
        findings.append({
            "cve_id": f.cve_id,
            "severity": f.severity,
            "description": f.description,
            "published": f.published,
            "cvss_score": f.cvss_score,
            "epss_score": f.epss_score,
            "known_exploited": f.known_exploited,
            "exploit_available": f.exploit_available,
            "references": f.references,
        })

    output_file = Path(output_dir) / "cve_results.json"
    with open(output_file, "w") as f:
        json.dump({
            "target": target,
            "keyword": target,
            "findings": findings,
            "sources_queried": result.sources_queried,
        }, f, indent=2, default=str)

    return {"status": "success", "findings": len(findings), "file": str(output_file)}


def run_quick_scan(target: str, output_dir: str = "./results") -> dict:
    """Run a quick scan (recon + basic scanning).

    Args:
        target: Target domain
        output_dir: Output directory
    """
    return run_full_pipeline(target, output_dir, scan_type="quick")


def run_recon_only(target: str, output_dir: str = "./results") -> dict:
    """Run reconnaissance only.

    Args:
        target: Target domain
        output_dir: Output directory
    """
    return run_full_pipeline(target, output_dir, scan_type="recon")


def run_scan_only(target: str, output_dir: str = "./results") -> dict:
    """Run vulnerability scanning only.

    Args:
        target: Target URL
        output_dir: Output directory
    """
    return run_full_pipeline(target, output_dir, scan_type="scan")
