"""CVE search module."""

import json
import os
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cve(
    keyword: str,
    year: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 20,
) -> list:
    """Search CVE databases for vulnerabilities.

    Uses NIST NVD API for CVE data.

    Args:
        keyword: Search keyword (e.g., "apache", "nginx", "log4j")
        year: Filter by year (e.g., "2024")
        severity: Filter by severity (HIGH, CRITICAL)
        limit: Maximum results to return
    """
    results = []

    try:
        import requests

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 200),
        }

        if year:
            start_date = f"{year}-01-01T00:00:00.000"
            end_date = f"{year}-12-31T23:59:59.999"
            params["pubStartDate"] = start_date
            params["pubEndDate"] = end_date

        console.print(f"  [dim]Searching NVD for: {keyword}[/dim]")
        resp = requests.get(NVD_API_BASE, params=params, timeout=30)

        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # Get severity from CVSS
                severity_score = _extract_severity(cve)

                # Filter by severity if specified
                if severity and severity_score:
                    if severity.upper() not in severity_score.upper():
                        continue

                results.append({
                    "id": cve_id,
                    "description": _extract_description(cve),
                    "severity": severity_score or "UNKNOWN",
                    "published": cve.get("published", ""),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })

            console.print(f"  [green]✓ Found {len(results)} CVEs[/green]")
        else:
            console.print(f"  [yellow]NVD API returned status {resp.status_code}[/yellow]")

    except ImportError:
        console.print("  [yellow]requests not installed — skipping NVD search[/yellow]")
    except Exception as e:
        console.print(f"  [red]Error searching NVD: {e}[/red]")

    return results


def _extract_severity(cve: dict) -> Optional[str]:
    """Extract severity from CVE data."""
    metrics = cve.get("metrics", {})

    # Try CVSS v3.1 first
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31:
        cvss_data = cvss_v31[0].get("cvssData", {})
        return cvss_data.get("baseSeverity")

    # Try CVSS v3.0
    cvss_v30 = metrics.get("cvssMetricV30", [])
    if cvss_v30:
        cvss_data = cvss_v30[0].get("cvssData", {})
        return cvss_data.get("baseSeverity")

    # Try CVSS v2.0
    cvss_v2 = metrics.get("cvssMetricV2", [])
    if cvss_v2:
        cvss_data = cvss_v2[0].get("cvssData", {})
        score = cvss_data.get("baseScore", 0)
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        return "LOW"

    return None


def _extract_description(cve: dict) -> str:
    """Extract description from CVE data."""
    descriptions = cve.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""
