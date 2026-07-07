"""CVE search module — 2026 exploit intelligence."""

import json
import os
import re
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CVEFinding:
    """Single CVE finding."""
    cve_id: str
    severity: str
    cvss_score: float
    title: str
    description: str
    published: str
    url: str
    exploit_available: bool = False
    exploit_links: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class CVESearchResult:
    """Complete CVE search result."""
    keyword: str
    findings: List[CVEFinding] = field(default_factory=list)
    total_results: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 2026 Exploit Intelligence Sources
EXPLOIT_SOURCES = {
    "exploit_db": "https://www.exploit-db.com/search?q=",
    "github_exploits": "https://api.github.com/search/repositories?q=",
    "vulmon": "https://vulmon.com/search?q=",
    "packetstorm": "https://packetstormsecurity.com/search?q=",
}


def search_cve(
    keyword: str,
    year: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 20,
    include_exploits: bool = True,
) -> CVESearchResult:
    """Search CVE databases with 2026 exploit intelligence.

    Args:
        keyword: Search keyword (e.g., "apache", "nginx", "log4j")
        year: Filter by year (e.g., "2026")
        severity: Filter by severity (HIGH, CRITICAL)
        limit: Maximum results to return
        include_exploits: Check for available exploits
    """
    result = CVESearchResult(keyword=keyword)

    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 200),
        }

        if year:
            start_date = f"{year}-01-01T00:00:00.000"
            end_date = f"{year}-12-31T23:59:59.999"
            params["pubStartDate"] = start_date
            params["pubEndDate"] = end_date

        logger.info(f"Searching NVD for: {keyword}")

        with httpx.Client(timeout=30.0) as client:
            resp = client.get(NVD_API_BASE, params=params)

            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")

                    # Get severity from CVSS
                    severity_score, cvss_score = _extract_severity(cve)

                    # Filter by severity if specified
                    if severity and severity_score:
                        if severity.upper() not in severity_score.upper():
                            continue

                    finding = CVEFinding(
                        cve_id=cve_id,
                        severity=severity_score or "UNKNOWN",
                        cvss_score=cvss_score or 0.0,
                        title=_extract_title(cve),
                        description=_extract_description(cve),
                        published=cve.get("published", ""),
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        affected_products=_extract_products(cve),
                        references=_extract_references(cve),
                    )

                    # Check for exploits if requested
                    if include_exploits:
                        finding.exploit_available, finding.exploit_links = _check_exploits(
                            cve_id, keyword
                        )

                    result.findings.append(finding)

                result.total_results = data.get("totalResults", len(result.findings))
                logger.info(f"Found {len(result.findings)} CVEs")
            else:
                logger.warning(f"NVD API returned status {resp.status_code}")

    except Exception as e:
        logger.error(f"Error searching NVD: {e}")

    return result


def _extract_severity(cve: dict) -> tuple[Optional[str], Optional[float]]:
    """Extract severity and CVSS score from CVE data."""
    metrics = cve.get("metrics", {})

    # Try CVSS v3.1 first
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31:
        cvss_data = cvss_v31[0].get("cvssData", {})
        return cvss_data.get("baseSeverity"), cvss_data.get("baseScore")

    # Try CVSS v3.0
    cvss_v30 = metrics.get("cvssMetricV30", [])
    if cvss_v30:
        cvss_data = cvss_v30[0].get("cvssData", {})
        return cvss_data.get("baseSeverity"), cvss_data.get("baseScore")

    # Try CVSS v2.0
    cvss_v2 = metrics.get("cvssMetricV2", [])
    if cvss_v2:
        cvss_data = cvss_v2[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = "HIGH" if score and score >= 7.0 else "MEDIUM" if score and score >= 4.0 else "LOW"
        return severity, score

    return None, None


def _extract_title(cve: dict) -> str:
    """Extract title from CVE."""
    descriptions = cve.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            text = desc.get("value", "")
            # Truncate to first sentence
            if "." in text:
                return text.split(".")[0] + "."
            return text[:100]
    return "No description available"


def _extract_description(cve: dict) -> str:
    """Extract full description from CVE."""
    descriptions = cve.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return "No description available"


def _extract_products(cve: dict) -> List[str]:
    """Extract affected products from CVE."""
    products = []
    configurations = cve.get("configurations", [])
    
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                # Extract product name from CPE
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    products.append(f"{vendor}/{product}")
    
    return list(set(products))[:5]  # Limit to 5 products


def _extract_references(cve: dict) -> List[str]:
    """Extract references from CVE."""
    refs = cve.get("references", [])
    return [ref.get("url", "") for ref in refs[:5]]


def _check_exploits(cve_id: str, keyword: str) -> tuple[bool, List[str]]:
    """Check for available exploits."""
    exploit_links = []
    
    try:
        # Search for exploits on GitHub
        github_query = f"{cve_id} exploit"
        github_url = f"https://api.github.com/search/repositories?q={github_query}"
        
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(github_url)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", [])[:3]:
                    exploit_links.append(item.get("html_url", ""))
    except Exception:
        pass
    
    return len(exploit_links) > 0, exploit_links
