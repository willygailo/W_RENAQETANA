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
    cwe_ids: List[str] = field(default_factory=list)
    github_advisory_url: str = ""
    vulmon_url: str = ""
    epss_score: float = 0.0
    known_exploited: bool = False


@dataclass
class CVESearchResult:
    """Complete CVE search result."""
    keyword: str
    findings: List[CVEFinding] = field(default_factory=list)
    total_results: int = 0
    timestamp: float = field(default_factory=time.time)
    sources_queried: List[str] = field(default_factory=list)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts

    @property
    def exploit_summary(self) -> Dict[str, int]:
        return {
            "with_exploits": sum(1 for f in self.findings if f.exploit_available),
            "known_exploited": sum(1 for f in self.findings if f.known_exploited),
            "total": len(self.findings),
        }


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 2026 Exploit Intelligence Sources
EXPLOIT_SOURCES = {
    "exploit_db": "https://www.exploit-db.com/search?q=",
    "github_exploits": "https://api.github.com/search/repositories?q=",
    "vulmon": "https://vulmon.com/search?q=",
    "packetstorm": "https://packetstormsecurity.com/search?q=",
}

# CISA Known Exploited Vulnerabilities (KEV) catalog
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# EPSS (Exploit Prediction Scoring System) API
EPSS_API = "https://api.first.org/data/v1/epss"


def search_cve(
    keyword: str,
    year: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 20,
    include_exploits: bool = True,
    check_kev: bool = True,
    check_epss: bool = True,
    search_github_advisory: bool = True,
) -> CVESearchResult:
    """Search CVE databases with 2026 exploit intelligence.

    Args:
        keyword: Search keyword (e.g., "apache", "nginx", "log4j")
        year: Filter by year (e.g., "2026")
        severity: Filter by severity (HIGH, CRITICAL)
        limit: Maximum results to return
        include_exploits: Check for available exploits
        check_kev: Check CISA Known Exploited Vulnerabilities catalog
        check_epss: Check EPSS exploit prediction scores
        search_github_advisory: Search GitHub Security Advisories
    """
    result = CVESearchResult(keyword=keyword)

    # Load CISA KEV catalog if needed
    kev_cves = set()
    if check_kev:
        kev_cves = _load_kev_catalog()
        if kev_cves:
            result.sources_queried.append("CISA_KEV")

    # Search NVD
    _search_nvd(keyword, year, severity, limit, include_exploits, kev_cves, result)

    # Search GitHub Security Advisories
    if search_github_advisory:
        _search_github_advisories(keyword, severity, limit, result)

    # Enrich with EPSS scores
    if check_epss and result.findings:
        cve_ids = [f.cve_id for f in result.findings]
        epss_scores = _fetch_epss_scores(cve_ids)
        for finding in result.findings:
            if finding.cve_id in epss_scores:
                finding.epss_score = epss_scores[finding.cve_id]
                result.sources_queried.append("EPSS")

    logger.info(
        f"Found {len(result.findings)} CVEs from {len(result.sources_queried)} sources"
    )
    return result


def _search_nvd(
    keyword: str,
    year: Optional[str],
    severity: Optional[str],
    limit: int,
    include_exploits: bool,
    kev_cves: set,
    result: CVESearchResult,
):
    """Search NVD API with retry logic."""
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
            for attempt in range(3):
                try:
                    resp = client.get(NVD_API_BASE, params=params)
                    if resp.status_code == 200:
                        break
                    elif resp.status_code == 403:
                        # Rate limited, back off
                        time.sleep(2 ** (attempt + 1))
                        continue
                    else:
                        logger.warning(f"NVD API returned status {resp.status_code}")
                        return
                except httpx.TimeoutException:
                    if attempt == 2:
                        logger.warning("NVD API timeout after 3 attempts")
                        return
                    time.sleep(2 ** attempt)
                    continue

            data = resp.json()
            result.sources_queried.append("NVD")

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
                    cwe_ids=_extract_cwe_ids(cve),
                    known_exploited=cve_id in kev_cves,
                )

                # Check for exploits if requested
                if include_exploits:
                    finding.exploit_available, finding.exploit_links = _check_exploits(
                        cve_id, keyword
                    )

                result.findings.append(finding)

            result.total_results = data.get("totalResults", len(result.findings))

    except Exception as e:
        logger.error(f"Error searching NVD: {e}")


def _load_kev_catalog() -> set:
    """Load CISA Known Exploited Vulnerabilities catalog."""
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(CISA_KEV_URL)
            if resp.status_code == 200:
                data = resp.json()
                return {vuln["cveID"] for vuln in data.get("vulnerabilities", [])}
    except Exception as e:
        logger.debug(f"Failed to load KEV catalog: {e}")
    return set()


def _fetch_epss_scores(cve_ids: List[str]) -> Dict[str, float]:
    """Fetch EPSS scores for CVE IDs."""
    scores = {}
    if not cve_ids:
        return scores

    try:
        # EPSS API accepts comma-separated CVE IDs
        ids_param = ",".join(cve_ids[:100])  # API limit
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(EPSS_API, params={"cve": ids_param})
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve", "")
                    epss = item.get("epss", 0.0)
                    scores[cve_id] = epss
    except Exception as e:
        logger.debug(f"Failed to fetch EPSS scores: {e}")

    return scores


def _search_github_advisories(
    keyword: str,
    severity: Optional[str],
    limit: int,
    result: CVESearchResult,
):
    """Search GitHub Security Advisories API."""
    try:
        # GraphQL query for GitHub advisories
        query = f"{keyword} type:reviewed"
        if severity:
            severity_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
            gh_severity = severity_map.get(severity.upper(), severity.upper())
            query += f" severity:{gh_severity}"

        api_url = "https://api.github.com/advisories"
        params = {
            "type": "reviewed",
            "affects": keyword,
            "per_page": min(limit, 30),
        }

        with httpx.Client(timeout=15.0) as client:
            resp = client.get(api_url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                result.sources_queried.append("GitHub_Advisory")

                for advisory in data:
                    cve_id = advisory.get("cve_id", "")
                    if not cve_id:
                        continue

                    # Check if we already have this CVE from NVD
                    existing = next(
                        (f for f in result.findings if f.cve_id == cve_id), None
                    )
                    if existing:
                        # Enrich existing finding
                        existing.github_advisory_url = advisory.get("html_url", "")
                        if advisory.get("severity"):
                            existing.severity = advisory["severity"].upper()
                        continue

                    # Create new finding from GitHub advisory
                    severity_val = (advisory.get("severity") or "unknown").upper()
                    finding = CVEFinding(
                        cve_id=cve_id,
                        severity=severity_val,
                        cvss_score=advisory.get("cvss", {}).get("score", 0.0)
                        if advisory.get("cvss")
                        else 0.0,
                        title=advisory.get("summary", "No title"),
                        description=advisory.get("description", "No description"),
                        published=advisory.get("published_at", ""),
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        github_advisory_url=advisory.get("html_url", ""),
                        affected_products=[
                            p.get("package", {}).get("name", "")
                            for p in advisory.get("vulnerabilities", [])
                            if p.get("package")
                        ],
                        cwe_ids=[
                            c.get("cwe_id", "")
                            for c in advisory.get("cwes", [])
                            if c.get("cwe_id")
                        ],
                    )
                    result.findings.append(finding)

    except Exception as e:
        logger.debug(f"GitHub Advisory search failed: {e}")


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


def _extract_cwe_ids(cve: dict) -> List[str]:
    """Extract CWE IDs from CVE data."""
    cwe_ids = []
    weaknesses = cve.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            cwe_value = desc.get("value", "")
            if cwe_value.startswith("CWE-"):
                cwe_ids.append(cwe_value)
    return list(set(cwe_ids))


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
