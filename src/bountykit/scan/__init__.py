"""Scan modules — web, sqli, xss, ssrf, api, deserialization, graphql, oauth, takeover, headers, waf, template_builder."""

from bountykit.scan.web import run_nuclei
from bountykit.scan.sqli import run_sqlmap
from bountykit.scan.xss import run_dalfox
from bountykit.scan.ssrf import test_ssrf
from bountykit.scan.api import test_api
from bountykit.scan.deserialization import (
    detect_java_deserialization, detect_php_deserialization, detect_dotnet_deserialization,
    scan_all_deserialization,
)
from bountykit.scan.graphql import test_introspection, test_batch_queries, test_query_complexity, scan_graphql
from bountykit.scan.oauth import test_redirect_uri, test_token_theft, analyze_jwt
from bountykit.scan.takeover import scan_takeover
from bountykit.scan.headers import analyze_headers
from bountykit.scan.waf import detect_waf, test_waf_bypass, WAFScanner
from bountykit.scan.websocket import WebSocketScanner, scan_websocket
from bountykit.scan.cloud_misconfig import CloudMisconfigurationScanner
from bountykit.scan.template_builder import build_sqli_template, build_xss_template, build_idor_template, validate_template

# Aliases
WFBDetector = WAFScanner

__all__ = [
    "run_nuclei", "run_sqlmap", "run_dalfox", "test_ssrf", "test_api",
    "detect_java_deserialization", "detect_php_deserialization", "detect_dotnet_deserialization", "scan_all_deserialization",
    "test_introspection", "test_batch_queries", "test_query_complexity", "scan_graphql",
    "test_redirect_uri", "test_token_theft", "analyze_jwt",
    "scan_takeover", "analyze_headers", "detect_waf", "test_waf_bypass",
    "WAFScanner", "WFBDetector", "WebSocketScanner", "scan_websocket", "CloudMisconfigurationScanner",
    "build_sqli_template", "build_xss_template", "build_idor_template", "validate_template",
]
