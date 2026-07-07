"""Endpoint discovery module.

2026 techniques:
- Wayback Machine + CT logs for historical endpoint discovery
- Arjun/ParamSpider for hidden parameter mining
- API versioning detection (v1/v2/v3 path bruteforce)
- Parameter pollution testing
- GraphQL/REST endpoint fingerprinting
- Source map and .map file discovery
- Hidden API gateway detection (Kong, AWS API Gateway, etc.)
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class EndpointFinding:
    endpoint: str
    source: str
    status: str = "info"
    method: str = "GET"
    evidence: str = ""
    severity: str = "info"


@dataclass
class EndpointResult:
    target: str
    method: str = "combined_endpoints"
    findings: list = field(default_factory=list)
    total_unique: int = 0
    interesting: list = field(default_factory=list)
    api_versions: list = field(default_factory=list)
    parameter_candidates: list = field(default_factory=list)
    errors: list = field(default_factory=list)


class EndpointDiscovery:
    """Discover endpoints, hidden parameters, and API surfaces."""

    INTERESTING_PATTERNS = [
        "admin", "login", "api", "upload", "backup", "config",
        "debug", "test", "dev", "staging", ".env", "git",
        "wp-admin", "phpmyadmin", "console", "swagger", "graphql",
        ".well-known", "openapi", "actuator", "metrics", "trace",
        "health", "ready", "prometheus", "grafana", "_debug",
    ]

    API_VERSION_PATHS = ["/v1/", "/v2/", "/v3/", "/v4/", "/api/v1/", "/api/v2/"]

    PARAM_PATTERNS = [
        re.compile(r"[?&](\w+)="),
        re.compile(r'"(\w+)":\s*["\']'),
        re.compile(r"(\w+)\s*:\s*request\."),
    ]

    MAP_FILE_PATTERN = re.compile(r'//#\s*sourceMappingURL=(.+\.map)')

    def __init__(self, timeout: int = 30, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def _fetch(self, url: str, client: httpx.AsyncClient) -> Optional[httpx.Response]:
        try:
            resp = await client.get(url, follow_redirects=True, timeout=self.timeout)
            return resp
        except Exception as e:
            logger.debug(f"Fetch failed for {url}: {e}")
            return None

    def discover_wayback_urls(self, target: str, output_dir: str = "./results") -> dict:
        """Discover historical URLs via Wayback Machine."""
        results = {"target": target, "method": "waybackurls", "urls": [], "total": 0}
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Querying Wayback Machine for {target}")

        try:
            cmd = ["gau", target, "--threads", "5", "--silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
                results["urls"] = urls
                results["total"] = len(urls)
        except FileNotFoundError:
            try:
                cmd = f'echo "{target}" | waybackurls'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
                if result.returncode == 0:
                    urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
                    results["urls"] = urls
                    results["total"] = len(urls)
            except Exception as e:
                logger.warning(f"Wayback tools not available: {e}")
        except subprocess.TimeoutExpired:
            logger.warning("gau timed out")

        results["interesting"] = [
            u for u in results["urls"]
            if any(p in u.lower() for p in self.INTERESTING_PATTERNS)
        ]
        output_file = Path(output_dir) / "wayback_urls.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        return results

    def discover_parameters(self, target: str, output_dir: str = "./results") -> dict:
        """Discover hidden parameters using Arjun."""
        results = {"target": target, "method": "arjun", "parameters": []}
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Discovering parameters with Arjun for {target}")

        try:
            cmd = ["arjun", "-u", target, "-oJ", "-", "--silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, dict) and "parameters" in data:
                        results["parameters"] = data["parameters"]
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and "parameters" in item:
                                results["parameters"].extend(item["parameters"])
                except json.JSONDecodeError:
                    for line in result.stdout.splitlines():
                        try:
                            data = json.loads(line)
                            if "parameters" in data:
                                results["parameters"].extend(data["parameters"])
                        except json.JSONDecodeError:
                            continue
                results["parameters"] = list(set(results["parameters"]))
        except FileNotFoundError:
            logger.warning("Arjun not installed")
        except subprocess.TimeoutExpired:
            logger.warning("Arjun timed out")

        output_file = Path(output_dir) / "parameters.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        return results

    def mine_paramspider(self, target: str, output_dir: str = "./results") -> dict:
        """Mine parameters using ParamSpider."""
        results = {"target": target, "method": "paramspider", "urls_with_params": []}
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Mining parameters with ParamSpider for {target}")

        try:
            cmd = ["paramspider", "-d", target, "-q"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
                results["urls_with_params"] = urls
        except FileNotFoundError:
            logger.warning("ParamSpider not installed")
        except subprocess.TimeoutExpired:
            logger.warning("ParamSpider timed out")

        output_file = Path(output_dir) / "paramspider.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        return results

    async def detect_api_versions(self, base_url: str) -> list:
        """Detect API versioning by probing common version paths."""
        findings = []
        async with httpx.AsyncClient(verify=False) as client:
            for path in self.API_VERSION_PATHS:
                url = f"{base_url.rstrip('/')}{path}"
                resp = await self._fetch(url, client)
                if resp and resp.status_code < 404:
                    findings.append({
                        "path": path,
                        "status_code": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "alive": True,
                    })
        return findings

    async def detect_source_maps(self, urls: list, client: httpx.AsyncClient) -> list:
        """Discover exposed source maps (.map files)."""
        findings = []
        for url in urls[:50]:
            resp = await self._fetch(url, client)
            if resp and resp.status_code == 200:
                for match in self.MAP_FILE_PATTERN.findall(resp.text):
                    map_url = match if match.startswith("http") else f"{url.rsplit('/', 1)[0]}/{match}"
                    findings.append({"source_url": url, "map_url": map_url})
                if ".map" in resp.headers.get("content-type", ""):
                    findings.append({"source_url": url, "map_url": url, "direct_map": True})
        return findings

    async def detect_api_gateway(self, base_url: str) -> list:
        """Detect API gateway technologies."""
        findings = []
        gateway_signatures = {
            "kong": ["x-kong-upstream-latency", "x-kong-proxy-latency", "via: 1.1 kong"],
            "aws_api_gateway": ["x-amzn-requestid", "x-amz-apigw-id", "x-amz-cf-id"],
            "cloudflare_workers": ["cf-ray", "cf-connecting-ip"],
            "nginx_unit": ["server: Unit"],
            "traefik": ["x-traefik", "via: traefik"],
            "envoy": ["x-envoy-upstream-service-time", "x-envoy-decorator"],
            "tyk": ["x-tyk-api-gateway"],
            "gravitee": ["x-gravitee"],
        }
        async with httpx.AsyncClient(verify=False) as client:
            resp = await self._fetch(base_url, client)
            if resp:
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                for gw_name, sigs in gateway_signatures.items():
                    for sig in sigs:
                        if any(sig.lower() in k or sig.lower() in v for k, v in headers_lower.items()):
                            findings.append({"gateway": gw_name, "evidence": sig})
                            break
        return findings

    async def run_full_scan(self, target: str, output_dir: str = "./results") -> EndpointResult:
        """Run full endpoint discovery pipeline."""
        result = EndpointResult(target=target)
        os.makedirs(output_dir, exist_ok=True)

        logger.info(f"Running endpoint discovery for {target}")

        base_url = target if target.startswith("http") else f"https://{target}"

        # Historical endpoints
        wb = self.discover_wayback_urls(target, output_dir)
        all_urls = set(wb.get("urls", []))

        # ParamSpider
        ps = self.mine_paramspider(target, output_dir)
        all_urls.update(ps.get("urls_with_params", []))

        # Arjun parameters
        arjun = self.discover_parameters(base_url, output_dir)
        result.parameter_candidates = arjun.get("parameters", [])

        result.total_unique = len(all_urls)
        result.interesting = sorted([
            u for u in all_urls
            if any(p in u.lower() for p in self.INTERESTING_PATTERNS)
        ])

        # Async scans
        url_list = sorted(all_urls)[:100]
        async with httpx.AsyncClient(verify=False) as client:
            result.api_versions = await self.detect_api_versions(base_url)
            result.findings.extend([
                EndpointFinding(endpoint=v["path"], source="api_versioning",
                                status="alive", evidence=f"HTTP {v['status_code']}")
                for v in result.api_versions
            ])
            maps = await self.detect_source_maps(url_list, client)
            for m in maps:
                result.findings.append(EndpointFinding(
                    endpoint=m["map_url"], source="source_map",
                    severity="medium", evidence=f"Exposed map from {m['source_url']}"
                ))

        # Save
        output_file = Path(output_dir) / "endpoints.json"
        with open(output_file, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)

        logger.info(f"Found {result.total_unique} unique endpoints, {len(result.findings)} findings")
        return result


def discover_wayback_urls(target: str, output_dir: str = "./results") -> dict:
    disc = EndpointDiscovery()
    return disc.discover_wayback_urls(target, output_dir)


def discover_parameters(target: str, output_dir: str = "./results") -> dict:
    disc = EndpointDiscovery()
    return disc.discover_parameters(target, output_dir)


def mine_paramspider(target: str, output_dir: str = "./results") -> dict:
    disc = EndpointDiscovery()
    return disc.mine_paramspider(target, output_dir)


def discover_all_endpoints(target: str, output_dir: str = "./results") -> dict:
    """Run all endpoint discovery tools and merge results."""
    disc = EndpointDiscovery()
    import asyncio
    result = asyncio.get_event_loop().run_until_complete(
        disc.run_full_scan(target, output_dir)
    )
    return asdict(result)
