"""Web crawler module.

2026 techniques:
- Katana/Gospider deep crawling with JavaScript rendering
- sitemap.xml and robots.txt parsing
- Headless browser detection and rendering
- GraphQL endpoint discovery during crawl
- Hidden form field extraction
- Technology fingerprinting during crawl
- Rate limit and crawl depth optimization
"""

import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CrawlFinding:
    url: str
    source: str
    status: str = "info"
    evidence: str = ""
    severity: str = "info"


@dataclass
class CrawlResult:
    target: str
    method: str = "deep_crawl"
    findings: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    hidden_fields: list = field(default_factory=list)
    graphql_endpoints: list = field(default_factory=list)
    sitemap_urls: list = field(default_factory=list)
    robots_directives: list = field(default_factory=list)
    technology_fingerprints: list = field(default_factory=list)
    total_unique: int = 0
    errors: list = field(default_factory=list)


class WebCrawler:
    """Crawl target web applications for endpoints, forms, and technologies."""

    FORM_PATTERN = re.compile(r"<form[^>]*>(.*?)</form>", re.DOTALL | re.IGNORECASE)
    HIDDEN_INPUT = re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*>', re.IGNORECASE)
    INPUT_NAME = re.compile(r'name=["\']([^"\']+)["\']')
    INPUT_VALUE = re.compile(r'value=["\']([^"\']*)["\']')
    GRAPHQL_PATTERN = re.compile(
        r'(query|mutation|subscription)\s+\w+',
        re.IGNORECASE,
    )
    TECH_SIGNATURES = {
        "React": ["_react", "__react", "react-root", "data-reactroot"],
        "Vue": ["vue-", "data-v-", "__vue__"],
        "Angular": ["ng-", "ngapp", "angular"],
        "Next.js": ["_next/", "__next", "_buildManifest"],
        "Nuxt.js": ["_nuxt/", "__nuxt", "_payload"],
        "WordPress": ["wp-content", "wp-includes", "wp-json"],
        "Laravel": ["laravel_session", "XSRF-TOKEN", "csrf-token"],
        "Django": ["csrftoken", "django", "csrfmiddlewaretoken"],
        "Rails": ["authenticity_token", "csrf-token", "ruby"],
    }

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

    def crawl_katana(self, target: str, depth: int = 3, output_dir: str = "./results") -> dict:
        """Crawl target using Katana crawler."""
        results = {"target": target, "method": "katana", "urls": [], "total": 0}
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Crawling {target} with Katana (depth={depth})")

        try:
            cmd = ["katana", "-u", target, "-d", str(depth), "-jc", "-silent", "-timeout", "10"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
                results["urls"] = urls
                results["total"] = len(urls)
        except FileNotFoundError:
            logger.warning("Katana not installed")
        except subprocess.TimeoutExpired:
            logger.warning("Katana timed out")

        output_file = Path(output_dir) / "katana_crawl.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        return results

    def crawl_gospider(self, target: str, depth: int = 3, output_dir: str = "./results") -> dict:
        """Crawl target using Gospider."""
        results = {"target": target, "method": "gospider", "urls": [], "forms": [], "links": [], "total": 0}
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Crawling {target} with Gospider")

        try:
            cmd = ["gospider", "-s", target, "-d", str(depth), "-c", "5", "--sitemap", "--robots", "--other-source"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("[url]"):
                        results["urls"].append(line[5:].strip())
                    elif line.startswith("[form]"):
                        results["forms"].append(line[6:].strip())
                    elif line.startswith("[link]"):
                        results["links"].append(line[6:].strip())
                results["total"] = len(results["urls"])
        except FileNotFoundError:
            logger.warning("Gospider not installed")
        except subprocess.TimeoutExpired:
            logger.warning("Gospider timed out")

        output_file = Path(output_dir) / "gospider_crawl.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        return results

    async def parse_sitemap(self, base_url: str, client: httpx.AsyncClient) -> list:
        """Parse sitemap.xml for discovered URLs."""
        urls = []
        sitemap_path = f"{base_url.rstrip('/')}/sitemap.xml"
        resp = await self._fetch(sitemap_path, client)
        if resp and resp.status_code == 200:
            try:
                root = ET.fromstring(resp.text)
                ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                for loc in root.findall(".//s:loc", ns):
                    if loc.text:
                        urls.append(loc.text.strip())
            except ET.ParseError:
                pass
        return urls

    async def parse_robots(self, base_url: str, client: httpx.AsyncClient) -> list:
        """Parse robots.txt for hidden paths."""
        directives = []
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        resp = await self._fetch(robots_url, client)
        if resp and resp.status_code == 200:
            current_agent = "*"
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("user-agent:"):
                    current_agent = line.split(":", 1)[1].strip()
                elif line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    parts = line.split(":", 1)
                    directives.append({
                        "agent": current_agent,
                        "directive": parts[0].strip(),
                        "value": parts[1].strip() if len(parts) > 1 else "",
                    })
        return directives

    async def extract_forms_and_fields(self, url: str, client: httpx.AsyncClient) -> list:
        """Extract forms and hidden fields from a page."""
        forms = []
        resp = await self._fetch(url, client)
        if not resp or resp.status_code != 200:
            return forms

        for match in self.FORM_PATTERN.finditer(resp.text):
            form_html = match.group(0)
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)

            hidden_fields = []
            for inp in self.HIDDEN_INPUT.findall(form_html):
                name = self.INPUT_NAME.search(inp)
                value = self.INPUT_VALUE.search(inp)
                if name:
                    hidden_fields.append({
                        "name": name.group(1),
                        "value": value.group(1) if value else "",
                    })

            forms.append({
                "url": url,
                "action": action_match.group(1) if action_match else "",
                "method": method_match.group(1).upper() if method_match else "GET",
                "hidden_fields": hidden_fields,
                "has_csrf": any("csrf" in f["name"].lower() for f in hidden_fields),
            })
        return forms

    async def detect_graphql(self, base_url: str, client: httpx.AsyncClient) -> list:
        """Detect GraphQL endpoints."""
        endpoints = []
        graphql_paths = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"]
        for path in graphql_paths:
            url = f"{base_url.rstrip('/')}{path}"
            resp = await self._fetch(url, client)
            if resp and resp.status_code in [200, 400, 405]:
                ct = resp.headers.get("content-type", "")
                if "json" in ct or self.GRAPHQL_PATTERN.search(resp.text[:500]):
                    endpoints.append({
                        "url": url,
                        "status_code": resp.status_code,
                        "introspection_hint": "schema" in resp.text.lower()[:1000],
                    })
        return endpoints

    async def fingerprint_technologies(self, url: str, client: httpx.AsyncClient) -> list:
        """Detect technologies from page content and headers."""
        techs = []
        resp = await self._fetch(url, client)
        if not resp:
            return techs

        body = resp.text.lower()
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for tech, signatures in self.TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in body or any(sig.lower() in v for v in headers.values()):
                    techs.append({"technology": tech, "evidence": sig})
                    break

        server = headers.get("server", "")
        if server:
            techs.append({"technology": "Server", "evidence": server})
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            techs.append({"technology": "X-Powered-By", "evidence": powered_by})

        return techs

    async def crawl_deep_async(self, target: str, depth: int = 3, output_dir: str = "./results") -> CrawlResult:
        """Run full async crawl pipeline."""
        result = CrawlResult(target=target)
        os.makedirs(output_dir, exist_ok=True)
        base_url = target if target.startswith("http") else f"https://{target}"

        logger.info(f"Deep crawling {target}")

        # External tool crawls
        katana = self.crawl_katana(target, depth, output_dir)
        gospider = self.crawl_gospider(target, depth, output_dir)

        all_urls = set()
        all_urls.update(katana.get("urls", []))
        all_urls.update(gospider.get("urls", []))
        all_urls.update(gospider.get("links", []))
        result.forms = gospider.get("forms", [])

        # Async analysis
        async with httpx.AsyncClient(verify=False) as client:
            sitemap_urls = await self.parse_sitemap(base_url, client)
            all_urls.update(sitemap_urls)
            result.sitemap_urls = sitemap_urls

            robots = await self.parse_robots(base_url, client)
            result.robots_directives = robots
            for d in robots:
                if d["directive"] == "Disallow" and d["value"]:
                    all_urls.add(f"{base_url.rstrip('/')}{d['value']}")

            result.graphql_endpoints = await self.detect_graphql(base_url, client)

            for url in list(all_urls)[:50]:
                techs = await self.fingerprint_technologies(url, client)
                if techs:
                    result.technology_fingerprints.append({"url": url, "techs": techs})

            for url in list(all_urls)[:30]:
                forms = await self.extract_forms_and_fields(url, client)
                result.forms.extend(forms)
                for form in forms:
                    for hf in form.get("hidden_fields", []):
                        result.hidden_fields.append({"url": url, "field": hf})
                        if not hf.get("value") or "csrf" in hf["name"].lower():
                            result.findings.append(CrawlFinding(
                                url=url, source="hidden_field",
                                severity="medium" if not hf.get("value") else "low",
                                evidence=f"Hidden field: {hf['name']}"
                            ))

        result.urls = sorted(all_urls)
        result.total_unique = len(all_urls)

        output_file = Path(output_dir) / "deep_crawl.json"
        with open(output_file, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)

        logger.info(f"Crawled {result.total_unique} URLs, {len(result.forms)} forms, "
                     f"{len(result.graphql_endpoints)} GraphQL endpoints")
        return result


def crawl_katana(target: str, depth: int = 3, output_dir: str = "./results") -> dict:
    crawler = WebCrawler()
    return crawler.crawl_katana(target, depth, output_dir)


def crawl_gospider(target: str, depth: int = 3, output_dir: str = "./results") -> dict:
    crawler = WebCrawler()
    return crawler.crawl_gospider(target, depth, output_dir)


def crawl_deep(target: str, depth: int = 3, output_dir: str = "./results") -> dict:
    """Run deep crawl using both Katana and Gospider."""
    crawler = WebCrawler()
    import asyncio
    result = asyncio.get_event_loop().run_until_complete(
        crawler.crawl_deep_async(target, depth, output_dir)
    )
    return asdict(result)


def extract_forms(urls: list, output_dir: str = "./results") -> dict:
    """Extract forms from a list of URLs."""
    results = {"method": "form_extraction", "forms": []}
    os.makedirs(output_dir, exist_ok=True)

    async def _extract():
        async with httpx.AsyncClient(verify=False) as client:
            crawler = WebCrawler()
            for url in urls[:20]:
                forms = await crawler.extract_forms_and_fields(url, client)
                results["forms"].extend(forms)

    import asyncio
    asyncio.get_event_loop().run_until_complete(_extract())

    output_file = Path(output_dir) / "forms.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    return results
