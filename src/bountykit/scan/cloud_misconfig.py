"""Cloud misconfiguration scanner — web-facing, no credentials required.

Complements bountykit.cloud.multi_cloud (which needs cloud SDK credentials).
This module uses only HTTP requests to detect publicly exposed resources:
- S3 bucket enumeration and open access
- GCS bucket enumeration and public listing
- Azure Blob Storage anonymous access
- Kubernetes API server exposure
- Firebase Realtime Database / Firestore open rules
- AWS Lambda function URL exposure
- AWS EC2 metadata endpoint (SSRF-based)
- Cognito user pool enumeration
- Docker Registry anonymous pull
- Elasticsearch / OpenSearch open clusters

All probes are passive HTTP-based — no cloud SDK or credentials required.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class CloudMisconfigFinding:
    """Single cloud misconfiguration finding."""

    provider: str
    service: str
    severity: str
    title: str
    description: str
    endpoint: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: str = "medium"


@dataclass
class CloudMisconfigResult:
    """Complete cloud misconfiguration scan result."""

    target: str
    findings: list[CloudMisconfigFinding] = field(default_factory=list)
    endpoints_tested: int = 0
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ─── Common Patterns ──────────────────────────────────────────────────────────

S3_BUCKET_RESPONSES = {
    "public_list": "<ListBucketResult>",
    "access_denied": "AccessDenied",
    "not_found": "NoSuchBucket",
}

GCS_BUCKET_RESPONSES = {
    "public_list": "<ListBucketResult>",
    "public_read": "200",
    "access_denied": "AccessDenied",
}

AZURE_BLOB_RESPONSES = {
    "public_list": "<EnumerationResults>",
    "public_read": "200",
    "server_unavailable": "ServerUnavailable",
}

K8S_API_RESPONSES = {
    "unauthenticated": '"kind":"Status"',
    "forbidden": '"reason":"Forbidden"',
    "unauthorized": '"reason":"Unauthorized"',
}

FIREBASE_RESPONSES = {
    "open_database": '"rules"',
    "null_rules": '"rules":{".read":true,".write":true}',
    "denied": "Permission denied",
}

DOCKER_REGISTRY_RESPONSES = {
    "catalog": '{"repositories":',
    "empty_catalog": '{"repositories":[]}',
    "unauthorized": "UNAUTHORIZED",
}

ELASTICSEARCH_RESPONSES = {
    "open_cluster": '"cluster_name"',
    "open_indices": '"indices"',
    "security_exception": "security_exception",
}


# ─── Scanner ──────────────────────────────────────────────────────────────────

class CloudMisconfigurationScanner:
    """Web-facing cloud misconfiguration scanner (no credentials needed)."""

    def __init__(
        self,
        target: str,
        output_dir: str = "./results",
        timeout: int = 10,
        verify_ssl: bool = False,
    ):
        self.target = target.rstrip("/")
        parsed = urlparse(self.target if "://" in self.target else f"https://{self.target}")
        self.domain = parsed.hostname or self.target
        self.output_dir = output_dir
        self.timeout = timeout
        self.findings: list[CloudMisconfigFinding] = []
        self._tested: set[str] = set()
        self.session = httpx.AsyncClient(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
            http2=False,
        )

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=1, max=5))
    async def _request(self, url: str, method: str = "GET", **kwargs) -> httpx.Response:
        """Send HTTP request with retry."""
        return await self.session.request(method, url, **kwargs)

    async def scan_all(self) -> CloudMisconfigResult:
        """Run all cloud misconfiguration checks."""
        import time
        start = time.time()
        result = CloudMisconfigResult(target=self.domain)

        logger.info(f"Starting cloud misconfiguration scan on {self.domain}")

        # Run all scan methods concurrently (capped at 5)
        scan_methods = [
            self._scan_s3_buckets(),
            self._scan_gcs_buckets(),
            self._scan_azure_blobs(),
            self._scan_kubernetes_api(),
            self._scan_firebase(),
            self._scan_lambda_urls(),
            self._scan_ec2_metadata(),
            self._scan_cognito_pools(),
            self._scan_docker_registry(),
            self._scan_elasticsearch(),
        ]

        # Run in batches of 5 to avoid overwhelming the target
        for i in range(0, len(scan_methods), 5):
            batch = scan_methods[i:i + 5]
            await asyncio.gather(*batch, return_exceptions=True)

        result.findings = self.findings
        result.endpoints_tested = len(self._tested)
        result.scan_duration = time.time() - start

        await self.session.aclose()
        logger.info(
            f"Cloud misconfig scan complete: {len(self.findings)} findings "
            f"({result.endpoints_tested} endpoints tested)"
        )
        return result

    # ─── S3 Bucket Checks ─────────────────────────────────────────────────

    async def _scan_s3_buckets(self):
        """Check for open S3 buckets via DNS and common naming patterns."""
        bucket_patterns = [
            self.domain,
            f"{self.domain}-assets",
            f"{self.domain}-backup",
            f"{self.domain}-staging",
            f"{self.domain}-dev",
            f"{self.domain}-prod",
            f"{self.domain}-logs",
            f"{self.domain}-uploads",
            f"{self.domain}-media",
            f"{self.domain}-static",
        ]

        for bucket_name in bucket_patterns:
            s3_url = f"https://{bucket_name}.s3.amazonaws.com"
            if s3_url in self._tested:
                continue
            self._tested.add(s3_url)

            try:
                resp = await self._request(s3_url)
                body = resp.text[:2000]

                if "<ListBucketResult>" in body:
                    # Extract file listing
                    keys = re.findall(r"<Key>([^<]+)</Key>", body)
                    evidence = f"Bucket {bucket_name} is publicly listable. "
                    if keys:
                        evidence += f"Found {len(keys)} objects. First 5: {keys[:5]}"

                    self.findings.append(CloudMisconfigFinding(
                        provider="AWS",
                        service="S3",
                        severity="high",
                        title=f"Open S3 Bucket: {bucket_name}",
                        description=f"S3 bucket '{bucket_name}' allows public listing",
                        endpoint=s3_url,
                        evidence=evidence,
                        remediation="Enable S3 Block Public Access and restrict bucket policy",
                        confidence="high",
                    ))
                    logger.warning(f"Open S3 bucket found: {bucket_name}")

                elif resp.status_code == 200 and "NoSuchBucket" not in body:
                    # Bucket exists but doesn't list — check if individual objects are accessible
                    if keys:
                        test_key = keys[0]
                        obj_resp = await self._request(f"{s3_url}/{test_key}")
                        if obj_resp.status_code == 200:
                            self.findings.append(CloudMisconfigFinding(
                                provider="AWS",
                                service="S3",
                                severity="medium",
                                title=f"S3 Object Publicly Accessible: {bucket_name}",
                                description=f"Object {test_key} in bucket {bucket_name} is publicly readable",
                                endpoint=f"{s3_url}/{test_key}",
                                evidence=f"HTTP {obj_resp.status_code} on object retrieval",
                                remediation="Restrict bucket policy and enable S3 Block Public Access",
                                confidence="high",
                            ))
            except Exception as e:
                logger.debug(f"S3 check failed for {bucket_name}: {e}")

    # ─── GCS Bucket Checks ────────────────────────────────────────────────

    async def _scan_gcs_buckets(self):
        """Check for open Google Cloud Storage buckets."""
        bucket_patterns = [
            self.domain,
            f"{self.domain}-assets",
            f"{self.domain}-backup",
            f"{self.domain}-staging",
            f"{self.domain}-dev",
        ]

        for bucket_name in bucket_patterns:
            gcs_url = f"https://storage.googleapis.com/{bucket_name}"
            if gcs_url in self._tested:
                continue
            self._tested.add(gcs_url)

            try:
                resp = await self._request(gcs_url)
                body = resp.text[:2000]

                if "<ListBucketResult>" in body:
                    keys = re.findall(r"<Key>([^<]+)</Key>", body)
                    self.findings.append(CloudMisconfigFinding(
                        provider="GCP",
                        service="GCS",
                        severity="high",
                        title=f"Open GCS Bucket: {bucket_name}",
                        description=f"GCS bucket '{bucket_name}' allows public listing",
                        endpoint=gcs_url,
                        evidence=f"Found {len(keys)} objects: {keys[:5]}",
                        remediation="Restrict bucket IAM policy to remove allUsers/allAuthenticatedUsers",
                        confidence="high",
                    ))
                    logger.warning(f"Open GCS bucket found: {bucket_name}")
            except Exception as e:
                logger.debug(f"GCS check failed for {bucket_name}: {e}")

    # ─── Azure Blob Checks ────────────────────────────────────────────────

    async def _scan_azure_blobs(self):
        """Check for open Azure Blob Storage containers."""
        storage_patterns = [
            self.domain.replace(".", ""),
            f"{self.domain.replace('.', '')}assets",
            f"{self.domain.replace('.', '')}backup",
        ]

        for account_name in storage_patterns:
            blob_url = f"https://{account_name}.blob.core.windows.net/?comp=list"
            if blob_url in self._tested:
                continue
            self._tested.add(blob_url)

            try:
                resp = await self._request(blob_url)
                body = resp.text[:2000]

                if "<EnumerationResults>" in body:
                    containers = re.findall(r"<Container><Name>([^<]+)</Name>", body)
                    self.findings.append(CloudMisconfigFinding(
                        provider="Azure",
                        service="Blob Storage",
                        severity="high",
                        title=f"Open Azure Blob Account: {account_name}",
                        description=f"Blob storage account '{account_name}' allows anonymous listing",
                        endpoint=blob_url,
                        evidence=f"Containers: {containers[:5]}",
                        remediation="Disable anonymous blob access and configure proper RBAC",
                        confidence="high",
                    ))
                    logger.warning(f"Open Azure Blob account found: {account_name}")
            except Exception as e:
                logger.debug(f"Azure Blob check failed for {account_name}: {e}")

    # ─── Kubernetes API Checks ────────────────────────────────────────────

    async def _scan_kubernetes_api(self):
        """Check for exposed Kubernetes API servers."""
        k8s_endpoints = [
            f"https://{self.domain}:6443",
            f"https://k8s.{self.domain}:6443",
            f"https://api.{self.domain}:6443",
            f"https://kubernetes.{self.domain}:6443",
        ]

        for endpoint in k8s_endpoints:
            if endpoint in self._tested:
                continue
            self._tested.add(endpoint)

            try:
                resp = await self._request(endpoint)
                body = resp.text[:1000]

                if '"kind":"Status"' in body:
                    if '"reason":"Forbidden"' in body or '"reason":"Unauthorized"' in body:
                        self.findings.append(CloudMisconfigFinding(
                            provider="Kubernetes",
                            service="API Server",
                            severity="medium",
                            title=f"Exposed K8s API (Auth Required): {endpoint}",
                            description="Kubernetes API server is reachable and requires authentication",
                            endpoint=endpoint,
                            evidence=body[:500],
                            remediation="Restrict API server access to internal networks via firewall",
                            confidence="medium",
                        ))
                    elif '"reason":"Forbidden"' not in body and '"reason":"Unauthorized"' not in body:
                        # Possibly unauthenticated!
                        self.findings.append(CloudMisconfigFinding(
                            provider="Kubernetes",
                            service="API Server",
                            severity="critical",
                            title=f"Unauthenticated K8s API: {endpoint}",
                            description="Kubernetes API server may allow unauthenticated access",
                            endpoint=endpoint,
                            evidence=body[:500],
                            remediation="Enable authentication, restrict network access immediately",
                            confidence="medium",
                        ))
                        logger.warning(f"Potentially unauthenticated K8s API: {endpoint}")
            except Exception as e:
                logger.debug(f"K8s API check failed for {endpoint}: {e}")

    # ─── Firebase Checks ──────────────────────────────────────────────────

    async def _scan_firebase(self):
        """Check for open Firebase Realtime Databases."""
        firebase_names = [
            self.domain.replace(".", "-"),
            self.domain.replace(".", ""),
            f"{self.domain.split('.')[0]}-prod",
            f"{self.domain.split('.')[0]}-dev",
        ]

        for db_name in firebase_names:
            firebase_url = f"https://{db_name}.firebaseio.com/.json"
            if firebase_url in self._tested:
                continue
            self._tested.add(firebase_url)

            try:
                resp = await self._request(firebase_url)
                body = resp.text[:2000]

                if resp.status_code == 200 and body not in ("null", ""):
                    if "Permission denied" not in body and "unauthorized" not in body.lower():
                        self.findings.append(CloudMisconfigFinding(
                            provider="Firebase",
                            service="Realtime Database",
                            severity="critical",
                            title=f"Open Firebase Database: {db_name}",
                            description=f"Firebase database '{db_name}' allows unauthenticated read access",
                            endpoint=firebase_url,
                            evidence=body[:500],
                            remediation="Configure Firebase Realtime Database security rules to deny public access",
                            confidence="high",
                        ))
                        logger.warning(f"Open Firebase database found: {db_name}")
            except Exception as e:
                logger.debug(f"Firebase check failed for {db_name}: {e}")

    # ─── Lambda Function URL Checks ───────────────────────────────────────

    async def _scan_lambda_urls(self):
        """Check for exposed AWS Lambda function URLs."""
        lambda_patterns = [
            f"https://{self.domain}/lambda",
            f"https://{self.domain}/api/lambda",
            f"https://{self.domain}/.netlify/functions",
        ]

        for url in lambda_patterns:
            if url in self._tested:
                continue
            self._tested.add(url)

            try:
                resp = await self._request(url)
                body = resp.text[:1000]

                # Lambda function URLs return JSON with function info
                if resp.status_code == 200:
                    if '"errorMessage"' in body or '"functionError"' in body:
                        self.findings.append(CloudMisconfigFinding(
                            provider="AWS",
                            service="Lambda",
                            severity="medium",
                            title=f"Exposed Lambda Function URL: {url}",
                            description="Lambda function URL is publicly accessible and leaking error details",
                            endpoint=url,
                            evidence=body[:500],
                            remediation="Restrict Lambda function URL auth or remove public access",
                            confidence="medium",
                        ))
            except Exception as e:
                logger.debug(f"Lambda URL check failed for {url}: {e}")

    # ─── EC2 Metadata Checks ──────────────────────────────────────────────

    async def _scan_ec2_metadata(self):
        """Check for EC2 metadata endpoint access (useful after SSRF discovery)."""
        metadata_url = "http://169.254.169.254/latest/meta-data/"
        if metadata_url in self._tested:
            return
        self._tested.add(metadata_url)

        try:
            resp = await self._request(metadata_url)
            if resp.status_code == 200 and "ami-id" in resp.text:
                self.findings.append(CloudMisconfigFinding(
                    provider="AWS",
                    service="EC2 Metadata",
                    severity="critical",
                    title="EC2 Metadata Endpoint Accessible",
                    description="EC2 instance metadata endpoint is reachable (SSRF vector)",
                    endpoint=metadata_url,
                    evidence=resp.text[:500],
                    remediation="Enable IMDSv2 and restrict metadata access",
                    confidence="high",
                ))
                logger.warning("EC2 metadata endpoint accessible!")
        except Exception as e:
            logger.debug(f"EC2 metadata check failed (expected in non-EC2): {e}")

    # ─── Cognito User Pool Checks ─────────────────────────────────────────

    async def _scan_cognito_pools(self):
        """Check for exposed Cognito user pools."""
        cognito_regions = ["us-east-1", "us-west-2", "eu-west-1"]
        pool_ids = [
            self.domain.replace(".", ""),
            f"{self.domain.split('.')[0]}",
        ]

        for region in cognito_regions:
            for pool_id in pool_ids:
                cognito_url = (
                    f"https://cognito-idp.{region}.amazonaws.com/"
                    f"{pool_id}/.well-known/openid-configuration"
                )
                if cognito_url in self._tested:
                    continue
                self._tested.add(cognito_url)

                try:
                    resp = await self._request(cognito_url)
                    if resp.status_code == 200:
                        self.findings.append(CloudMisconfigFinding(
                            provider="AWS",
                            service="Cognito",
                            severity="medium",
                            title=f"Exposed Cognito User Pool: {pool_id}",
                            description=f"Cognito user pool '{pool_id}' in {region} is publicly discoverable",
                            endpoint=cognito_url,
                            evidence=resp.text[:500],
                            remediation="Restrict Cognito user pool visibility if not intended for public use",
                            confidence="medium",
                        ))
                except Exception as e:
                    logger.debug(f"Cognito check failed: {e}")

    # ─── Docker Registry Checks ───────────────────────────────────────────

    async def _scan_docker_registry(self):
        """Check for open Docker registries."""
        registry_urls = [
            f"https://{self.domain}/v2/_catalog",
            f"https://registry.{self.domain}/v2/_catalog",
            f"https://{self.domain}:5000/v2/_catalog",
        ]

        for url in registry_urls:
            if url in self._tested:
                continue
            self._tested.add(url)

            try:
                resp = await self._request(url)
                body = resp.text[:2000]

                if resp.status_code == 200 and '"repositories"' in body:
                    repos = re.findall(r'"([^"]+)"', body)
                    if repos and repos != ["repositories"]:
                        self.findings.append(CloudMisconfigFinding(
                            provider="Docker",
                            service="Registry",
                            severity="high",
                            title=f"Open Docker Registry: {url}",
                            description="Docker registry allows anonymous catalog listing",
                            endpoint=url,
                            evidence=f"Repositories: {repos[:10]}",
                            remediation="Enable authentication on Docker registry",
                            confidence="high",
                        ))
                        logger.warning(f"Open Docker registry found: {url}")
            except Exception as e:
                logger.debug(f"Docker registry check failed for {url}: {e}")

    # ─── Elasticsearch / OpenSearch Checks ─────────────────────────────────

    async def _scan_elasticsearch(self):
        """Check for open Elasticsearch / OpenSearch clusters."""
        es_urls = [
            f"https://{self.domain}:9200",
            f"https://es.{self.domain}:9200",
            f"https://elastic.{self.domain}:9200",
            f"https://{self.domain}:9200/_cat/indices",
        ]

        for url in es_urls:
            if url in self._tested:
                continue
            self._tested.add(url)

            try:
                resp = await self._request(url)
                body = resp.text[:2000]

                if resp.status_code == 200:
                    if '"cluster_name"' in body or '"indices"' in body:
                        if "security_exception" not in body:
                            self.findings.append(CloudMisconfigFinding(
                                provider="Elasticsearch",
                                service="Cluster",
                                severity="critical",
                                title=f"Open Elasticsearch Cluster: {url}",
                                description="Elasticsearch cluster allows unauthenticated access",
                                endpoint=url,
                                evidence=body[:500],
                                remediation="Enable X-Pack Security or restrict network access",
                                confidence="high",
                            ))
                            logger.warning(f"Open Elasticsearch cluster found: {url}")
            except Exception as e:
                logger.debug(f"Elasticsearch check failed for {url}: {e}")
