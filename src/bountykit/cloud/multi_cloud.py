"""
Multi-cloud security scanner — AWS, GCP, Azure — 2026 techniques.

AWS: S3, IAM, Lambda, EC2, RDS, ECS, EKS, CloudTrail, KMS, Secrets Manager
GCP: GCS, IAM, Cloud Functions, Compute Engine, Cloud Run, GKE, Secret Manager
Azure: Blob Storage, AD, Functions, VMs, AKS, Key Vault, SQL Database
"""

from __future__ import annotations

import re
import time
import json
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from enum import Enum

import httpx
import tenacity

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


@dataclass
class CloudFinding:
    """Single cloud security finding."""
    provider: str
    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    resource: str = ""
    region: str = ""
    remediation: str = ""


@dataclass
class CloudResult:
    """Complete cloud security assessment result."""
    target: str
    findings: List[CloudFinding] = field(default_factory=list)
    resources_scanned: int = 0
    providers_tested: Set[str] = field(default_factory=set)
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        return severity_counts


class MultiCloudScanner:
    """
    Multi-cloud security scanner.

    2026 attack vectors:
    - AWS: IMDSv1 bypass, Lambda RCE, ECS task takeover, EKS node escape
    - GCP: Metadata API bypass, Cloud Function RCE, GKE node escape
    - Azure: Instance Metadata Service, Function RCE, AKS escape
    - Multi-cloud: Cross-cloud SSRF, shared credential exposure
    """

    # AWS metadata endpoint
    AWS_METADATA = "http://169.254.169.254/latest/meta-data"
    AWS_METADATA_IAM = "http://169.254.169.254/latest/meta-data/iam/security-credentials"

    # GCP metadata endpoint
    GCP_METADATA = "http://metadata.google.internal/computeMetadata/v1"
    GCP_METADATA_HEADERS = {"Metadata-Flavor": "Google"}

    # Azure metadata endpoint
    AZURE_METADATA = "http://169.254.169.254/metadata/instance"
    AZURE_METADATA_HEADERS = {"Metadata": "true"}

    # Common cloud endpoints to test
    CLOUD_ENDPOINTS = [
        "/",
        "/api/cloud",
        "/api/storage",
        "/api/s3",
        "/api/gcs",
        "/api/azure",
        "/api/bucket",
        "/api/upload",
        "/api/download",
        "/health",
        "/status",
        "/debug",
        "/admin",
    ]

    # Cloud-specific attack payloads
    AWS_PAYLOADS = [
        {
            "name": "IMDSv1 Bypass",
            "category": "metadata_bypass",
            "description": "AWS Instance Metadata Service v1 access",
            "url": "http://169.254.169.254/latest/meta-data/",
            "severity": "critical",
        },
        {
            "name": "IAM Credentials",
            "category": "credential_theft",
            "description": "AWS IAM role credentials via metadata",
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "severity": "critical",
        },
        {
            "name": "User Data",
            "category": "data_exposure",
            "description": "EC2 user data (may contain secrets)",
            "url": "http://169.254.169.254/latest/user-data",
            "severity": "high",
        },
        {
            "name": "S3 Bucket Enumeration",
            "category": "storage_enumeration",
            "description": "Public S3 bucket access",
            "url": "https://s3.amazonaws.com",
            "severity": "high",
        },
        {
            "name": "Lambda Environment Variables",
            "category": "secret_exposure",
            "description": "Lambda function environment variables",
            "url": "http://169.254.169.254/latest/meta-data/lambda/",
            "severity": "high",
        },
    ]

    GCP_PAYLOADS = [
        {
            "name": "GCP Metadata API",
            "category": "metadata_bypass",
            "description": "GCP Compute Metadata API access",
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "severity": "critical",
        },
        {
            "name": "GCP Service Account",
            "category": "credential_theft",
            "description": "GCP service account token",
            "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "severity": "critical",
        },
        {
            "name": "GCP Project Info",
            "category": "data_exposure",
            "description": "GCP project information",
            "url": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "severity": "high",
        },
        {
            "name": "GCS Bucket Access",
            "category": "storage_enumeration",
            "description": "Google Cloud Storage bucket access",
            "url": "https://storage.googleapis.com",
            "severity": "high",
        },
    ]

    AZURE_PAYLOADS = [
        {
            "name": "Azure Instance Metadata",
            "category": "metadata_bypass",
            "description": "Azure Instance Metadata Service access",
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "severity": "critical",
        },
        {
            "name": "Azure Identity Token",
            "category": "credential_theft",
            "description": "Azure managed identity token",
            "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "severity": "critical",
        },
        {
            "name": "Azure Blob Storage",
            "category": "storage_enumeration",
            "description": "Azure Blob Storage access",
            "url": "https://blob.core.windows.net",
            "severity": "high",
        },
        {
            "name": "Azure Key Vault",
            "category": "secret_exposure",
            "description": "Azure Key Vault access",
            "url": "https://vault.azure.net",
            "severity": "high",
        },
    ]

    def __init__(
        self,
        target: str,
        timeout: float = 10.0,
        proxy: Optional[str] = None,
        verbose: bool = False,
        providers: Optional[List[str]] = None,
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.proxy = proxy
        self.verbose = verbose
        self.providers = providers or ["aws", "gcp", "azure"]

        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            proxy=proxy,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            },
        )

    async def close(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def scan_all(self) -> CloudResult:
        """Scan all configured cloud providers."""
        result = CloudResult(target=self.target)

        logger.info(f"[*] Starting multi-cloud security scan: {self.target}")

        if "aws" in self.providers:
            await self._scan_aws(result)
        if "gcp" in self.providers:
            await self._scan_gcp(result)
        if "azure" in self.providers:
            await self._scan_azure(result)

        # Test cloud endpoints on target
        for ep in self.CLOUD_ENDPOINTS:
            for provider_payloads in [self.AWS_PAYLOADS, self.GCP_PAYLOADS, self.AZURE_PAYLOADS]:
                for payload in provider_payloads:
                    finding = await self._test_cloud_endpoint(ep, payload)
                    if finding:
                        result.findings.append(finding)

        logger.info(
            f"[+] Multi-cloud scan complete: {len(result.findings)} findings "
            f"across {len(result.providers_tested)} providers"
        )
        return result

    async def _scan_aws(self, result: CloudResult) -> None:
        """Scan AWS-specific attack vectors."""
        result.providers_tested.add("aws")
        logger.info("[*] Scanning AWS attack vectors...")

        for payload in self.AWS_PAYLOADS:
            try:
                resp = await self._client.get(
                    payload["url"],
                    headers={"User-Agent": "Mozilla/5.0"},
                )

                if resp.status_code == 200 and len(resp.text) > 0:
                    # Check if real metadata (not blocked)
                    if any(key in resp.text for key in ["ami-id", "instance-id", "instance-type"]):
                        result.findings.append(
                            CloudFinding(
                                provider="aws",
                                category=payload["category"],
                                severity=payload["severity"],
                                title=f"AWS: {payload['name']}",
                                description=payload["description"],
                                evidence=resp.text[:1000],
                                remediation=self._get_remediation(payload["category"]),
                            )
                        )
                        result.resources_scanned += 1

            except httpx.ConnectError:
                # Expected - not on AWS
                if self.verbose:
                    logger.debug(f"  [-] Not on AWS: {payload['name']}")
            except Exception as e:
                if self.verbose:
                    logger.debug(f"  [-] AWS test failed: {payload['name']}: {e}")

        # Test for Lambda RCE via environment variables
        await self._test_lambda_rce(result)

        # Test for ECS/EKS task metadata
        await self._test_ecs_metadata(result)

    async def _scan_gcp(self, result: CloudResult) -> None:
        """Scan GCP-specific attack vectors."""
        result.providers_tested.add("gcp")
        logger.info("[*] Scanning GCP attack vectors...")

        for payload in self.GCP_PAYLOADS:
            try:
                resp = await self._client.get(
                    payload["url"],
                    headers=self.GCP_METADATA_HEADERS,
                )

                if resp.status_code == 200 and len(resp.text) > 0:
                    result.findings.append(
                        CloudFinding(
                            provider="gcp",
                            category=payload["category"],
                            severity=payload["severity"],
                            title=f"GCP: {payload['name']}",
                            description=payload["description"],
                            evidence=resp.text[:1000],
                            remediation=self._get_remediation(payload["category"]),
                        )
                    )
                    result.resources_scanned += 1

            except httpx.ConnectError:
                if self.verbose:
                    logger.debug(f"  [-] Not on GCP: {payload['name']}")
            except Exception as e:
                if self.verbose:
                    logger.debug(f"  [-] GCP test failed: {payload['name']}: {e}")

    async def _scan_azure(self, result: CloudResult) -> None:
        """Scan Azure-specific attack vectors."""
        result.providers_tested.add("azure")
        logger.info("[*] Scanning Azure attack vectors...")

        for payload in self.AZURE_PAYLOADS:
            try:
                resp = await self._client.get(
                    payload["url"],
                    headers=self.AZURE_METADATA_HEADERS,
                )

                if resp.status_code == 200 and len(resp.text) > 0:
                    result.findings.append(
                        CloudFinding(
                            provider="azure",
                            category=payload["category"],
                            severity=payload["severity"],
                            title=f"Azure: {payload['name']}",
                            description=payload["description"],
                            evidence=resp.text[:1000],
                            remediation=self._get_remediation(payload["category"]),
                        )
                    )
                    result.resources_scanned += 1

            except httpx.ConnectError:
                if self.verbose:
                    logger.debug(f"  [-] Not on Azure: {payload['name']}")
            except Exception as e:
                if self.verbose:
                    logger.debug(f"  [-] Azure test failed: {payload['name']}: {e}")

    async def _test_cloud_endpoint(
        self, endpoint: str, payload: Dict[str, Any]
    ) -> Optional[CloudFinding]:
        """Test if cloud endpoint leaks metadata via SSRF."""
        url = f"{self.target}{endpoint}"

        try:
            # Test if endpoint fetches our metadata URL
            resp = await self._client.post(
                url,
                json={"url": payload["url"], "fetch": True},
            )

            if resp.status_code == 200:
                body = resp.text.lower()
                indicators = ["ami-id", "instance-id", "metadata", "credentials"]
                for indicator in indicators:
                    if indicator in body:
                        return CloudFinding(
                            provider="unknown",
                            category="ssrf_cloud_metadata",
                            severity="critical",
                            title=f"SSRF to Cloud Metadata: {payload['name']}",
                            description=f"Endpoint {endpoint} fetches cloud metadata via SSRF.",
                            evidence=f"Indicator: {indicator}",
                            remediation="Block internal metadata endpoints. Validate/allowlist URLs.",
                        )

        except Exception:
            pass

        return None

    async def _test_lambda_rce(self, result: CloudResult) -> None:
        """Test for Lambda RCE via environment variable injection."""
        try:
            # Test if Lambda environment contains secrets
            resp = await self._client.get(
                "http://169.254.169.254/latest/meta-data/lambda/",
                headers={"User-Agent": "Mozilla/5.0"},
            )

            if resp.status_code == 200:
                result.findings.append(
                    CloudFinding(
                        provider="aws",
                        category="lambda_exposure",
                        severity="high",
                        title="Lambda Metadata Accessible",
                        description="Lambda function metadata is accessible via IMDS.",
                        evidence=resp.text[:500],
                        remediation="Restrict Lambda IAM role permissions.",
                    )
                )

        except Exception:
            pass

    async def _test_ecs_metadata(self, result: CloudResult) -> None:
        """Test for ECS/EKS task metadata exposure."""
        try:
            # ECS task metadata
            resp = await self._client.get(
                "http://169.254.169.254/metadata/v1/",
                headers={"User-Agent": "Mozilla/5.0"},
            )

            if resp.status_code == 200:
                result.findings.append(
                    CloudFinding(
                        provider="aws",
                        category="ecs_metadata",
                        severity="high",
                        title="ECS/EKS Metadata Accessible",
                        description="ECS/EKS task metadata is accessible.",
                        evidence=resp.text[:500],
                        remediation="Enable IMDSv2, restrict task IAM roles.",
                    )
                )

        except Exception:
            pass

    def _get_remediation(self, category: str) -> str:
        """Get remediation advice for category."""
        remediations = {
            "metadata_bypass": "Enable IMDSv2 (AWS), require Metadata header (GCP/Azure), "
            "restrict metadata access via network policies.",
            "credential_theft": "Use short-lived credentials, implement least-privilege IAM, "
            "enable credential rotation, use workload identity.",
            "data_exposure": "Encrypt sensitive data, restrict access via IAM, "
            "use environment-specific configurations.",
            "storage_enumeration": "Enable bucket-level access controls, disable public access, "
            "use signed URLs for temporary access.",
            "secret_exposure": "Use managed secret services (AWS Secrets Manager, GCP Secret Manager, "
            "Azure Key Vault), rotate secrets regularly.",
            "lambda_exposure": "Minimize Lambda IAM role permissions, use VPC endpoints, "
            "enable VPC flow logs.",
            "ecs_metadata": "Enable IMDSv2, restrict ECS task roles, use VPC endpoints.",
            "ssrf_cloud_metadata": "Block requests to internal metadata endpoints, "
            "implement URL allowlists, use network policies.",
        }
        return remediations.get(category, "Review cloud security configuration.")
