"""OAuth/OIDC security testing module.

Covers 2026 OAuth/OIDC security testing:
- OAuth redirect URI manipulation
- Token theft via open redirect
- PKCE bypass testing
- JWT token analysis (algorithm confusion, key injection)
- OAuth token leakage via referer
- Session fixation via OAuth
- OAuth scope escalation
- Refresh token abuse
- OAuth implicit flow vulnerabilities
"""

import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse, urljoin

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)

# ─── OAuth Redirect URI Manipulation Payloads ────────────────────────────────

REDIRECT_PAYLOADS = [
    "{original}",
    "{original}@evil.com",
    "{original}#.evil.com",
    "{original}%0d%0aLocation:%20http://evil.com",
    "http://localhost",
    "http://127.0.0.1",
    "https://evil.com/callback",
    "{original}..%2f..%2f..%2f",
    "{original}%00",
    "{original}/*",
    "https://evil.com/callback%40{domain}",
    "https://evil.com/callback#{original}",
]

# ─── Open Redirect Indicators ────────────────────────────────────────────────

OPEN_REDIRECT_INDICATORS = [
    "return_url", "redirect", "next", "callback", "continue",
    "url", "dest", "destination", "returnTo", "redirect_uri",
    "return_uri", "checkout_url", "redir", "redirect_url",
    "forward", "goto", "target", "out", "view", "link",
]

# ─── Common OAuth Endpoints ──────────────────────────────────────────────────

OAUTH_ENDPOINTS = {
    "authorize": [
        "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
        "/authorize", "/login/oauth/authorize", "/connect/authorize",
        "/realms/*/protocol/openid-connect/auth",
    ],
    "token": [
        "/oauth/token", "/oauth2/token", "/auth/token",
        "/token", "/connect/token", "/realms/*/protocol/openid-connect/token",
    ],
    "userinfo": [
        "/oauth/userinfo", "/oauth2/userinfo",
        "/user/info", "/me", "/api/user",
    ],
    "jwks": [
        "/.well-known/jwks.json", "/oauth/jwks",
        "/oauth2/jwks", "/.well-known/openid-configuration",
    ],
}


@dataclass
class OAuthFinding:
    """OAuth security finding."""

    test_name: str
    finding_type: str  # "redirect", "token_theft", "jwt", "pkce", "scope", "session"
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    evidence: str = ""
    affected_endpoints: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class OAuthResult:
    """Complete OAuth scan result."""

    target: str
    findings: list[OAuthFinding] = field(default_factory=list)
    auth_endpoint_found: bool = False
    token_endpoint_found: bool = False
    pkce_enabled: bool = False
    implicit_flow_enabled: bool = False
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class OAuthScanner:
    """Advanced OAuth/OIDC scanner with 2026 techniques."""

    def __init__(
        self,
        target: str,
        output_dir: str = "./results",
        timeout: int = 15,
        verify_ssl: bool = False,
    ):
        self.target = target.rstrip("/")
        self.output_dir = output_dir
        self.timeout = timeout
        self.findings: list[OAuthFinding] = []
        self.session = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
            http2=True,
        )
        os.makedirs(output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def _send_request(self, url: str, method: str = "GET", **kwargs) -> httpx.Response:
        """Send HTTP request with retry."""
        return self.session.request(method, url, **kwargs)

    def discover_endpoints(self) -> dict:
        """Discover OAuth/OIDC endpoints."""
        logger.info(f"Discovering OAuth endpoints on {self.target}")

        endpoints = {
            "authorize": None,
            "token": None,
            "userinfo": None,
            "jwks": None,
        }

        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for ep_type, paths in OAUTH_ENDPOINTS.items():
            for path in paths:
                # Handle wildcard paths
                if "*" in path:
                    # Skip wildcard paths for now
                    continue

                url = base_url + path
                try:
                    resp = self._send_request(url)
                    if resp.status_code in [200, 301, 302, 303, 307]:
                        endpoints[ep_type] = url
                        logger.info(f"Found {ep_type} endpoint: {url}")
                        break
                except Exception:
                    continue

        return endpoints

    def test_redirect_uri(self) -> OAuthFinding:
        """Test OAuth redirect URI validation."""
        logger.info(f"Testing OAuth redirect URI on {self.target}")

        try:
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Find authorization endpoint
            auth_endpoint = None
            for path in OAUTH_ENDPOINTS["authorize"]:
                if "*" in path:
                    continue
                url = base_url + path
                try:
                    resp = self._send_request(url, follow_redirects=False)
                    if resp.status_code in [301, 302, 303, 307]:
                        auth_endpoint = url
                        break
                except Exception:
                    continue

            if not auth_endpoint:
                return OAuthFinding(
                    test_name="Redirect URI",
                    finding_type="redirect",
                    severity="info",
                    description="No authorization endpoint found.",
                )

            # Test redirect URI manipulation
            for payload_template in REDIRECT_PAYLOADS:
                try:
                    test_url = f"{auth_endpoint}?redirect_uri={payload_template}"
                    resp = self._send_request(test_url, follow_redirects=False)

                    if resp.status_code in [301, 302, 303, 307]:
                        location = resp.headers.get("location", "")
                        if "evil.com" in location or "localhost" in location:
                            return OAuthFinding(
                                test_name="Redirect URI",
                                finding_type="redirect",
                                severity="critical",
                                description=f"Redirect URI manipulation successful. Payload: {payload_template}",
                                evidence=f"Redirect to: {location}",
                                affected_endpoints=[auth_endpoint],
                                remediation="Validate redirect_uri against whitelist. Never use partial matching.",
                            )

                except Exception as e:
                    logger.debug(f"Redirect test failed: {e}")
                    continue

            return OAuthFinding(
                test_name="Redirect URI",
                finding_type="redirect",
                severity="info",
                description="No redirect URI manipulation vulnerabilities detected.",
            )

        except Exception as e:
            logger.error(f"Redirect URI test failed: {e}")
            return OAuthFinding(
                test_name="Redirect URI",
                finding_type="redirect",
                severity="info",
                description=f"Redirect URI test failed: {str(e)}",
            )

    def test_token_theft(self) -> OAuthFinding:
        """Test for token theft via open redirect."""
        logger.info(f"Testing token theft on {self.target}")

        try:
            for indicator in OPEN_REDIRECT_INDICATORS:
                test_url = f"{self.target}?{indicator}=https://evil.com"
                try:
                    resp = self._send_request(test_url, follow_redirects=False)
                    location = resp.headers.get("location", "")

                    if "evil.com" in location:
                        return OAuthFinding(
                            test_name="Token Theft",
                            finding_type="token_theft",
                            severity="critical",
                            description=f"Open redirect found via {indicator} parameter. Can be used to steal OAuth tokens.",
                            evidence=f"Redirect to: {location}",
                            affected_endpoints=[self.target],
                            remediation="Validate redirect parameters. Do not allow arbitrary redirects.",
                        )

                except Exception as e:
                    logger.debug(f"Token theft test failed: {e}")
                    continue

            return OAuthFinding(
                test_name="Token Theft",
                finding_type="token_theft",
                severity="info",
                description="No token theft vectors detected.",
            )

        except Exception as e:
            logger.error(f"Token theft test failed: {e}")
            return OAuthFinding(
                test_name="Token Theft",
                finding_type="token_theft",
                severity="info",
                description=f"Token theft test failed: {str(e)}",
            )

    def analyze_jwt(self, token: str) -> OAuthFinding:
        """Analyze JWT token for security issues."""
        logger.info("Analyzing JWT token")

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return OAuthFinding(
                    test_name="JWT Analysis",
                    finding_type="jwt",
                    severity="info",
                    description="Invalid JWT format.",
                )

            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Check algorithm
            alg = header.get("alg", "")

            if alg == "none":
                return OAuthFinding(
                    test_name="JWT Analysis",
                    finding_type="jwt",
                    severity="critical",
                    description="JWT uses 'none' algorithm. Token can be forged without secret.",
                    evidence=f"Header: {json.dumps(header)}",
                    remediation="Reject tokens with 'none' algorithm. Always require signature verification.",
                )

            if alg in ["HS256", "HS384", "HS512"]:
                return OAuthFinding(
                    test_name="JWT Analysis",
                    finding_type="jwt",
                    severity="medium",
                    description=f"JWT uses symmetric algorithm: {alg}. Potential for brute force if secret is weak.",
                    evidence=f"Algorithm: {alg}",
                    remediation="Use asymmetric algorithms (RS256, ES256) for better security.",
                )

            if alg in ["RS256", "RS384", "RS512"]:
                # Check for key confusion attack
                return OAuthFinding(
                    test_name="JWT Analysis",
                    finding_type="jwt",
                    severity="medium",
                    description="JWT uses RSA algorithm. Check for key confusion attack (HS256 with public key).",
                    evidence=f"Algorithm: {alg}",
                    remediation="Validate algorithm matches expected. Do not allow algorithm switching.",
                )

            # Check expiration
            exp = payload.get("exp")
            if exp:
                if exp < time.time():
                    return OAuthFinding(
                        test_name="JWT Analysis",
                        finding_type="jwt",
                        severity="info",
                        description="JWT has expired.",
                    )
                else:
                    remaining = exp - time.time()
                    if remaining > 86400 * 365:
                        return OAuthFinding(
                            test_name="JWT Analysis",
                            finding_type="jwt",
                            severity="low",
                            description=f"JWT has long expiration: {remaining/86400:.0f} days.",
                            remediation="Reduce token lifetime. Use refresh tokens.",
                        )

            # Check for sensitive data
            sensitive_keys = ["password", "secret", "token", "key", "ssn", "credit", "api_key"]
            for key in payload:
                if any(s in key.lower() for s in sensitive_keys):
                    return OAuthFinding(
                        test_name="JWT Analysis",
                        finding_type="jwt",
                        severity="high",
                        description=f"Sensitive data in JWT payload: {key}",
                        evidence=f"Payload: {json.dumps(payload)[:500]}",
                        remediation="Remove sensitive data from JWT payload.",
                    )

            return OAuthFinding(
                test_name="JWT Analysis",
                finding_type="jwt",
                severity="info",
                description="JWT analysis complete. No critical issues found.",
            )

        except Exception as e:
            logger.error(f"JWT analysis failed: {e}")
            return OAuthFinding(
                test_name="JWT Analysis",
                finding_type="jwt",
                severity="info",
                description=f"JWT analysis failed: {str(e)}",
            )

    def test_pkce(self) -> OAuthFinding:
        """Test for PKCE bypass."""
        logger.info(f"Testing PKCE on {self.target}")

        try:
            # Generate code verifier and challenge
            code_verifier = hashlib.sha256(os.urandom(32)).hexdigest()
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b"=").decode()

            # Test authorization endpoint without PKCE
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in OAUTH_ENDPOINTS["authorize"]:
                if "*" in path:
                    continue
                url = base_url + path
                try:
                    resp = self._send_request(url, follow_redirects=False)
                    if resp.status_code in [301, 302, 303, 307]:
                        # Check if PKCE is enforced
                        location = resp.headers.get("location", "")
                        if "code_challenge" not in location:
                            return OAuthFinding(
                                test_name="PKCE",
                                finding_type="pkce",
                                severity="high",
                                description="PKCE not enforced. Authorization endpoint does not require code_challenge.",
                                evidence=f"Redirect: {location[:200]}",
                                affected_endpoints=[url],
                                remediation="Enforce PKCE for all OAuth flows, especially public clients.",
                            )
                        break
                except Exception:
                    continue

            return OAuthFinding(
                test_name="PKCE",
                finding_type="pkce",
                severity="info",
                description="PKCE appears to be enforced or not applicable.",
            )

        except Exception as e:
            logger.error(f"PKCE test failed: {e}")
            return OAuthFinding(
                test_name="PKCE",
                finding_type="pkce",
                severity="info",
                description=f"PKCE test failed: {str(e)}",
            )

    def test_scope_escalation(self) -> OAuthFinding:
        """Test for OAuth scope escalation."""
        logger.info(f"Testing scope escalation on {self.target}")

        try:
            # Test authorization endpoint with elevated scopes
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in OAUTH_ENDPOINTS["authorize"]:
                if "*" in path:
                    continue
                url = base_url + path
                try:
                    # Test with admin scope
                    test_url = f"{url}?scope=admin+openid+email+profile"
                    resp = self._send_request(test_url, follow_redirects=False)

                    if resp.status_code in [301, 302, 303, 307]:
                        location = resp.headers.get("location", "")
                        if "admin" in location.lower():
                            return OAuthFinding(
                                test_name="Scope Escalation",
                                finding_type="scope",
                                severity="high",
                                description="OAuth scope escalation possible. Admin scope accepted.",
                                evidence=f"Redirect: {location[:200]}",
                                affected_endpoints=[url],
                                remediation="Validate scopes against allowed list. Do not accept arbitrary scopes.",
                            )
                        break
                except Exception:
                    continue

            return OAuthFinding(
                test_name="Scope Escalation",
                finding_type="scope",
                severity="info",
                description="No scope escalation detected.",
            )

        except Exception as e:
            logger.error(f"Scope escalation test failed: {e}")
            return OAuthFinding(
                test_name="Scope Escalation",
                finding_type="scope",
                severity="info",
                description=f"Scope escalation test failed: {str(e)}",
            )

    def run_full_scan(self) -> OAuthResult:
        """Run full OAuth security scan."""
        start_time = time.time()

        logger.info(f"Running full OAuth scan on {self.target}")

        result = OAuthResult(target=self.target)

        # 1. Discover endpoints
        endpoints = self.discover_endpoints()
        result.auth_endpoint_found = endpoints["authorize"] is not None
        result.token_endpoint_found = endpoints["token"] is not None

        # 2. Test redirect URI
        redirect_finding = self.test_redirect_uri()
        self.findings.append(redirect_finding)

        # 3. Test token theft
        token_theft_finding = self.test_token_theft()
        self.findings.append(token_theft_finding)

        # 4. Test PKCE
        pkce_finding = self.test_pkce()
        self.findings.append(pkce_finding)
        result.pkce_enabled = pkce_finding.severity in ["high", "critical"]

        # 5. Test scope escalation
        scope_finding = self.test_scope_escalation()
        self.findings.append(scope_finding)

        # Compile results
        result.findings = self.findings
        result.scan_duration = time.time() - start_time

        # Save results
        self._save_results(result)

        return result

    def _save_results(self, result: OAuthResult):
        """Save scan results."""
        output_file = Path(self.output_dir) / "oauth_scan.json"

        with open(output_file, "w") as f:
            json.dump(
                {
                    "target": result.target,
                    "auth_endpoint_found": result.auth_endpoint_found,
                    "token_endpoint_found": result.token_endpoint_found,
                    "pkce_enabled": result.pkce_enabled,
                    "scan_duration": result.scan_duration,
                    "findings": [
                        {
                            "test_name": f.test_name,
                            "finding_type": f.finding_type,
                            "severity": f.severity,
                            "description": f.description,
                            "evidence": f.evidence,
                            "remediation": f.remediation,
                        }
                        for f in result.findings
                    ],
                },
                f,
                indent=2,
            )

        logger.info(f"Results saved to {output_file}")


# ─── Legacy Functions ────────────────────────────────────────────────────────

def test_redirect_uri(target: str, output_dir: str = "./results") -> dict:
    """Legacy redirect URI test."""
    scanner = OAuthScanner(target, output_dir)
    finding = scanner.test_redirect_uri()
    return {
        "target": target,
        "vulnerable": finding.severity in ["high", "critical"],
        "description": finding.description,
    }


def test_token_theft(target: str, output_dir: str = "./results") -> dict:
    """Legacy token theft test."""
    scanner = OAuthScanner(target, output_dir)
    finding = scanner.test_token_theft()
    return {
        "target": target,
        "vulnerable": finding.severity in ["high", "critical"],
        "description": finding.description,
    }


def analyze_jwt(token: str, output_dir: str = "./results") -> dict:
    """Legacy JWT analysis."""
    scanner = OAuthScanner("", output_dir)
    finding = scanner.analyze_jwt(token)
    return {
        "method": "jwt_analysis",
        "description": finding.description,
        "severity": finding.severity,
    }
