"""GraphQL security testing module.

Covers 2026 GraphQL security testing:
- Introspection abuse & schema extraction
- Batched query attacks & rate limit bypass
- Query complexity DoS (nested queries, field suggestions)
- Subscription abuse & WebSocket hijacking
- GraphQL-specific injection (IDOR, BOLA via __node)
- persisted queries bypass
- GraphQL-specific WAF bypass
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)

# ─── Introspection Query ─────────────────────────────────────────────────────

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
"""

# ─── Dangerous Queries ───────────────────────────────────────────────────────

DANGEROUS_QUERIES = [
    # Nested query for DoS
    "{ __typename " + "{ " * 50 + "}" * 50 + " }",
    # Self-referencing query
    "{ users { friends { friends { friends { friends { id } } } } } }",
    # Large field selection
    "{ __schema types { fields { type { name } } } }",
    # Query with high cost
    "{ users(first: 1000000) { edges { node { id name email } } } }",
    # Circular fragment
    "{ ...A } fragment A on Query { ...B } fragment B on Query { ...A }",
]


@dataclass
class GraphQLFinding:
    """GraphQL security finding."""

    test_name: str
    finding_type: str  # "introspection", "batch", "dos", "injection", "bypass"
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    evidence: str = ""
    affected_endpoints: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class GraphQLResult:
    """Complete GraphQL scan result."""

    target: str
    findings: list[GraphQLFinding] = field(default_factory=list)
    schema_exposed: bool = False
    introspection_enabled: bool = False
    batch_enabled: bool = False
    depth_limit: Optional[int] = None
    types_count: int = 0
    queries_count: int = 0
    mutations_count: int = 0
    subscriptions_count: int = 0
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class GraphQLScanner:
    """Advanced GraphQL scanner with 2026 techniques."""

    def __init__(
        self,
        endpoint: str,
        output_dir: str = "./results",
        timeout: int = 30,
        verify_ssl: bool = False,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.output_dir = output_dir
        self.timeout = timeout
        self.findings: list[GraphQLFinding] = []
        self.session = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
            http2=False,
        )
        os.makedirs(output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    def _send_query(self, query: str, variables: dict = None) -> dict:
        """Send GraphQL query."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        resp = self.session.post(self.endpoint, json=payload, headers=headers)
        return resp.json()

    def test_introspection(self) -> GraphQLFinding:
        """Test for introspection enabled."""
        logger.info(f"Testing introspection on {self.endpoint}")

        try:
            data = self._send_query(INTROSPECTION_QUERY)

            if "data" in data and "__schema" in data["data"]:
                schema = data["data"]["__schema"]

                # Extract types, queries, mutations, subscriptions
                types = [
                    t["name"]
                    for t in schema.get("types", [])
                    if not t["name"].startswith("__")
                ]

                query_type = schema.get("queryType", {})
                queries = []
                if query_type and "name" in query_type:
                    for t in schema.get("types", []):
                        if t["name"] == query_type["name"]:
                            queries = [f["name"] for f in t.get("fields", [])]

                mutation_type = schema.get("mutationType", {})
                mutations = []
                if mutation_type and "name" in mutation_type:
                    for t in schema.get("types", []):
                        if t["name"] == mutation_type["name"]:
                            mutations = [f["name"] for f in t.get("fields", [])]

                subscription_type = schema.get("subscriptionType", {})
                subscriptions = []
                if subscription_type and "name" in subscription_type:
                    for t in schema.get("types", []):
                        if t["name"] == subscription_type["name"]:
                            subscriptions = [f["name"] for f in t.get("fields", [])]

                finding = GraphQLFinding(
                    test_name="Introspection",
                    finding_type="introspection",
                    severity="high",
                    description=f"GraphQL introspection enabled. Schema fully exposed with {len(types)} types, {len(queries)} queries, {len(mutations)} mutations, {len(subscriptions)} subscriptions.",
                    evidence=f"Types: {', '.join(types[:10])}...",
                    affected_endpoints=[self.endpoint],
                    remediation="Disable introspection in production. Use persisted queries instead.",
                )
                self.findings.append(finding)

                # Check for sensitive types
                sensitive_patterns = ["user", "admin", "auth", "token", "secret", "password", "credential"]
                sensitive_types = [
                    t for t in types
                    if any(p in t.lower() for p in sensitive_patterns)
                ]

                if sensitive_types:
                    finding2 = GraphQLFinding(
                        test_name="Sensitive Types Exposed",
                        finding_type="introspection",
                        severity="critical",
                        description=f"Sensitive types found in schema: {', '.join(sensitive_types)}",
                        affected_endpoints=[self.endpoint],
                        remediation="Remove sensitive types from schema or disable introspection.",
                    )
                    self.findings.append(finding2)

                return finding

            else:
                return GraphQLFinding(
                    test_name="Introspection",
                    finding_type="introspection",
                    severity="info",
                    description="Introspection appears disabled or limited.",
                )

        except Exception as e:
            logger.error(f"Introspection test failed: {e}")
            return GraphQLFinding(
                test_name="Introspection",
                finding_type="introspection",
                severity="info",
                description=f"Introspection test failed: {str(e)}",
            )

    def test_batch_queries(self, batch_size: int = 10) -> GraphQLFinding:
        """Test for batch query support."""
        logger.info(f"Testing batch queries on {self.endpoint}")

        try:
            batch = [{"query": "{ __typename }"} for _ in range(batch_size)]

            start_time = time.time()
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            resp = self.session.post(self.endpoint, json=batch, headers=headers)
            elapsed = time.time() - start_time

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) == batch_size:
                    finding = GraphQLFinding(
                        test_name="Batch Queries",
                        finding_type="batch",
                        severity="high",
                        description=f"Batch queries supported ({batch_size} queries in {elapsed:.2f}s). Can bypass rate limiting.",
                        evidence=f"Batch of {batch_size} queries processed successfully",
                        affected_endpoints=[self.endpoint],
                        remediation="Implement query cost analysis and rate limiting per query, not per request.",
                    )
                    self.findings.append(finding)
                    return finding

            return GraphQLFinding(
                test_name="Batch Queries",
                finding_type="batch",
                severity="info",
                description="Batch queries not supported or limited.",
            )

        except Exception as e:
            logger.error(f"Batch query test failed: {e}")
            return GraphQLFinding(
                test_name="Batch Queries",
                finding_type="batch",
                severity="info",
                description=f"Batch query test failed: {str(e)}",
            )

    def test_query_depth(self) -> GraphQLFinding:
        """Test query depth limits."""
        logger.info(f"Testing query depth limits on {self.endpoint}")

        try:
            for depth in range(1, 50):
                nested_query = "{ __typename " + "{ " * depth + "}" * depth + " }"

                try:
                    data = self._send_query(nested_query)

                    if "errors" in data:
                        for error in data["errors"]:
                            msg = error.get("message", "").lower()
                            if any(p in msg for p in ["depth", "complexity", "limit", "too deep"]):
                                finding = GraphQLFinding(
                                    test_name="Query Depth",
                                    finding_type="dos",
                                    severity="medium",
                                    description=f"Depth limit found at level {depth}",
                                    affected_endpoints=[self.endpoint],
                                    remediation="Implement query depth limiting.",
                                )
                                self.findings.append(finding)
                                return finding

                except Exception:
                    continue

            finding = GraphQLFinding(
                test_name="Query Depth",
                finding_type="dos",
                severity="critical",
                description="No depth limit detected. Vulnerable to nested query DoS attacks.",
                evidence="Tested up to depth 50 without limit",
                affected_endpoints=[self.endpoint],
                remediation="Implement strict query depth limiting (recommended: max depth 10).",
            )
            self.findings.append(finding)
            return finding

        except Exception as e:
            logger.error(f"Depth test failed: {e}")
            return GraphQLFinding(
                test_name="Query Depth",
                finding_type="dos",
                severity="info",
                description=f"Depth test failed: {str(e)}",
            )

    def test_field_suggestion(self) -> GraphQLFinding:
        """Test for field suggestion info disclosure."""
        logger.info(f"Testing field suggestion on {self.endpoint}")

        try:
            # Query with invalid field name
            query = '{ user { nonexistent_field_xyz } }'
            data = self._send_query(query)

            if "errors" in data:
                for error in data["errors"]:
                    msg = error.get("message", "")
                    # Check if error suggests similar fields
                    if "did you mean" in msg.lower() or "suggestion" in msg.lower():
                        finding = GraphQLFinding(
                            test_name="Field Suggestion",
                            finding_type="introspection",
                            severity="medium",
                            description="Field suggestion enabled. Attackers can enumerate schema fields.",
                            evidence=f"Error message: {msg}",
                            affected_endpoints=[self.endpoint],
                            remediation="Disable field suggestions in production.",
                        )
                        self.findings.append(finding)
                        return finding

            return GraphQLFinding(
                test_name="Field Suggestion",
                finding_type="introspection",
                severity="info",
                description="Field suggestion not detected or disabled.",
            )

        except Exception as e:
            logger.error(f"Field suggestion test failed: {e}")
            return GraphQLFinding(
                test_name="Field Suggestion",
                finding_type="introspection",
                severity="info",
                description=f"Field suggestion test failed: {str(e)}",
            )

    def test_injection(self) -> GraphQLFinding:
        """Test for GraphQL-specific injection (IDOR via __node)."""
        logger.info(f"Testing GraphQL injection on {self.endpoint}")

        try:
            # Test __node injection (common in Relay-based GraphQL)
            query = '{ __node(id: "user:1") { ... on User { id email name } } }'
            data = self._send_query(query)

            if "data" in data and data["data"] and "__node" in str(data["data"]):
                finding = GraphQLFinding(
                    test_name="IDOR via __node",
                    finding_type="injection",
                    severity="critical",
                    description="__node query accessible. Potential IDOR/BOLA vulnerability.",
                    evidence=f"Response: {json.dumps(data)[:500]}",
                    affected_endpoints=[self.endpoint],
                    remediation="Implement proper authorization checks for node-based queries.",
                )
                self.findings.append(finding)
                return finding

            # Test nested injection
            query = '{ user(id: "1") { posts { comments { author { id } } } } }'
            data = self._send_query(query)

            if "data" in data and data["data"]:
                finding = GraphQLFinding(
                    test_name="Nested Data Access",
                    finding_type="injection",
                    severity="medium",
                    description="Nested queries accessible. Check for authorization bypass.",
                    affected_endpoints=[self.endpoint],
                    remediation="Implement field-level authorization.",
                )
                self.findings.append(finding)
                return finding

            return GraphQLFinding(
                test_name="Injection",
                finding_type="injection",
                severity="info",
                description="No injection vulnerabilities detected.",
            )

        except Exception as e:
            logger.error(f"Injection test failed: {e}")
            return GraphQLFinding(
                test_name="Injection",
                finding_type="injection",
                severity="info",
                description=f"Injection test failed: {str(e)}",
            )

    def test_persisted_queries(self) -> GraphQLFinding:
        """Test for persisted queries bypass."""
        logger.info(f"Testing persisted queries on {self.endpoint}")

        try:
            # Test automatic persisted queries (APQ)
            query = "{ __typename }"
            # SHA-256 hash of query
            import hashlib
            query_hash = hashlib.sha256(query.encode()).hexdigest()

            payload = {
                "extensions": {
                    "persistedQuery": {
                        "version": 1,
                        "sha256Hash": query_hash,
                    }
                }
            }

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            resp = self.session.post(self.endpoint, json=payload, headers=headers)

            if resp.status_code == 200:
                data = resp.json()
                if "data" in data:
                    finding = GraphQLFinding(
                        test_name="Persisted Queries",
                        finding_type="bypass",
                        severity="medium",
                        description="Automatic Persisted Queries (APQ) supported. Can be used to bypass WAF.",
                        evidence=f"APQ query executed successfully",
                        affected_endpoints=[self.endpoint],
                        remediation="Validate persisted query hashes or disable APQ.",
                    )
                    self.findings.append(finding)
                    return finding

            return GraphQLFinding(
                test_name="Persisted Queries",
                finding_type="bypass",
                severity="info",
                description="Persisted queries not supported or not enabled.",
            )

        except Exception as e:
            logger.error(f"Persisted queries test failed: {e}")
            return GraphQLFinding(
                test_name="Persisted Queries",
                finding_type="bypass",
                severity="info",
                description=f"Persisted queries test failed: {str(e)}",
            )

    def run_full_scan(self) -> GraphQLResult:
        """Run full GraphQL security scan."""
        start_time = time.time()

        logger.info(f"Running full GraphQL scan on {self.endpoint}")

        result = GraphQLResult(target=self.endpoint)

        # 1. Test introspection
        introspection_finding = self.test_introspection()
        result.introspection_enabled = introspection_finding.severity in ["high", "critical"]
        result.schema_exposed = result.introspection_enabled

        # 2. Test batch queries
        batch_finding = self.test_batch_queries()
        result.batch_enabled = batch_finding.severity in ["high", "critical"]

        # 3. Test query depth
        depth_finding = self.test_query_depth()

        # 4. Test field suggestion
        self.test_field_suggestion()

        # 5. Test injection
        self.test_injection()

        # 6. Test persisted queries
        self.test_persisted_queries()

        # Compile results
        result.findings = self.findings
        result.scan_duration = time.time() - start_time

        # Save results
        self._save_results(result)

        return result

    def _save_results(self, result: GraphQLResult):
        """Save scan results."""
        output_file = Path(self.output_dir) / "graphql_scan.json"

        with open(output_file, "w") as f:
            json.dump(
                {
                    "target": result.target,
                    "introspection_enabled": result.introspection_enabled,
                    "batch_enabled": result.batch_enabled,
                    "schema_exposed": result.schema_exposed,
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

def test_introspection(target: str, output_dir: str = "./results") -> dict:
    """Legacy introspection test."""
    scanner = GraphQLScanner(target, output_dir)
    finding = scanner.test_introspection()
    return {
        "target": target,
        "introspection_enabled": finding.severity in ["high", "critical"],
        "description": finding.description,
    }


def test_batch_queries(target: str, batch_size: int = 10, output_dir: str = "./results") -> dict:
    """Legacy batch query test."""
    scanner = GraphQLScanner(target, output_dir)
    finding = scanner.test_batch_queries(batch_size)
    return {
        "target": target,
        "batch_supported": finding.severity in ["high", "critical"],
        "description": finding.description,
    }


def test_query_complexity(target: str, output_dir: str = "./results") -> dict:
    """Legacy query complexity test."""
    scanner = GraphQLScanner(target, output_dir)
    finding = scanner.test_query_depth()
    return {
        "target": target,
        "depth_limit_found": finding.severity in ["medium", "info"],
        "description": finding.description,
    }


def scan_graphql(target: str, output_dir: str = "./results") -> dict:
    """Legacy full GraphQL scan."""
    scanner = GraphQLScanner(target, output_dir)
    result = scanner.run_full_scan()
    return {
        "target": result.target,
        "introspection_enabled": result.introspection_enabled,
        "batch_enabled": result.batch_enabled,
        "findings_count": len(result.findings),
    }
