"""GraphQL security testing module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 13:
- GraphQL introspection abuse
- Batched query attacks
- Query complexity DoS
- Field suggestion for info disclosure
"""

import json
import os
import re
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

# Introspection query
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

# Dangerous query patterns for DoS
DANGEROUS_QUERIES = [
    # Nested query for DoS
    "{ __typename }" * 100,
    # Self-referencing query
    "{ users { friends { friends { friends { id } } } } }",
    # Large field selection
    "{ __schema types { fields { type { name } } } }",
]


def test_introspection(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Test GraphQL endpoint for introspection.

    Args:
        target: GraphQL endpoint URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "graphql_introspection",
        "introspection_enabled": False,
        "schema": {},
        "types": [],
        "queries": [],
        "mutations": [],
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Testing introspection on {target}...[/dim]")

    try:
        import requests

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = {"query": INTROSPECTION_QUERY}
        resp = requests.post(target, json=payload, headers=headers, timeout=30)

        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "__schema" in data["data"]:
                results["introspection_enabled"] = True
                schema = data["data"]["__schema"]
                results["schema"] = schema

                # Extract types
                if "types" in schema:
                    results["types"] = [
                        t["name"] for t in schema["types"]
                        if not t["name"].startswith("__")
                    ]

                # Extract query fields
                query_type = schema.get("queryType", {})
                if query_type and "name" in query_type:
                    query_type_name = query_type["name"]
                    for t in schema.get("types", []):
                        if t["name"] == query_type_name:
                            results["queries"] = [
                                f["name"] for f in t.get("fields", [])
                            ]

                # Extract mutation fields
                mutation_type = schema.get("mutationType", {})
                if mutation_type and "name" in mutation_type:
                    mutation_type_name = mutation_type["name"]
                    for t in schema.get("types", []):
                        if t["name"] == mutation_type_name:
                            results["mutations"] = [
                                f["name"] for f in t.get("fields", [])
                            ]

                console.print(f"  [bold red]⚠ Introspection enabled![/bold red]")
                console.print(f"    Types: {len(results['types'])}")
                console.print(f"    Queries: {len(results['queries'])}")
                console.print(f"    Mutations: {len(results['mutations'])}")
            else:
                console.print("  [green]✓ Introspection appears disabled (no schema in response)[/green]")
        else:
            console.print(f"  [yellow]GraphQL returned status {resp.status_code}[/yellow]")

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "graphql_introspection.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"  [dim]Results saved to {output_file}[/dim]")
    return results


def test_batch_queries(
    target: str,
    batch_size: int = 10,
    output_dir: str = "./results",
) -> dict:
    """Test GraphQL endpoint for batch query support.

    Batch queries can bypass rate limiting and cause DoS.

    Args:
        target: GraphQL endpoint URL
        batch_size: Number of queries to batch
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "graphql_batch_queries",
        "batch_supported": False,
        "response_time": 0,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Testing batch queries on {target}...[/dim]")

    try:
        import requests
        import time

        # Create batch of introspection queries
        batch = [
            {"query": "{ __typename }"}
            for _ in range(batch_size)
        ]

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        start_time = time.time()
        resp = requests.post(target, json=batch, headers=headers, timeout=30)
        elapsed = time.time() - start_time

        results["response_time"] = elapsed

        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) == batch_size:
                results["batch_supported"] = True
                console.print(
                    f"  [bold red]⚠ Batch queries supported ({batch_size} queries in {elapsed:.2f}s)[/bold red]"
                )
            else:
                console.print("  [green]✓ Batch queries may not be fully supported[/green]")
        else:
            console.print(f"  [yellow]Batch query returned status {resp.status_code}[/yellow]")

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "graphql_batch.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def test_query_complexity(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Test GraphQL query complexity and depth limits.

    Args:
        target: GraphQL endpoint URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "graphql_complexity",
        "depth_limit_found": False,
        "complexity_limit_found": False,
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"  [dim]Testing query complexity limits on {target}...[/dim]")

    try:
        import requests

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Test increasing depth
        for depth in range(1, 20):
            nested_query = "{ __typename " + "{ " * depth + "}" * depth + " }"
            payload = {"query": nested_query}

            try:
                resp = requests.post(target, json=payload, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    if "errors" in data:
                        for error in data["errors"]:
                            msg = error.get("message", "").lower()
                            if any(p in msg for p in ["depth", "complexity", "limit", "too"]):
                                results["depth_limit_found"] = True
                                console.print(f"  [cyan]Depth limit found at level {depth}[/cyan]")
                                break
                else:
                    results["depth_limit_found"] = True
                    console.print(f"  [cyan]Depth limit found at level {depth} (status {resp.status_code})[/cyan]")
                    break
            except Exception:
                continue

        if not results["depth_limit_found"]:
            console.print("  [bold red]⚠ No depth limit detected — potential DoS vector[/bold red]")

    except requests.RequestException as e:
        console.print(f"  [yellow]Request failed: {e}[/yellow]")

    # Save results
    output_file = Path(output_dir) / "graphql_complexity.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def scan_graphql(
    target: str,
    output_dir: str = "./results",
) -> dict:
    """Run full GraphQL security scan.

    Args:
        target: GraphQL endpoint URL
        output_dir: Output directory
    """
    results = {
        "target": target,
        "method": "graphql_full",
        "introspection": {},
        "batch": {},
        "complexity": {},
    }

    os.makedirs(output_dir, exist_ok=True)

    console.print(f"[bold]  Running full GraphQL scan on {target}[/bold]")

    results["introspection"] = test_introspection(target, output_dir)
    results["batch"] = test_batch_queries(target, output_dir=output_dir)
    results["complexity"] = test_query_complexity(target, output_dir)

    # Save merged results
    merged_file = Path(output_dir) / "graphql_full.json"
    with open(merged_file, "w") as f:
        json.dump(results, f, indent=2)

    return results
