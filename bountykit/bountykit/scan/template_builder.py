"""Nuclei template builder module.

Covers ADVANCED_BUGBOUNTY_CVE.md Section 18:
- Generate custom Nuclei templates
- Template syntax reference
- Template validation
- Template generation from findings
"""

import json
import os
from pathlib import Path

from rich.console import Console

console = Console()

# Nuclei template examples
TEMPLATE_EXAMPLES = {
    "sqli_error": """id: custom-sqli-error
info:
  name: Custom SQL Injection - Error Based
  author: bountykit
  severity: high
  description: Detects SQL injection via error messages
  tags: sqli,sql,database

http:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1'"
      - "{{BaseURL}}/?id=1%27%20OR%20%271%27%3D%271"
      - "{{BaseURL}}/?id=1%20UNION%20SELECT%20NULL--"

    matchers-condition: or
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-01756"
          - "Microsoft OLE DB"
          - "pg_query"
          - "SQLite3::"
        condition: or

      - type: status
        status:
          - 500
          - 200
""",
    "xss_reflected": """id: custom-xss-reflected
info:
  name: Custom Reflected XSS
  author: bountykit
  severity: medium
  description: Detects reflected XSS vulnerabilities
  tags: xss,cross-site-scripting

http:
  - method: GET
    path:
      - "{{BaseURL}}/?q=%3Cscript%3Ealert(1)%3C/script%3E"
      - "{{BaseURL}}/?search=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E"

    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"
          - "<img src=x onerror=alert(1)>"

      - type: status
        status:
          - 200
""",
    "idor_detect": """id: custom-idor-detect
info:
  name: Custom IDOR Detection
  author: bountykit
  severity: high
  description: Detects Insecure Direct Object Reference
  tags: idor,access-control

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/users/1"
      - "{{BaseURL}}/api/v1/users/2"
      - "{{BaseURL}}/api/v1/users/100"
      - "{{BaseURL}}/api/v1/admin"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "email"
          - "name"
          - "phone"
        condition: or

      - type: word
        words:
          - "unauthorized"
          - "forbidden"
        negative: true
""",
    "cors_misconfig": """id: custom-cors-misconfig
info:
  name: Custom CORS Misconfiguration
  author: bountykit
  severity: medium
  description: Detects CORS misconfigurations
  tags: cors,misconfiguration

http:
  - method: GET
    headers:
      Origin: "https://evil.com"
    path:
      - "{{BaseURL}}/"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
          - "Access-Control-Allow-Origin: *"

      - type: word
        words:
          - "Access-Control-Allow-Credentials: true"
""",
}


def build_sqli_template(
    target: str,
    parameters: list,
    output_dir: str = "./results",
) -> str:
    """Build a custom SQL injection Nuclei template.

    Args:
        target: Target URL
        parameters: List of parameters to test
        output_dir: Output directory
    """
    os.makedirs(output_dir, exist_ok=True)

    template = f"""id: custom-sqli-{target.replace('/', '_').replace(':', '_')}
info:
  name: Custom SQL Injection - {target}
  author: bountykit
  severity: high
  description: Tests for SQL injection on {target}
  tags: sqli,sql,database,custom

http:
  - method: GET
    path:
"""
    for param in parameters:
        template += f'      - "{{{{BaseURL}}}}/?{param}=1\'"\n'
        template += f'      - "{{{{BaseURL}}}}/?{param}=1%27%20OR%20%271%27%3D%271"\n'
        template += f'      - "{{{{BaseURL}}}}/?{param}=1%20UNION%20SELECT%20NULL--"\n'

    template += """
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-01756"
          - "Microsoft OLE DB"
          - "pg_query"
        condition: or

      - type: status
        status:
          - 500
"""

    # Save template
    template_file = Path(output_dir) / "custom_sqli_template.yaml"
    with open(template_file, "w") as f:
        f.write(template)

    console.print(f"  [green]✓ SQL injection template saved to {template_file}[/green]")
    return str(template_file)


def build_xss_template(
    target: str,
    parameters: list,
    output_dir: str = "./results",
) -> str:
    """Build a custom XSS Nuclei template.

    Args:
        target: Target URL
        parameters: List of parameters to test
        output_dir: Output directory
    """
    os.makedirs(output_dir, exist_ok=True)

    template = f"""id: custom-xss-{target.replace('/', '_').replace(':', '_')}
info:
  name: Custom XSS - {target}
  author: bountykit
  severity: medium
  description: Tests for reflected XSS on {target}
  tags: xss,cross-site-scripting,custom

http:
  - method: GET
    path:
"""
    for param in parameters:
        template += f'      - "{{{{BaseURL}}}}/?{param}=%3Cscript%3Ealert(1)%3C/script%3E"\n'
        template += f'      - "{{{{BaseURL}}}}/?{param}=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E"\n'

    template += """
    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"
          - "<img src=x onerror=alert(1)>"

      - type: status
        status:
          - 200
"""

    # Save template
    template_file = Path(output_dir) / "custom_xss_template.yaml"
    with open(template_file, "w") as f:
        f.write(template)

    console.print(f"  [green]✓ XSS template saved to {template_file}[/green]")
    return str(template_file)


def build_idor_template(
    target: str,
    paths: list,
    output_dir: str = "./results",
) -> str:
    """Build a custom IDOR Nuclei template.

    Args:
        target: Target URL
        paths: List of paths to test
        output_dir: Output directory
    """
    os.makedirs(output_dir, exist_ok=True)

    template = f"""id: custom-idor-{target.replace('/', '_').replace(':', '_')}
info:
  name: Custom IDOR - {target}
  author: bountykit
  severity: high
  description: Tests for IDOR on {target}
  tags: idor,access-control,custom

http:
  - method: GET
    path:
"""
    for path in paths:
        template += f'      - "{{{{BaseURL}}}}{path}"\n'

    template += """
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "email"
          - "name"
          - "phone"
          - "address"
        condition: or

      - type: word
        words:
          - "unauthorized"
          - "forbidden"
          - "access denied"
        negative: true
"""

    # Save template
    template_file = Path(output_dir) / "custom_idor_template.yaml"
    with open(template_file, "w") as f:
        f.write(template)

    console.print(f"  [green]✓ IDOR template saved to {template_file}[/green]")
    return str(template_file)


def validate_template(template_path: str) -> dict:
    """Validate a Nuclei template.

    Args:
        template_path: Path to YAML template file

    Returns:
        Validation results
    """
    results = {
        "valid": False,
        "errors": [],
        "warnings": [],
    }

    try:
        import yaml

        with open(template_path, "r") as f:
            template = yaml.safe_load(f)

        # Check required fields
        required_fields = ["id", "info", "http"]
        for field in required_fields:
            if field not in template:
                results["errors"].append(f"Missing required field: {field}")

        # Check info section
        if "info" in template:
            info = template["info"]
            required_info = ["name", "severity"]
            for field in required_info:
                if field not in info:
                    results["warnings"].append(f"Missing info field: {field}")

        # Check http section
        if "http" in template:
            http = template["http"]
            if not isinstance(http, list):
                results["errors"].append("'http' must be a list")
            else:
                for i, request in enumerate(http):
                    if "method" not in request:
                        results["errors"].append(f"Request {i}: Missing 'method'")
                    if "path" not in request:
                        results["errors"].append(f"Request {i}: Missing 'path'")

        results["valid"] = len(results["errors"]) == 0

    except ImportError:
        results["errors"].append("PyYAML not installed")
    except Exception as e:
        results["errors"].append(f"Validation error: {str(e)}")

    return results


def get_template_reference() -> str:
    """Get Nuclei template syntax reference.

    Returns:
        Template syntax reference string
    """
    return """
# Nuclei Template Syntax Reference

## Basic Structure
```yaml
id: template-id
info:
  name: Template Name
  author: author
  severity: low|medium|high|critical
  description: Description
  tags: tag1,tag2

http:
  - method: GET|POST|PUT|DELETE
    path:
      - "{{BaseURL}}/path"
    headers:
      Header: "Value"
    body: "request body"
    matchers:
      - type: word|status|regex|binary
        words: ["pattern"]
        status: [200]
```

## Matchers
- **word**: Match response body/headers for strings
- **status**: Match HTTP status codes
- **regex**: Match using regex patterns
- **binary**: Match binary content

## Variables
- `{{BaseURL}}`: Target base URL
- `{{Hostname}}`: Target hostname
- `{{Port}}`: Target port
- `{{path}}`: URL path

## Extractors
```yaml
extractors:
  - type: regex
    regex:
      - "pattern"
    group: 1
```

## Matchers Condition
- `and`: All matchers must match
- `or`: Any matcher can match
"""

# Export templates for easy access
TEMPLATES = TEMPLATE_EXAMPLES
