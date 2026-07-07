"""Input validation utilities."""

import re
from typing import Optional
from urllib.parse import urlparse


def validate_target(target: str) -> tuple[bool, Optional[str]]:
    """Validate a target domain or URL.

    Returns (is_valid, error_message).
    """
    target = target.strip()

    if not target:
        return False, "Target cannot be empty"

    if len(target) > 253:
        return False, "Target exceeds maximum length (253 chars)"

    # Check for URL format
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        if not parsed.hostname:
            return False, "Invalid URL format"
        return True, None

    # Domain validation
    domain_regex = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
    )

    if not domain_regex.match(target):
        return False, f"Invalid domain format: {target}"

    return True, None


def validate_url(url: str) -> tuple[bool, Optional[str]]:
    """Validate a URL.

    Returns (is_valid, error_message).
    """
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        return False, "URL must start with http:// or https://"

    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return False, "URL must have a hostname"
        return True, None
    except Exception:
        return False, "Invalid URL format"


def validate_severity(severity: str) -> tuple[bool, list[str]]:
    """Validate and parse severity filter.

    Returns (is_valid, list_of_severities).
    """
    valid = {"info", "low", "medium", "high", "critical"}
    parts = [s.strip().lower() for s in severity.split(",")]

    for p in parts:
        if p not in valid:
            return False, []

    return True, parts


def sanitize_target(target: str) -> str:
    """Sanitize target input for safe shell execution."""
    # Remove shell metacharacters
    dangerous = set(";&|`$(){}[]!#~<>?\\'\"")
    return "".join(c for c in target if c not in dangerous)


def sanitize_target_filename(target: str) -> str:
    """Convert a target (URL or domain) into a safe filename component.

    Handles any input: URLs, domains, subdomains, or malformed targets.
    Strips schemes, replaces path-unsafe chars with underscores, and
    ensures the result is a single flat filename (no directory separators).

    Examples:
        "https://www.fortinet.com" → "www.fortinet.com"
        "https://example.com/path?q=1" → "example.com_path_q_1"
        "example.com" → "example.com"
        "admin.https://www.fortinet.com" → "admin.www.fortinet.com"
        "subdomain.example.com" → "subdomain.example.com"
    """
    from urllib.parse import urlparse

    # Strip any leading/trailing whitespace
    target = target.strip()

    # Try to parse as URL
    try:
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            hostname = parsed.hostname or ""
            path = parsed.path.lstrip("/") if parsed.path else ""
            query = parsed.query.replace("=", "_").replace("&", "_") if parsed.query else ""

            parts = [hostname]
            if path:
                parts.append(path.replace("/", "_"))
            if query:
                parts.append(query)

            result = "_".join(parts)
        else:
            # Not a standard URL — strip any embedded scheme like "admin.https://..."
            # Replace "://" with "." so "admin.https://www.fortinet.com" → "admin.https.www.fortinet.com"
            cleaned = target.replace("://", ".")
            # Now try to parse the cleaned version as a URL in case it became one
            if cleaned.startswith(("http.", "https.")):
                cleaned = cleaned[5:]  # strip "http." or "https."
            result = cleaned
    except Exception:
        result = target

    # Replace ANY character that is unsafe in filenames
    # On Linux only / is truly banned, but we also clean : ? * " ' and more for safety
    unsafe = '/:*?"<>|\\\' ;\t;&|`$(){}[]!#~()='
    for ch in unsafe:
        result = result.replace(ch, "_")

    # Collapse multiple underscores and dots
    while "__" in result:
        result = result.replace("__", "_")
    while ".." in result:
        result = result.replace("..", ".")

    # Strip leading/trailing underscores and dots
    result = result.strip("_.")

    # Truncate to reasonable length (keep under 200 chars)
    if len(result) > 200:
        result = result[:200]

    return result
