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
