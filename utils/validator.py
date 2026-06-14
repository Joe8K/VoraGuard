"""
VoraGuard Input Validation
Sanitize and validate all user inputs before use.
"""

import re
import ipaddress
from urllib.parse import urlparse


# Strict domain regex — no shell metacharacters allowed
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)+[a-zA-Z]{2,}$"
)


def validate_domain(value: str) -> str:
    """
    Validate and sanitize a domain name.
    Raises ValueError if invalid.
    Returns cleaned domain string.
    """
    if not value or not isinstance(value, str):
        raise ValueError("Domain must be a non-empty string.")

    value = value.strip()

    # Strip protocol if user accidentally passed a URL
    if value.startswith(("http://", "https://")):
        value = urlparse(value).netloc

    value = value.lower().rstrip(".")

    # Check for IP address (valid target too)
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if not _DOMAIN_RE.match(value):
        raise ValueError(
            f"Invalid domain: '{value}'. "
            "Use format like: example.com"
        )

    if len(value) > 253:
        raise ValueError("Domain name too long (max 253 characters).")

    return value
