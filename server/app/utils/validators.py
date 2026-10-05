"""
Input Validation Utilities — Sanitize and validate user inputs.

🎓 WHY INPUT VALIDATION MATTERS:
User-supplied domain names, URLs, and patterns could contain:
- Command injection characters (;, |, &&, `)
- Path traversal (../../../etc/passwd)
- SQL injection (though SQLAlchemy handles this)
- Excessively long strings that waste resources

Always validate before passing to external tools.
"""
from __future__ import annotations

import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Valid domain name pattern (RFC 1035 + wildcards)
DOMAIN_PATTERN = re.compile(
    r"^(?:\*\.)?"  # Optional wildcard prefix
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"  # Subdomains
    r"[a-zA-Z]{2,}$"  # TLD
)

# Characters that could be used for command injection
DANGEROUS_CHARS = re.compile(r"[;|&`$(){}\[\]<>!\\\n\r]")

# Max lengths
MAX_DOMAIN_LENGTH = 253
MAX_URL_LENGTH = 2048
MAX_PATTERN_LENGTH = 500


def validate_domain(domain: str) -> tuple[bool, str]:
    """
    Validate and sanitize a domain name.
    Returns (is_valid, cleaned_domain_or_error_message).
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain cannot be empty"

    domain = domain.strip().lower()

    if len(domain) > MAX_DOMAIN_LENGTH:
        return False, f"Domain exceeds maximum length of {MAX_DOMAIN_LENGTH}"

    if DANGEROUS_CHARS.search(domain):
        return False, "Domain contains invalid characters"

    # Remove protocol if accidentally included
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.hostname or domain

    if not DOMAIN_PATTERN.match(domain):
        return False, f"Invalid domain format: {domain}"

    return True, domain


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate a URL.
    Returns (is_valid, cleaned_url_or_error_message).
    """
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty"

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH}"

    if DANGEROUS_CHARS.search(url):
        return False, "URL contains potentially dangerous characters"

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https", ""):
            return False, f"Invalid URL scheme: {parsed.scheme}"
        if not parsed.hostname:
            return False, "URL has no hostname"
    except Exception as e:
        return False, f"Invalid URL: {e}"

    return True, url


def validate_scope_pattern(pattern: str) -> tuple[bool, str]:
    """
    Validate a scope inclusion/exclusion pattern.
    Returns (is_valid, cleaned_pattern_or_error_message).
    """
    if not pattern or not isinstance(pattern, str):
        return False, "Pattern cannot be empty"

    pattern = pattern.strip().lower()

    if len(pattern) > MAX_PATTERN_LENGTH:
        return False, f"Pattern exceeds maximum length of {MAX_PATTERN_LENGTH}"

    if DANGEROUS_CHARS.search(pattern):
        return False, "Pattern contains potentially dangerous characters"

    return True, pattern


def sanitize_for_command(value: str) -> str:
    """
    Remove any characters that could be used for shell command injection.
    Use this before passing any user input to subprocess commands.
    """
    return DANGEROUS_CHARS.sub("", value).strip()
