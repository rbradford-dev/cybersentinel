"""Input validation — CVE IDs, IP addresses, domains, file hashes."""

import re
from typing import Optional

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def is_valid_cve(value: str) -> bool:
    """Check if a string is a valid CVE ID (CVE-YYYY-NNNNN)."""
    return bool(CVE_RE.match(value.strip()))


def is_valid_ipv4(value: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    return bool(IPV4_RE.match(value.strip()))


def is_valid_domain(value: str) -> bool:
    """Check if a string is a plausible domain name."""
    return bool(DOMAIN_RE.match(value.strip()))


def is_valid_hash(value: str) -> Optional[str]:
    """Return the hash type ('md5', 'sha1', 'sha256') if valid, else None."""
    v = value.strip()
    if SHA256_RE.match(v):
        return "sha256"
    if SHA1_RE.match(v):
        return "sha1"
    if MD5_RE.match(v):
        return "md5"
    return None


def normalize_cve(value: str) -> Optional[str]:
    """Normalize and validate a CVE ID, returning upper-cased form or None."""
    v = value.strip().upper()
    if CVE_RE.match(v):
        return v
    return None


def extract_cve_ids(text: str) -> list[str]:
    """Extract all CVE IDs from a block of text."""
    return [m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)]
