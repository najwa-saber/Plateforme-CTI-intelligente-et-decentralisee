"""Refanging and normalisation of indicators.

CTI reports frequently *defang* indicators so that they are not clickable:
``hxxp://evil[.]example``, ``198.51.100[.]7``, ``evil(dot)example``.
They are refanged before extraction, and the information is kept (``defanged``).
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

# Ordered list of (pattern, replacement) used to refang a text.
_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bhxxp(s?)(\[:\]|:)//", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bh\*\*p(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bfxp://", re.IGNORECASE), "ftp://"),
    (re.compile(r"\[:\]//"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", re.IGNORECASE), "."),
    (re.compile(r"\s\[dot\]\s|\s\(dot\)\s", re.IGNORECASE), "."),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[@\]|\[at\]", re.IGNORECASE), "@"),
]
_DEFANG_MARKERS = re.compile(r"hxxp|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[:\]|\[/\]", re.IGNORECASE)


def is_defanged(token: str) -> bool:
    return bool(_DEFANG_MARKERS.search(token))


def refang(text: str) -> str:
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def normalize_ipv4(value: str) -> str:
    """Canonical dotted-quad (removes leading zeros). Raises ValueError if invalid."""
    parts = value.strip().split(".")
    if len(parts) != 4 or not all(p.isdigit() and len(p) <= 3 for p in parts):
        raise ValueError(f"not an IPv4: {value!r}")
    octets = [int(p) for p in parts]
    if any(o > 255 for o in octets):
        raise ValueError(f"octet out of range: {value!r}")
    return str(ipaddress.IPv4Address(".".join(str(o) for o in octets)))


def normalize_domain(value: str) -> str:
    value = value.strip().strip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")  # IDN -> punycode
    except UnicodeError:
        pass
    return value


def normalize_hash(value: str) -> str:
    return value.strip().lower()


def normalize_url(value: str) -> str:
    """Lower-case scheme and host, drop default ports and fragments, keep path/query as-is."""
    value = value.strip().rstrip(".,;:)]}>\"'")
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    port = parts.port
    netloc = host
    if parts.username:
        netloc = f"{parts.username}@{host}"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def url_host(url: str) -> str | None:
    try:
        return (urlsplit(url).hostname or "").lower() or None
    except ValueError:
        return None
