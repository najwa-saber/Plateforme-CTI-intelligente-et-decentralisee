"""Syntactic validation and *suspicion flags* for IOCs.

IMPORTANT: a syntactically valid indicator is NOT necessarily malicious. The flags
below only describe properties that deserve analyst attention (reserved ranges,
well-known benign infrastructure, probable false positives, ...).
"""
from __future__ import annotations

import ipaddress
import re

IOC_TYPES = ("ipv4", "domain", "url", "md5", "sha256")

# Reserved / special-use names (RFC 2606, RFC 6761)
RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local", "internal", "lan", "home", "corp"}
RESERVED_SLDS = {"example.com", "example.net", "example.org"}
# Special-use names that are valid indicators but absent from the IANA root zone (RFC 7686)
SPECIAL_USE_TLDS = {"onion"}

# Extensions frequently mis-detected as TLDs ("invoice.pdf", "payload.exe")
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "scr",
    "msi", "jar", "py", "sh", "bin", "dat", "tmp", "log", "txt", "csv", "json", "xml", "yml", "yaml", "ini",
    "cfg", "conf", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "one", "iso",
    "img", "vhd", "zip", "rar", "7z", "gz", "tar", "cab", "png", "jpg", "jpeg", "gif", "bmp", "svg", "html",
    "htm", "php", "asp", "aspx", "jsp", "db", "sql", "bak", "lock", "key", "pem", "crt", "locked", "encrypted",
    "enc", "crypt", "md", "c", "h", "cpp", "go", "rs", "so", "dylib", "elf", "apk", "dmg", "pkg", "deb", "rpm",
}

# Well-known benign infrastructure: an IOC on these domains is a probable false positive
# (or legitimate service abuse) and must be verified by an analyst.
KNOWN_BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "office.com", "live.com", "google.com", "googleapis.com", "gstatic.com",
    "github.com", "githubusercontent.com", "amazon.com", "amazonaws.com", "cloudflare.com", "apple.com",
    "mozilla.org", "wikipedia.org", "w3.org", "mitre.org", "attack.mitre.org", "virustotal.com",
    "linkedin.com", "facebook.com", "twitter.com", "x.com", "youtube.com", "dropbox.com",
}
KNOWN_BENIGN_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}

# Hashes of the empty input (frequent copy/paste mistakes in reports)
EMPTY_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",  # md5("")
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256("")
}

_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD = re.compile(r"^(xn--[a-z0-9-]{2,59}|[a-z]{2,24})$")
_HEX = re.compile(r"^[0-9a-f]+$")


def _registered_domain(domain: str) -> str:
    labels = domain.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def is_benign_domain(domain: str) -> bool:
    d = domain.lower()
    return any(d == b or d.endswith("." + b) for b in KNOWN_BENIGN_DOMAINS)


def validate_ipv4(value: str) -> tuple[str, list[str]]:
    """Return (status, flags). value must already be normalised."""
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return "malformed", ["invalid_ipv4"]
    flags: list[str] = []
    doc_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    if any(ip in n for n in doc_nets):
        flags.append("documentation_range")  # RFC 5737 - test data
    elif ip.is_private:
        flags.append("private_address")
    if ip.is_loopback:
        flags.append("loopback")
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified or str(ip) == "255.255.255.255":
        flags.append("reserved_address")
    if value in KNOWN_BENIGN_IPS:
        flags.append("known_benign_infrastructure")
    status = "valid"
    if {"private_address", "loopback", "reserved_address", "known_benign_infrastructure"} & set(flags):
        status = "suspicious"
    return status, flags


def validate_domain(value: str) -> tuple[str, list[str]]:
    flags: list[str] = []
    if len(value) > 253 or "." not in value:
        return "malformed", ["invalid_domain_length"]
    labels = value.split(".")
    tld = labels[-1]
    if not all(_DOMAIN_LABEL.match(lbl) for lbl in labels):
        return "malformed", ["invalid_domain_label"]
    if not _TLD.match(tld):
        return "malformed", ["invalid_tld"]
    if tld in FILE_EXTENSIONS and len(labels) == 2:
        return "malformed", ["probable_filename"]
    if tld in SPECIAL_USE_TLDS:
        flags.append("tor_onion_service")
    if tld in RESERVED_TLDS or _registered_domain(value) in RESERVED_SLDS:
        flags.append("reserved_test_domain")  # RFC 2606 / 6761: fictitious test data
    status = "valid"
    if is_benign_domain(value):
        flags.append("known_benign_infrastructure")
        status = "suspicious"
    return status, flags


def validate_url(value: str, host: str | None) -> tuple[str, list[str]]:
    if not host:
        return "malformed", ["url_without_host"]
    if re.fullmatch(r"[0-9.]+", host):
        status, flags = validate_ipv4(host)
        return status, ["ip_based_url", *flags]
    status, flags = validate_domain(host)
    if status == "malformed":
        return "malformed", ["invalid_url_host", *flags]
    return status, flags


def validate_hash(value: str, expected_len: int) -> tuple[str, list[str]]:
    if len(value) != expected_len or not _HEX.match(value):
        return "malformed", ["invalid_hash_length"]
    flags: list[str] = []
    if value in EMPTY_HASHES:
        return "suspicious", ["hash_of_empty_input"]
    if len(set(value)) <= 2:
        return "suspicious", ["low_entropy_hash"]
    return "valid", flags
