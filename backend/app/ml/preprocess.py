"""Text preprocessing for threat classification.

Indicators (URLs, IPs, hashes, domains) and CVE identifiers are replaced by type
tokens. This prevents the classifier from memorising campaign-specific strings
(a form of leakage) and lets it learn from the *language* of the report.
"""
from __future__ import annotations

import re

from app.nlp.ioc_extractor import DOMAIN_RE, HEX_RE, IPV4_RE, URL_RE
from app.nlp.normalizer import refang

PREPROCESSING_VERSION = "v1-ioc-masking"
CATEGORIES = ["phishing", "ransomware", "malware", "exploitation"]
CATEGORY_LABELS = {
    "phishing": "Phishing",
    "ransomware": "Ransomware",
    "malware": "Malware (hors ransomware)",
    "exploitation": "Exploitation de vulnerabilites",
}

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_NUM = re.compile(r"\b\d+(?:[.,]\d+)?\b")
_NON_WORD = re.compile(r"[^a-z_\s-]")
_SPACES = re.compile(r"\s+")


def clean_text(text: str) -> str:
    text = refang(text or "")
    text = URL_RE.sub(" urltoken ", text)
    text = HEX_RE.sub(" hashtoken ", text)
    text = IPV4_RE.sub(" iptoken ", text)
    text = _CVE.sub(" cvetoken ", text)
    text = DOMAIN_RE.sub(" domaintoken ", text)
    text = text.lower()
    text = _NUM.sub(" numtoken ", text)
    text = _NON_WORD.sub(" ", text)
    return _SPACES.sub(" ", text).strip()


def build_document(title: str | None, text: str) -> str:
    """The title is informative: it is concatenated (once) to the body."""
    return clean_text(f"{title or ''}. {text}")
