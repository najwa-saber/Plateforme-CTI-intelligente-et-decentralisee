"""Canonical representation of a CTI report and its SHA-256 fingerprint.

The SAME function is used at submission time (hash stored on Ethereum) and at
verification time (hash recomputed from the off-chain data), see CDC 9.5.

Canonicalisation v1 rules
-------------------------
* Only the *shared intelligence* is hashed: report id, title, text, provenance,
  publication date, TLP, submitting organisation and the normalised IOC set.
  Derived analysis results (ML probabilities, MITRE suggestions, scores) are
  excluded on purpose: they may legitimately change when a model is retrained
  and must not break integrity verification.
* Strings are Unicode NFC-normalised; line endings are converted to ``\\n``;
  trailing whitespace on each line and leading/trailing blank lines are removed.
* IOCs are deduplicated and sorted by (type, value).
* JSON serialisation: sorted keys, no insignificant whitespace, UTF-8.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Iterable

CANONICAL_VERSION = "cti-report/v1"


def _norm_text(value: str | None) -> str:
    if not value:
        return ""
    value = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in value.split("\n")]
    return "\n".join(lines).strip()


def canonical_payload(
    *,
    report_id: str,
    title: str,
    text: str,
    source: str | None,
    published_at: str | None,
    tlp: str | None,
    submitter_code: str,
    iocs: Iterable[tuple[str, str]],
) -> dict:
    ioc_list = sorted({(t.strip().lower(), v.strip()) for t, v in iocs})
    return {
        "schema": CANONICAL_VERSION,
        "report_id": report_id,
        "title": _norm_text(title),
        "text": _norm_text(text),
        "source": _norm_text(source),
        "published_at": published_at or "",
        "tlp": (tlp or "").upper(),
        "submitter": submitter_code.upper(),
        "iocs": [[t, v] for t, v in ioc_list],
    }


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(payload: dict) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def text_fingerprint(text: str) -> str:
    """Hash of the normalised text only: used for exact duplicate report detection."""
    normalised = " ".join(_norm_text(text).lower().split())
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()
