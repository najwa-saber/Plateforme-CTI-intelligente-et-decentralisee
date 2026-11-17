"""Rule-based IOC extraction engine (regex + syntactic validation + normalisation).

Pipeline for one text:
    1. refang (hxxp, [.], (dot) ...) while remembering which tokens were defanged;
    2. URL extraction (spans are reserved so that hosts are not re-extracted);
    3. IPv4, hexadecimal hashes (MD5 / SHA-256) and domain extraction;
    4. normalisation + syntactic validation + suspicion flags;
    5. deduplication inside the report (occurrence counter) and context capture.

The *confidence* attached to an IOC is an EXTRACTION confidence (how sure we are
that the string is an indicator intended by the author), never a probability of
maliciousness.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path

from app.nlp.normalizer import (
    is_defanged,
    normalize_domain,
    normalize_hash,
    normalize_ipv4,
    normalize_url,
    refang,
    url_host,
)
from app.nlp.validators import (
    FILE_EXTENSIONS,
    RESERVED_TLDS,
    SPECIAL_USE_TLDS,
    validate_domain,
    validate_hash,
    validate_ipv4,
    validate_url,
)

_TLD_FILE = Path(__file__).parent / "data" / "tlds-alpha-by-domain.txt"

URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`{}|\\^\[\]]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
HEX_RE = re.compile(r"(?<![0-9a-z])[0-9a-f]{30,70}(?![0-9a-z])", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})(?![\w-]|\.[a-z0-9])",
    re.IGNORECASE,
)
EMAIL_DOMAIN_RE = re.compile(r"(?<=@)(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.IGNORECASE)
_TRAILING = ".,;:!?)]}>\"'"
_IOC_CONTEXT_WORDS = re.compile(
    r"\b(c2|c&c|command[- ]and[- ]control|malicious|payload|beacon|ioc|indicator|hash|sample|dropper|"
    r"download(?:ed|s)?|exfiltrat\w*|phishing|lure|callback|staging|implant|loader|hosted|served)\b",
    re.IGNORECASE,
)

BASE_CONFIDENCE = {"sha256": 0.95, "md5": 0.92, "url": 0.9, "ipv4": 0.85, "domain": 0.75}


@lru_cache(maxsize=1)
def known_tlds() -> frozenset[str]:
    """Official IANA root-zone TLD list (+ RFC 2606/6761 reserved names used in test data)."""
    tlds: set[str] = set(RESERVED_TLDS) | SPECIAL_USE_TLDS
    if _TLD_FILE.exists():
        for line in _TLD_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                tlds.add(line.lower())
    return frozenset(tlds)


@dataclass
class ExtractedIOC:
    ioc_type: str
    value: str
    raw_value: str
    status: str
    flags: list[str] = field(default_factory=list)
    context: str = ""
    occurrences: int = 1
    defanged: bool = False
    confidence: float | None = None
    provenance: str = "extracted"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractionResult:
    iocs: list[ExtractedIOC]
    stats: dict

    def by_type(self) -> dict[str, list[ExtractedIOC]]:
        out: dict[str, list[ExtractedIOC]] = {}
        for ioc in self.iocs:
            out.setdefault(ioc.ioc_type, []).append(ioc)
        return out


def _sentence_context(text: str, start: int, end: int, radius: int = 160) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    window_start = left
    for sep in (". ", "\n", "! ", "? "):
        idx = text.rfind(sep, left, start)
        if idx != -1:
            window_start = max(window_start, idx + len(sep))
    window_end = right
    for sep in (". ", "\n", "! ", "? "):
        idx = text.find(sep, end, right)
        if idx != -1:
            window_end = min(window_end, idx + 1)
    snippet = text[window_start:window_end].strip()
    return re.sub(r"\s+", " ", snippet)


def _overlaps(span: tuple[int, int], reserved: list[tuple[int, int]]) -> bool:
    return any(span[0] < r[1] and r[0] < span[1] for r in reserved)


def _confidence(ioc_type: str, status: str, flags: list[str], defanged: bool, context: str) -> float | None:
    if status == "malformed":
        return None
    conf = BASE_CONFIDENCE[ioc_type]
    if defanged:
        conf += 0.05
    if _IOC_CONTEXT_WORDS.search(context):
        conf += 0.05
    if "known_benign_infrastructure" in flags:
        conf -= 0.35
    if {"private_address", "loopback", "reserved_address"} & set(flags):
        conf -= 0.25
    if "email_domain" in flags:
        conf -= 0.1
    return round(max(0.05, min(conf, 0.99)), 2)


class IOCExtractor:
    """Stateless extractor; one instance can be shared between requests."""

    def __init__(self) -> None:
        self.tlds = known_tlds()

    # -- public API -----------------------------------------------------------------
    def extract(self, text: str) -> ExtractionResult:
        defanged_values = self._defanged_values(text)
        clean = refang(text)
        found: dict[tuple[str, str], ExtractedIOC] = {}
        filtered: list[dict] = []
        reserved: list[tuple[int, int]] = []
        candidates = 0

        def add(ioc_type: str, raw: str, value: str, status: str, flags: list[str], start: int, end: int) -> None:
            key = (ioc_type, value)
            defanged = raw.lower() in defanged_values or value.lower() in defanged_values
            if key in found:
                found[key].occurrences += 1
                found[key].defanged = found[key].defanged or defanged
                return
            context = _sentence_context(clean, start, end)
            found[key] = ExtractedIOC(
                ioc_type=ioc_type, value=value, raw_value=raw, status=status, flags=flags,
                context=context, defanged=defanged,
                confidence=_confidence(ioc_type, status, flags, defanged, context),
            )

        # 1) URLs
        for m in URL_RE.finditer(clean):
            raw = m.group(0).rstrip(_TRAILING)
            candidates += 1
            reserved.append((m.start(), m.start() + len(raw)))
            try:
                value = normalize_url(raw)
            except ValueError:
                add("url", raw, raw, "malformed", ["unparsable_url"], m.start(), m.end())
                continue
            host = url_host(value)
            if host and not re.fullmatch(r"[0-9.]+", host) and host.rsplit(".", 1)[-1] not in self.tlds:
                filtered.append({"value": raw, "reason": "url_host_unknown_tld"})
                continue
            status, flags = validate_url(value, host)
            add("url", raw, value, status, flags, m.start(), m.end())

        # 2) Hex strings: MD5 / SHA-256 (SHA-1 and others are reported as unsupported)
        for m in HEX_RE.finditer(clean):
            if _overlaps((m.start(), m.end()), reserved):
                continue
            raw = m.group(0)
            candidates += 1
            n = len(raw)
            value = normalize_hash(raw)
            if n == 32:
                status, flags = validate_hash(value, 32)
                add("md5", raw, value, status, flags, m.start(), m.end())
            elif n == 64:
                status, flags = validate_hash(value, 64)
                add("sha256", raw, value, status, flags, m.start(), m.end())
            elif n in (40, 56, 96, 128):
                filtered.append({"value": raw, "reason": f"unsupported_hash_length_{n}"})
            elif re.search(r"[a-f]", value) and re.search(r"\d", value):
                # Looks like a hash but has an impossible length -> malformed indicator
                kind = "md5" if abs(n - 32) < abs(n - 64) else "sha256"
                add(kind, raw, value, "malformed", ["invalid_hash_length"], m.start(), m.end())
            reserved.append((m.start(), m.end()))

        # 3) IPv4
        for m in IPV4_RE.finditer(clean):
            if _overlaps((m.start(), m.end()), reserved):
                continue
            raw = m.group(0)
            candidates += 1
            reserved.append((m.start(), m.end()))
            try:
                value = normalize_ipv4(raw)
            except ValueError:
                add("ipv4", raw, raw, "malformed", ["invalid_ipv4"], m.start(), m.end())
                continue
            status, flags = validate_ipv4(value)
            add("ipv4", raw, value, status, flags, m.start(), m.end())

        # 4) Domains (standalone; email domains are tagged)
        email_spans = {(m.start(), m.end()) for m in EMAIL_DOMAIN_RE.finditer(clean)}
        for m in DOMAIN_RE.finditer(clean):
            if _overlaps((m.start(), m.end()), reserved):
                continue
            raw = m.group(0).rstrip(_TRAILING)
            if re.fullmatch(r"[0-9.]+", raw):
                continue
            candidates += 1
            value = normalize_domain(raw)
            tld = value.rsplit(".", 1)[-1]
            labels = value.split(".")
            if tld in FILE_EXTENSIONS and len(labels) <= 3 and tld not in RESERVED_TLDS:
                filtered.append({"value": raw, "reason": "probable_filename"})
                continue
            if tld not in self.tlds:
                filtered.append({"value": raw, "reason": "unknown_tld"})
                continue
            status, flags = validate_domain(value)
            if status == "malformed":
                filtered.append({"value": raw, "reason": flags[0] if flags else "invalid_domain"})
                continue
            if (m.start(), m.end()) in email_spans or (m.start() > 0 and clean[m.start() - 1] == "@"):
                flags = [*flags, "email_domain"]
            add("domain", raw, value, status, flags, m.start(), m.end())

        iocs = list(found.values())
        total_occurrences = sum(i.occurrences for i in iocs)
        stats = {
            "candidates": candidates,
            "unique_iocs": len(iocs),
            "duplicates_removed": total_occurrences - len(iocs),
            "filtered": filtered,
            "by_type": {t: sum(1 for i in iocs if i.ioc_type == t) for t in BASE_CONFIDENCE},
            "by_status": {s: sum(1 for i in iocs if i.status == s) for s in ("valid", "suspicious", "malformed")},
            "defanged": sum(1 for i in iocs if i.defanged),
        }
        return ExtractionResult(iocs=iocs, stats=stats)

    # -- helpers -------------------------------------------------------------------
    @staticmethod
    def _defanged_values(text: str) -> set[str]:
        values: set[str] = set()
        for token in re.findall(r"\S+", text):
            if is_defanged(token):
                cleaned = refang(token).strip(_TRAILING + "(")
                values.add(cleaned.lower())
                values.add(cleaned.lower().rstrip("/"))
        return values


_default_extractor: IOCExtractor | None = None


def get_extractor() -> IOCExtractor:
    global _default_extractor
    if _default_extractor is None:
        _default_extractor = IOCExtractor()
    return _default_extractor


def merge_declared_iocs(result: ExtractionResult, declared: list[dict]) -> ExtractionResult:
    """Merge IOCs declared in a structured (JSON) import with the extracted ones."""
    extractor = get_extractor()
    index = {(i.ioc_type, i.value): i for i in result.iocs}
    for item in declared:
        ioc_type = str(item.get("type", "")).lower().strip()
        raw = str(item.get("value", "")).strip()
        if not raw:
            continue
        sub = extractor.extract(raw)
        matched = [i for i in sub.iocs if i.ioc_type == ioc_type] or sub.iocs
        if not matched:
            entry = ExtractedIOC(ioc_type=ioc_type or "unknown", value=raw, raw_value=raw, status="malformed",
                                 flags=["declared_value_not_recognised"], provenance="declared")
            index[(entry.ioc_type, entry.value)] = entry
            continue
        for ioc in matched:
            key = (ioc.ioc_type, ioc.value)
            if ioc_type and ioc.ioc_type != ioc_type:
                ioc.flags = [*ioc.flags, f"declared_type_mismatch:{ioc_type}"]
            if key in index:
                index[key].provenance = "extracted+declared"
            else:
                ioc.provenance = "declared"
                ioc.context = str(item.get("context") or "declared in structured import")
                index[key] = ioc
    result.iocs = list(index.values())
    return result
