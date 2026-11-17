"""Safe parsing of uploaded CTI documents (TXT, PDF, JSON).

Security measures (prompt section 17):
* extension allow-list + content sniffing (magic bytes / decodability);
* size limit enforced before parsing, page limit for PDF, char limit for text;
* filename sanitisation (no path components are ever used on disk);
* PDF parsed with pypdf in text-only mode: no JavaScript / embedded file is executed.
"""
from __future__ import annotations

import io
import json
import re
import unicodedata
from dataclasses import dataclass, field

from app.core.config import get_settings
from app.core.errors import BadRequestError, PayloadTooLargeError, UnprocessableError

ALLOWED_EXTENSIONS = {"txt": "txt", "text": "txt", "md": "txt", "log": "txt", "pdf": "pdf", "json": "json"}


@dataclass
class ParsedDocument:
    title: str
    text: str
    source_type: str
    filename: str
    metadata: dict = field(default_factory=dict)
    declared_iocs: list[dict] = field(default_factory=list)


def sanitize_filename(name: str | None) -> str:
    name = (name or "upload").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._") or "upload"
    return name[:120]


def _clean_text(text: str) -> str:
    text = text.replace("\x00", "")
    text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _title_from_text(text: str, fallback: str) -> str:
    for line in text.splitlines():
        line = line.strip(" #*-=\t")
        if 8 <= len(line) <= 200:
            return line
    return fallback


def _parse_txt(data: bytes) -> str:
    if b"\x00" in data[:4096]:
        raise UnprocessableError("Binary content detected in a text file")
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def _parse_pdf(data: bytes, max_pages: int) -> tuple[str, dict]:
    if not data.lstrip()[:5].startswith(b"%PDF-"):
        raise UnprocessableError("File does not look like a PDF (missing %PDF- header)")
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise UnprocessableError("Encrypted PDF files are not accepted")
        n_pages = len(reader.pages)
        if n_pages > max_pages:
            raise PayloadTooLargeError(f"PDF has {n_pages} pages (limit {max_pages})")
        texts = [(page.extract_text() or "") for page in reader.pages]
        meta = {}
        if reader.metadata:
            for key in ("/Title", "/Author", "/Subject", "/CreationDate"):
                val = reader.metadata.get(key)
                if val:
                    meta[key.strip("/").lower()] = str(val)[:200]
        meta["pages"] = n_pages
    except (PdfReadError, ValueError, KeyError, TypeError) as exc:
        raise UnprocessableError("Unable to read the PDF file") from exc
    text = "\n\n".join(texts)
    if not text.strip():
        raise UnprocessableError("No extractable text in PDF (scanned documents need OCR, not supported)")
    return text, meta


def _parse_json(data: bytes) -> tuple[str, str | None, dict, list[dict]]:
    try:
        obj = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnprocessableError("Invalid JSON document") from exc
    if not isinstance(obj, dict):
        raise UnprocessableError("JSON report must be an object (see data/annotated/reports.jsonl schema)")
    text = obj.get("text") or obj.get("description") or obj.get("content")
    if not isinstance(text, str) or not text.strip():
        raise UnprocessableError("JSON report requires a non-empty 'text' field")
    declared = obj.get("iocs") or []
    if not isinstance(declared, list):
        raise UnprocessableError("'iocs' must be a list of {type, value}")
    declared_iocs = [d for d in declared if isinstance(d, dict) and "value" in d][:5000]
    meta = {
        k: obj.get(k)
        for k in ("report_id", "source", "source_url", "published_at", "language", "category",
                  "mitre_techniques", "tlp", "campaign_id", "annotation_status")
        if obj.get(k) is not None
    }
    return text, obj.get("title"), meta, declared_iocs


def parse_upload(filename: str | None, data: bytes) -> ParsedDocument:
    settings = get_settings()
    safe_name = sanitize_filename(filename)
    if len(data) == 0:
        raise BadRequestError("Empty file")
    if len(data) > settings.max_upload_bytes:
        raise PayloadTooLargeError(f"File exceeds {settings.max_upload_mb} MB")
    ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
    kind = ALLOWED_EXTENSIONS.get(ext)
    if kind is None:
        raise BadRequestError(f"Unsupported file type '.{ext}'. Allowed: .txt, .pdf, .json")

    metadata: dict = {}
    declared: list[dict] = []
    title: str | None = None
    if kind == "txt":
        text = _parse_txt(data)
    elif kind == "pdf":
        text, metadata = _parse_pdf(data, settings.max_pdf_pages)
        title = metadata.get("title")
    else:
        text, title, metadata, declared = _parse_json(data)

    text = _clean_text(text)
    if len(text) < 20:
        raise UnprocessableError("Report text is too short to be analysed (min 20 characters)")
    if len(text) > settings.max_report_chars:
        raise PayloadTooLargeError(f"Report text exceeds {settings.max_report_chars} characters")
    title = (title or _title_from_text(text, safe_name)).strip()[:300]
    return ParsedDocument(title=title, text=text, source_type=kind, filename=safe_name,
                          metadata=metadata, declared_iocs=declared)
