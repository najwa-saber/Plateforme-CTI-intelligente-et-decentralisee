"""Unit tests: canonical hashing, document parsing, classification, MITRE enrichment, correlation engine."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.core.canonical import canonical_payload, sha256_hex, text_fingerprint
from app.core.errors import BadRequestError, PayloadTooLargeError, UnprocessableError
from app.correlation.engine import CorrelationEngine, CorrelationWeights, ReportFeatures
from app.ml.classifier import ThreatClassifier
from app.ml.preprocess import CATEGORIES, clean_text
from app.mitre.catalog import get_catalog
from app.mitre.enricher import get_enricher
from app.mitre.rules import RULES
from app.nlp.document_parser import parse_upload, sanitize_filename


# ------------------------------------------------------------------ canonical hash
def _payload(**kw):
    base = dict(report_id="CTI-1", title="T", text="line one\nline two", source="s", published_at="2026-01-01",
                tlp="tlp:green", submitter_code="a", iocs=[("domain", "x.example"), ("ipv4", "192.0.2.1")])
    base.update(kw)
    return canonical_payload(**base)


def test_canonical_hash_is_stable_and_order_independent():
    h1 = sha256_hex(_payload())
    h2 = sha256_hex(_payload(text="line one   \r\nline two\n\n", iocs=[("ipv4", "192.0.2.1"), ("domain", "x.example"),
                                                                       ("domain", "x.example")]))
    assert h1 == h2 and len(h1) == 64


def test_canonical_hash_detects_tampering():
    assert sha256_hex(_payload()) != sha256_hex(_payload(text="line one\nline 2"))
    assert sha256_hex(_payload()) != sha256_hex(_payload(iocs=[("domain", "x.example")]))


def test_text_fingerprint_ignores_case_and_spacing():
    assert text_fingerprint("Hello   World") == text_fingerprint("hello world")


# ------------------------------------------------------------------ document parser
def _minimal_pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offsets = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer << /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode()
    return out


def test_parse_txt_json_pdf():
    doc = parse_upload("report.txt", b"Phishing report title\n\nAttackers used evil.example to phish users.")
    assert doc.source_type == "txt" and doc.title == "Phishing report title"
    payload = {"title": "J", "text": "Ransomware encrypted servers via 203.0.113.5 last week.", "category": "ransomware",
               "iocs": [{"type": "ipv4", "value": "203.0.113.5"}], "mitre_techniques": ["T1486"]}
    doc = parse_upload("r.json", json.dumps(payload).encode())
    assert doc.source_type == "json" and doc.declared_iocs[0]["value"] == "203.0.113.5"
    assert doc.metadata["category"] == "ransomware"
    doc = parse_upload("r.pdf", _minimal_pdf("Malware beacon to 198.51.100.9 observed in the SOC"))
    assert doc.source_type == "pdf" and "198.51.100.9" in doc.text


@pytest.mark.parametrize("name,data,exc", [
    ("empty.txt", b"", BadRequestError),
    ("evil.exe", b"MZ....", BadRequestError),
    ("bin.txt", b"abc\x00\x00\x00def" * 10, UnprocessableError),
    ("bad.json", b"{not json", UnprocessableError),
    ("list.json", b"[1,2,3]", UnprocessableError),
    ("notext.json", b'{"title": "x"}', UnprocessableError),
    ("fake.pdf", b"this is not a pdf at all", UnprocessableError),
    ("short.txt", b"too short", UnprocessableError),
])
def test_parser_rejects_malicious_or_malformed_files(name, data, exc):
    with pytest.raises(exc):
        parse_upload(name, data)


def test_parser_size_limit(monkeypatch):
    from app.core import config

    monkeypatch.setattr(config.get_settings(), "max_upload_mb", 0.001)
    with pytest.raises(PayloadTooLargeError):
        parse_upload("big.txt", b"a" * 5000)


def test_sanitize_filename():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("C:\\x\\évil name.pdf") == "evil_name.pdf"


# ------------------------------------------------------------------ classification
@pytest.fixture(scope="module")
def clf():
    c = ThreatClassifier()
    assert c.load(), "model artefact missing: run python -m app.ml.train"
    return c


def test_classifier_outputs_probabilities_for_four_categories(clf):
    p = clf.predict("Credential phishing", "Employees received emails with a link to a fake login page that "
                                           "harvested their passwords.")
    assert set(p.probabilities) == set(CATEGORIES)
    assert abs(sum(p.probabilities.values()) - 1) < 1e-3
    assert p.category == "phishing" and p.method == "logistic_regression"
    assert p.explanation and all(e["weight"] > 0 for e in p.explanation)


@pytest.mark.parametrize("title,text,expected", [
    ("Locker attack", "The files were encrypted and a ransom note demanded bitcoin; shadow copies were deleted.",
     "ransomware"),
    ("Appliance flaw", "Attackers exploited an unauthenticated remote code execution vulnerability (CVE) in the "
                       "VPN appliance before the patch was applied.", "exploitation"),
    ("Stealer", "The trojan steals browser passwords, installs a backdoor and beacons to its C2 server.", "malware"),
])
def test_classifier_main_categories(clf, title, text, expected):
    assert clf.predict(title, text).category == expected


def test_classifier_falls_back_to_keyword_baseline(tmp_path):
    c = ThreatClassifier(model_path=str(tmp_path / "absent.joblib"))
    p = c.predict("x", "ransom note and encrypted files")
    assert p.method == "keyword_baseline" and p.category == "ransomware" and p.low_confidence


def test_preprocessing_masks_indicators():
    out = clean_text("C2 hxxp://evil[.]example/x at 203.0.113.5, CVE-2099-0001, hash 44d88612fea8a8f36de82e1278abb02f")
    assert "urltoken" in out and "iptoken" in out and "cvetoken" in out and "hashtoken" in out
    assert "evil" not in out and "203" not in out


# ------------------------------------------------------------------ MITRE
def test_catalogue_is_official_and_rules_are_valid():
    cat = get_catalog()
    assert len(cat) > 500 and cat.get("T1566.001")["name"] == "Spearphishing Attachment"
    enr = get_enricher()
    assert not enr.invalid_rules, f"rules referencing unknown techniques: {enr.invalid_rules}"
    assert len(enr.rules) == len(RULES)


def test_mitre_rules_with_justification():
    matches = get_enricher().enrich("Invoice lure", "Finance staff received a phishing email with a malicious "
                                                    "attachment; the macro launched PowerShell.")
    ids = {m.technique_id: m for m in matches}
    assert "T1566.001" in ids and "T1059.001" in ids
    m = ids["T1566.001"]
    assert m.method == "rule" and m.evidence and "requires analyst confirmation" in m.justification
    assert m.tactics == ["Initial Access"]


def test_mitre_ransomware_and_declared_unknown():
    matches = get_enricher().enrich("x", "The ransomware encrypted files and deleted shadow copies with vssadmin.",
                                    declared=["T1486", "T9999"])
    ids = {m.technique_id: m for m in matches}
    assert {"T1486", "T1490"} <= set(ids)
    assert "declared" in ids["T1486"].justification.lower()
    assert ids["T9999"].confidence == 0 and ids["T9999"].method == "declared"


# ------------------------------------------------------------------ correlation
def _feat(rid, iocs, mitre=(), cat="phishing", days=0, text="phishing emails with fake login page"):
    return ReportFeatures(report_id=rid, title=rid, text=text, category=cat,
                          date=datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(days=days),
                          iocs=set(iocs), mitre=set(mitre))


def test_correlation_shared_domain_and_technique():
    eng = CorrelationEngine(threshold=0.3)
    a = _feat("A", {("domain", "evil.example"), ("ipv4", "192.0.2.1")}, {"T1566.002"})
    b = _feat("B", {("domain", "evil.example")}, {"T1566.002"}, days=3)
    c = _feat("C", {("domain", "other.example")}, {"T1486"}, cat="ransomware", days=200,
              text="ransomware encrypted the servers and demanded a ransom")
    res = eng.correlate(a, [b, c])
    assert [r["report_id"] for r in res] == ["B"]
    ev = res[0]["evidence"]
    assert ev["shared_iocs"] == [{"type": "domain", "value": "evil.example"}]
    assert ev["shared_mitre"] == ["T1566.002"] and "does not prove" in ev["interpretation"]
    assert res[0]["components"]["ioc"] == pytest.approx(0.7)


def test_correlation_weights_are_normalised_and_configurable():
    w = CorrelationWeights.from_settings(ioc=1, mitre=0, text=0, time=0, category=0)
    assert w.ioc == 1.0 and w.text == 0
    eng = CorrelationEngine(weights=w, threshold=0.5)
    a = _feat("A", {("sha256", "f" * 64)})
    b = _feat("B", {("sha256", "f" * 64)})
    assert eng.correlate(a, [b])[0]["score"] == pytest.approx(0.9)
    with pytest.raises(ValueError):
        CorrelationWeights.from_settings(ioc=0, mitre=0, text=0, time=0, category=0)
