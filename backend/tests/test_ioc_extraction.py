"""Unit tests: IOC extraction, normalisation, validation, deduplication + corpus evaluation."""
import csv
import json
from pathlib import Path

import pytest

from app.nlp.ioc_extractor import IOCExtractor, merge_declared_iocs
from app.nlp.normalizer import normalize_domain, normalize_ipv4, normalize_url, refang

DATA = Path(__file__).resolve().parents[2] / "data" / "annotated"


@pytest.fixture(scope="module")
def ex():
    return IOCExtractor()


def values(result, t):
    return {i.value for i in result.iocs if i.ioc_type == t}


def test_extracts_all_five_types(ex):
    text = ("C2 at 198.51.100.7, domain evil-cdn.example, url https://evil-cdn.example/a/b?x=1, "
            "md5 44d88612fea8a8f36de82e1278abb02f and sha256 "
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f.")
    r = ex.extract(text)
    assert values(r, "ipv4") == {"198.51.100.7"}
    assert values(r, "domain") == {"evil-cdn.example"}
    assert values(r, "url") == {"https://evil-cdn.example/a/b?x=1"}
    assert values(r, "md5") == {"44d88612fea8a8f36de82e1278abb02f"}
    assert values(r, "sha256") == {"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}


def test_refang_and_defanged_flag(ex):
    r = ex.extract("Beacon to hxxp://bad[.]example/gate and 203.0.113[.]5 and c2(dot)test")
    assert values(r, "url") == {"http://bad.example/gate"}
    assert values(r, "ipv4") == {"203.0.113.5"}
    assert values(r, "domain") == {"c2.test"}
    assert all(i.defanged for i in r.iocs)
    assert refang("evil[.]com hxxps://x[.]y") == "evil.com https://x.y"


def test_normalisation():
    assert normalize_ipv4("010.001.002.003") == "10.1.2.3"
    assert normalize_domain("EVIL.Example.") == "evil.example"
    assert normalize_url("HTTP://Evil.EXAMPLE:80/Path#frag") == "http://evil.example/Path"
    assert normalize_url("https://evil.example:8443") == "https://evil.example:8443/"
    with pytest.raises(ValueError):
        normalize_ipv4("256.1.1.1")


def test_deduplication_counts_occurrences(ex):
    r = ex.extract("203.0.113.9 then again 203.0.113.9 and EVIL.example and evil.example")
    ip = next(i for i in r.iocs if i.ioc_type == "ipv4")
    dom = next(i for i in r.iocs if i.ioc_type == "domain")
    assert ip.occurrences == 2 and dom.occurrences == 2
    assert r.stats["duplicates_removed"] == 2


def test_malformed_iocs_detected(ex):
    r = ex.extract("Bad IP 999.10.10.10 and a truncated hash 44d88612fea8a8f36de82e1278abb02fa1 in the report.")
    statuses = {(i.ioc_type, i.status) for i in r.iocs}
    assert ("ipv4", "malformed") in statuses
    assert ("md5", "malformed") in statuses
    assert all(i.confidence is None for i in r.iocs if i.status == "malformed")


def test_false_positive_filters(ex):
    r = ex.extract("The dropper invoice.pdf launched update.exe; System.Drawing is a .NET namespace.")
    assert not r.iocs
    reasons = {f["reason"] for f in r.stats["filtered"]}
    assert {"probable_filename", "unknown_tld"} <= reasons


def test_suspicious_flags(ex):
    r = ex.extract("Traffic to google.com, 10.0.0.5, 8.8.8.8 and sha256 "
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    by_value = {i.value: i for i in r.iocs}
    assert "known_benign_infrastructure" in by_value["google.com"].flags
    assert by_value["google.com"].status == "suspicious"
    assert "private_address" in by_value["10.0.0.5"].flags
    assert "hash_of_empty_input" in by_value["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"].flags
    # suspicious IOCs get a lower extraction confidence
    assert by_value["google.com"].confidence < 0.5


def test_email_domain_and_context(ex):
    r = ex.extract("Emails were sent from billing@secure-pay.example to employees. The lure was convincing.")
    dom = next(i for i in r.iocs if i.ioc_type == "domain")
    assert dom.value == "secure-pay.example" and "email_domain" in dom.flags
    assert "Emails were sent from" in dom.context


def test_documentation_ranges_are_flagged_not_rejected(ex):
    r = ex.extract("C2 server 192.0.2.10 for phishing.test")
    ip = next(i for i in r.iocs if i.ioc_type == "ipv4")
    assert ip.status == "valid" and "documentation_range" in ip.flags


def test_merge_declared_iocs(ex):
    r = ex.extract("C2 at 198.51.100.7")
    merged = merge_declared_iocs(r, [{"type": "ipv4", "value": "198.51.100.7"},
                                     {"type": "domain", "value": "declared-only.example"},
                                     {"type": "md5", "value": "not-a-hash"}])
    prov = {i.value: i.provenance for i in merged.iocs}
    assert prov["198.51.100.7"] == "extracted+declared"
    assert prov["declared-only.example"] == "declared"
    assert any(i.status == "malformed" and i.provenance == "declared" for i in merged.iocs)


def test_empty_text(ex):
    r = ex.extract("")
    assert r.iocs == [] and r.stats["unique_iocs"] == 0


def test_corpus_precision_recall(ex):
    """Extraction quality on the 80-report annotated corpus (gold annotations are independent)."""
    gold: dict[str, set] = {}
    with (DATA / "iocs.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            gold.setdefault(row["report_id"], set()).add((row["ioc_type"], row["ioc_value"]))
    tp = fp = fn = 0
    for line in (DATA / "reports.jsonl").read_text(encoding="utf-8").splitlines():
        rep = json.loads(line)
        pred = {(i.ioc_type, i.value) for i in ex.extract(rep["text"]).iocs if i.status != "malformed"}
        g = gold.get(rep["report_id"], set())
        tp += len(pred & g)
        fp += len(pred - g)
        fn += len(g - pred)
    precision, recall = tp / (tp + fp), tp / (tp + fn)
    print(f"IOC extraction on corpus: P={precision:.3f} R={recall:.3f} (tp={tp} fp={fp} fn={fn})")
    assert recall >= 0.95
    assert precision >= 0.90
