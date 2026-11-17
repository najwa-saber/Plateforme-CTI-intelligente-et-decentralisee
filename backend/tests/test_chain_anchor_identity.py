"""Non-regression: on-chain id collisions between two instances of the local network, fingerprint checks,
historical reports, MISP error mapping and MITRE mapping (credential stuffing + no regression on other rules)."""
import json
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from tests.conftest import PHISHING_REPORT, SECOND_REPORT, headers

A, B, C = headers("A"), headers("B"), headers("C")
THIRD = {"title": "Ransomware intrusion with shadow copy deletion",
         "text": ("The locker encrypted the file servers after deleting shadow copies with vssadmin. The ransom note "
                  "pointed to restore-help.test and the binary contacted 198.51.100.240 before encryption started.")}


def _validated(client, body, submitter, voters):
    rid = client.post("/api/v1/reports", json=body, headers=submitter).json()["report_id"]
    assert client.post(f"/api/v1/reports/{rid}/submit", headers=submitter).status_code == 200
    for v in voters:
        client.post(f"/api/v1/reports/{rid}/vote", json={"approve": True}, headers=v)
    return rid


# ----------------------------------------------------------------------------- collisions
def test_id_collision_between_two_instances(client, chain, db_session):
    old = _validated(client, PHISHING_REPORT, A, [B, C])
    old_detail = client.get(f"/api/v1/reports/{old}", headers=B).json()
    chain.simulate_restart()
    new = _validated(client, SECOND_REPORT, B, [A, C])
    assert client.get(f"/api/v1/reports/{new}", headers=A).json()["blockchain"]["chain_report_id"] == \
        old_detail["blockchain"]["chain_report_id"] == 1                          # same on-chain id

    from app.models.entities import Report

    db_session.expire_all()
    o, n = db_session.get(Report, old), db_session.get(Report, new)
    assert o.chain_instance != n.chain_instance                                   # different instances recorded
    # historical report: still consultable, history untouched, never verified against the new record
    d = client.get(f"/api/v1/reports/{old}", headers=C).json()
    assert d["status"] == "VALIDATED" and d["blockchain"]["content_hash"] == old_detail["blockchain"]["content_hash"]
    assert d["chain_anchor"] == "previous_instance"
    integ = client.get(f"/api/v1/reports/{old}/integrity", headers=C).json()
    assert integ["verified"] is None and integ["anchor_status"] == "anchor_lost" and integ["onchain_hash"] is None
    assert integ["offchain_match"] is True
    ev = client.get(f"/api/v1/reports/{old}/chain-events", headers=C).json()
    assert ev["events"] == [] and "warning" in ev                                 # no leak of the new report's events
    # new report: normal behaviour
    assert client.get(f"/api/v1/reports/{new}", headers=A).json()["chain_anchor"] == "current"
    assert client.get(f"/api/v1/reports/{new}/integrity", headers=A).json()["verified"] is True
    assert client.get(f"/api/v1/reports/{new}/status", headers=A).json()["chain"]["external_id"] == new


def test_legacy_row_without_instance_is_detected_by_external_id(client, chain, db_session):
    """Rows anchored before migration 0002 have chain_instance = NULL: detection must not rely on it."""
    old = _validated(client, PHISHING_REPORT, A, [B, C])
    from app.models.entities import Report

    row = db_session.get(Report, old)
    row.chain_instance = None
    db_session.commit()
    assert client.get(f"/api/v1/reports/{old}", headers=A).json()["chain_anchor"] == "current"   # same chain
    chain.simulate_restart()
    _validated(client, SECOND_REPORT, B, [A, C])
    assert client.get(f"/api/v1/reports/{old}", headers=A).json()["chain_anchor"] == "previous_instance"
    assert client.get(f"/api/v1/reports/{old}/integrity", headers=A).json()["anchor_status"] == "anchor_lost"


def test_pending_historical_report_cannot_receive_new_transactions(client, chain):
    old = client.post("/api/v1/reports", json=PHISHING_REPORT, headers=A).json()["report_id"]
    client.post(f"/api/v1/reports/{old}/submit", headers=A)
    chain.simulate_restart()
    _validated(client, SECOND_REPORT, B, [A, C])                                  # occupies on-chain id 1
    for path, h, body in ((f"/api/v1/reports/{old}/vote", B, {"approve": True}),
                          (f"/api/v1/reports/{old}/finalize", B, None)):
        r = client.post(path, headers=h, json=body)
        assert r.status_code == 409 and r.json()["error"]["code"] == "chain_anchor_mismatch"
    assert client.get(f"/api/v1/reports/{old}", headers=A).json()["status"] == "PENDING"   # history untouched


def test_unique_anchor_per_instance_is_enforced_by_the_database(client, chain, db_session):
    r1 = _validated(client, PHISHING_REPORT, A, [B, C])
    r2 = client.post("/api/v1/reports", json=SECOND_REPORT, headers=B).json()["report_id"]
    from app.models.entities import Report

    first, second = db_session.get(Report, r1), db_session.get(Report, r2)
    second.chain_report_id, second.chain_instance = first.chain_report_id, first.chain_instance
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_submitter_mismatch_is_not_accepted_as_anchor(client, chain):
    rid = client.post("/api/v1/reports", json=PHISHING_REPORT, headers=A).json()["report_id"]
    client.post(f"/api/v1/reports/{rid}/submit", headers=A)
    chain.reports[1]["submitter"] = chain.addresses["C"]                         # forged / foreign record
    integ = client.get(f"/api/v1/reports/{rid}/integrity", headers=B).json()
    assert integ["anchor_status"] == "anchor_lost" and "another account" in integ["message"]


def test_fingerprint_tampering_is_an_integrity_failure_not_a_lost_anchor(client, chain, db_session):
    rid = _validated(client, PHISHING_REPORT, A, [B, C])
    from app.models.entities import Report

    row = db_session.get(Report, rid)
    row.title = row.title + " (edited)"
    db_session.commit()
    integ = client.get(f"/api/v1/reports/{rid}/integrity", headers=B).json()
    assert integ["anchor_status"] == "ok" and integ["verified"] is False and "INTEGRITY FAILURE" in integ["message"]


def test_restart_during_submission_is_refused(client, chain):
    rid = client.post("/api/v1/reports", json=PHISHING_REPORT, headers=A).json()["report_id"]
    chain.restart_during_submit = True
    r = client.post(f"/api/v1/reports/{rid}/submit", headers=A)
    assert r.status_code == 503 and r.json()["error"]["code"] == "blockchain_error"
    d = client.get(f"/api/v1/reports/{rid}", headers=A).json()
    assert d["status"] == "ANALYZED" and d["blockchain"]["chain_report_id"] is None


def test_new_reports_work_after_restart_and_transactions_record_their_instance(client, chain):
    _validated(client, PHISHING_REPORT, A, [B, C])
    chain.simulate_restart()
    new = _validated(client, THIRD, C, [A, B])
    assert client.get(f"/api/v1/reports/{new}", headers=C).json()["status"] == "VALIDATED"
    txs = client.get("/api/v1/blockchain/transactions", headers=A).json()
    assert {t["action"] for t in txs if t["report_id"] == new} == {"submit", "vote", "finalize"}
    from app.database.session import SessionLocal
    from app.models.entities import ChainTransaction

    with SessionLocal() as s:
        inst = {t.report_id: t.chain_instance for t in s.query(ChainTransaction).all()}
    assert inst[new] == chain.instance and len(set(inst.values())) == 2           # old txs keep the old instance


# ----------------------------------------------------------------------------- MISP errors
def test_unknown_misp_event_returns_404(client):
    assert client.get("/api/v1/misp/events/99999", headers=A).status_code == 404
    r = client.post("/api/v1/reports/import-misp/99999", headers=A)
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


def test_pymisp_error_mapping_without_network():
    from app.core.errors import MispError, NotFoundError
    from app.misp.pymisp_adapter import PyMispAdapter

    with pytest.raises(NotFoundError):
        PyMispAdapter._check({"errors": (404, {"name": "Invalid event"})}, "event lookup")
    with pytest.raises(MispError):
        PyMispAdapter._check({"errors": (403, {"name": "Forbidden"})}, "event creation")
    assert PyMispAdapter._check({"Event": {}}, "x") == {"Event": {}}


def test_machine_tags_are_replaced_not_accumulated():
    from app.misp.base import superseded_tags

    existing = ["tlp:green", 'cti-platform:status="PENDING"', 'cti-platform:report-id="CTI-1"']
    assert superseded_tags(existing, ['cti-platform:status="VALIDATED"']) == ['cti-platform:status="PENDING"']
    assert superseded_tags(existing, ["tlp:amber"]) == []                         # plain tags never removed


# ----------------------------------------------------------------------------- MITRE mapping
@pytest.mark.parametrize("text,expected", [
    ("Attackers performed credential stuffing against webmail portals using leaked password lists.", "T1110.004"),
    ("The phishing email carried a malicious attachment that users opened.", "T1566.001"),
    ("The ransomware encrypted files and deleted shadow copies with vssadmin.", "T1490"),
    ("A web shell was uploaded to the exploited server.", "T1505.003"),
    ("The loader executed an obfuscated PowerShell command.", "T1059.001"),
    ("The implant includes a keylogger module.", "T1056.001"),
])
def test_mitre_rule_mapping(text, expected):
    from app.mitre.enricher import get_enricher

    ids = {m.technique_id for m in get_enricher().enrich("t", text) if m.method == "rule"}
    assert expected in ids


def test_mitre_no_regression_on_annotated_corpus():
    """Rule-based precision/recall on the 80 annotated reports must not drop below the documented values."""
    from app.mitre.enricher import get_enricher

    enr = get_enricher()
    assert not enr.invalid_rules
    corpus = Path(__file__).resolve().parents[2] / "data" / "annotated" / "reports.jsonl"
    tp = fp = fn = 0
    for line in corpus.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        pred = {m.technique_id for m in enr.enrich(r["title"], r["text"]) if m.method == "rule"}
        gold = set(r["mitre_techniques"])
        tp, fp, fn = tp + len(pred & gold), fp + len(pred - gold), fn + len(gold - pred)
    assert tp / (tp + fp) >= 0.62 and tp / (tp + fn) >= 0.76
