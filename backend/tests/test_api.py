"""Integration tests: FastAPI + database + simulated MISP + contract double.

Covers the mandatory demonstration scenario end to end and the robustness cases
(auth, authorisation, duplicates, invalid input, MISP/blockchain failures).
"""
import pytest

from tests.conftest import PHISHING_REPORT, SECOND_REPORT, headers

A, B, C = headers("A"), headers("B"), headers("C")


def _import(client, body=PHISHING_REPORT, h=A):
    r = client.post("/api/v1/reports", json=body, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------------------ auth / validation
def test_health_and_liveness(client):
    assert client.get("/health").json() == {"status": "ok"}
    h = client.get("/api/v1/health").json()
    assert h["components"]["database"]["ok"] and h["components"]["ml"]["ok"]
    assert h["components"]["misp"]["mode"] == "simulated"


def test_authentication_required(client):
    assert client.get("/api/v1/reports").status_code == 401
    r = client.get("/api/v1/reports", headers={"X-API-Key": "wrong-key-wrong-key-wrong"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthenticated"
    assert client.get("/api/v1/organizations/me", headers=A).json()["code"] == "A"


@pytest.mark.parametrize("body", [
    {"title": "x", "text": "short"},                                   # too short
    {"title": "Valid title", "text": "y" * 30, "tlp": "TLP:PURPLE"},  # invalid enum
    {"title": "Valid title", "text": "y" * 30, "unknown": 1},         # extra field forbidden
    {"title": "Valid title", "text": "y" * 30, "mitre_techniques": ["X1234"]},
    {"title": "Valid title", "text": "y" * 30, "source_url": "javascript:alert(1)"},
])
def test_invalid_payloads_rejected_with_422(client, body):
    r = client.post("/api/v1/reports", json=body, headers=A)
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"


def test_analyze_endpoint_matches_cdc_contract(client):
    r = client.post("/api/v1/reports/analyze", json={"title": PHISHING_REPORT["title"],
                                                     "text": PHISHING_REPORT["text"]}, headers=A)
    assert r.status_code == 201, r.text
    body = r.json()
    assert {"report_id", "category", "iocs", "mitre_techniques", "status"} <= set(body)
    assert body["status"] == "ANALYZED" and body["category"] == "phishing"
    assert {"type": "domain", "value": "payroll-update-portal.example", "status": "valid"} in body["iocs"]
    assert any(t.startswith("T1566") for t in body["mitre_techniques"])


def test_preview_does_not_persist(client):
    r = client.post("/api/v1/reports/analyze", json={"title": "Preview only", "text": PHISHING_REPORT["text"],
                                                     "persist": False}, headers=A)
    assert r.status_code == 201 and r.json()["status"] == "PREVIEW" and r.json()["report_id"] is None
    assert client.get("/api/v1/reports", headers=A).json()["total"] == 0


# ------------------------------------------------------------------ import / duplicates / access
def test_import_detects_duplicates_and_conflicts(client):
    first = _import(client)
    assert first["details"]["misp"]["sync_status"] == "SYNCED"
    assert first["details"]["misp"]["mode"] == "simulated"
    dup = client.post("/api/v1/reports", json=PHISHING_REPORT, headers=B)
    assert dup.status_code == 409 and dup.json()["error"]["details"]["existing_report_id"] == first["report_id"]
    second = _import(client, SECOND_REPORT, B)
    known = second["duplicates"]["known_in_other_reports"]
    assert any(k["value"] == "payroll-update-portal.example" and first["report_id"] in k["reports"] for k in known)


def test_upload_files_and_unsupported_type(client):
    files = {"file": ("note.txt", b"Ransomware note\n\nThe locker encrypted file servers; C2 at 198.51.100.77.",
                      "text/plain")}
    r = client.post("/api/v1/reports/upload", files=files, data={"tlp": "TLP:AMBER"}, headers=C)
    assert r.status_code == 201, r.text
    assert r.json()["details"]["tlp"] == "TLP:AMBER" and r.json()["details"]["source_type"] == "txt"
    bad = client.post("/api/v1/reports/upload", files={"file": ("x.exe", b"MZ\x90\x00", "application/octet-stream")},
                      headers=C)
    assert bad.status_code == 400


def test_tlp_red_is_private(client):
    rep = _import(client, {**SECOND_REPORT, "title": "Private intel", "tlp": "TLP:RED"}, A)
    assert client.get(f"/api/v1/reports/{rep['report_id']}", headers=A).status_code == 200
    assert client.get(f"/api/v1/reports/{rep['report_id']}", headers=B).status_code == 403
    r = client.post(f"/api/v1/reports/{rep['report_id']}/submit", headers=A)
    assert r.status_code == 409


def test_not_found_and_owner_only_actions(client):
    assert client.get("/api/v1/reports/CTI-NOPE", headers=A).status_code == 404
    rep = _import(client)
    assert client.post(f"/api/v1/reports/{rep['report_id']}/submit", headers=B).status_code == 403
    assert client.post(f"/api/v1/reports/{rep['report_id']}/analyze", headers=B).status_code == 403


def test_submit_requires_analysis(client):
    r = client.post("/api/v1/reports?analyze=false", json=PHISHING_REPORT, headers=A)
    rid = r.json()["report_id"]
    assert r.json()["status"] == "IMPORTED"
    assert client.post(f"/api/v1/reports/{rid}/submit", headers=A).status_code == 409


# ------------------------------------------------------------------ mandatory demonstration scenario
def test_full_demonstration_scenario(client, chain):
    # 1-8 A imports and analyses a phishing report (IOC, normalisation, dedup, ML, MITRE, MISP)
    rep = _import(client)
    rid = rep["report_id"]
    assert rep["category"] == "phishing"
    assert rep["details"]["misp"]["event_id"]
    # 9 A submits the fingerprint on Ethereum
    sub = client.post(f"/api/v1/reports/{rid}/submit", headers=A)
    assert sub.status_code == 200, sub.text
    assert len(sub.json()["content_hash"]) == 64 and sub.json()["status"] == "PENDING"
    assert client.post(f"/api/v1/reports/{rid}/submit", headers=A).status_code == 409  # already submitted
    # 10-11 B consults and approves
    assert client.get(f"/api/v1/reports/{rid}", headers=B).status_code == 200
    vb = client.post(f"/api/v1/reports/{rid}/vote", json={"approve": True}, headers=B)
    assert vb.status_code == 200 and vb.json()["finalized"] is False
    assert client.get(f"/api/v1/reports/{rid}/status", headers=B).json()["status"] == "PENDING"
    # premature finalisation is refused by the contract
    early = client.post(f"/api/v1/reports/{rid}/finalize", headers=B)
    assert early.status_code == 409 and early.json()["error"]["details"]["contract_error"] == "FinalizationTooEarly"
    # robustness: double vote, self-validation
    assert client.post(f"/api/v1/reports/{rid}/vote", json={"approve": True}, headers=B).status_code == 409
    assert client.post(f"/api/v1/reports/{rid}/vote", json={"approve": True}, headers=A).status_code == 403
    # 12-15 C consults and approves -> automatic finalisation -> VALIDATED
    vc = client.post(f"/api/v1/reports/{rid}/vote", json={"approve": True, "comment": "seen in our logs"}, headers=C)
    assert vc.status_code == 200, vc.text
    assert vc.json()["finalized"] is True and vc.json()["status"] == "VALIDATED"
    # 16 reliability score is final and explained
    score = client.get(f"/api/v1/reports/{rid}/score", headers=A).json()
    assert score["is_final"] and score["v"] == 100.0
    assert score["score"] == pytest.approx(0.3 * score["r"] + 0.3 * score["q"] + 0.4 * score["v"], abs=0.02)
    # 17 reputation of A increased, with explanation
    reputation = client.get("/api/v1/organizations/org-a/reputation", headers=B).json()
    assert reputation["reputation"] > 50 and reputation["history"]
    assert "VALIDATED" in reputation["history"][0]["explanation"]
    assert chain.reputation[chain.addresses["A"]] == 5300
    # integrity verified against the on-chain fingerprint
    integ = client.get(f"/api/v1/reports/{rid}/integrity", headers=C).json()
    assert integ["verified"] is True and integ["offchain_match"] is True
    # 18-19 a second report sharing an IOC is correlated
    second = _import(client, SECOND_REPORT, B)
    corr = client.get(f"/api/v1/reports/{second['report_id']}/correlations", headers=B).json()
    linked = {c["report_id"]: c for c in corr["correlations"]}
    assert rid in linked
    assert {"type": "domain", "value": "payroll-update-portal.example"} in linked[rid]["evidence"]["shared_iocs"]
    graph = client.get("/api/v1/correlations/graph", headers=A).json()
    assert any({e["source"], e["target"]} == {rid, second["report_id"]} for e in graph["edges"])
    # 20 dashboard
    dash = client.get("/api/v1/stats/dashboard", headers=A).json()
    assert dash["validated"] == 1 and dash["reports_total"] == 2 and dash["correlations_total"] >= 1
    # MISP event visible and tagged with the validation status (simulated adapter)
    event = client.get(f"/api/v1/misp/events/{rep['details']['misp']['event_id']}", headers=A).json()
    assert event["mode"] == "simulated"
    assert 'cti-platform:status="VALIDATED"' in event["event"]["tags"]
    # machine tags are replaced, not accumulated: a single status tag remains
    assert [t for t in event["event"]["tags"] if t.startswith("cti-platform:status=")] == ['cti-platform:status="VALIDATED"']
    # audit trail of sensitive operations
    actions = {a["action"] for a in client.get("/api/v1/audit", headers=A).json()}
    assert {"report.import", "report.submit"} <= actions


def test_integrity_failure_is_detected(client, chain, db_session):
    rep = _import(client)
    rid = rep["report_id"]
    client.post(f"/api/v1/reports/{rid}/submit", headers=A)
    from app.models.entities import Report

    report = db_session.get(Report, rid)
    report.text = report.text + " (tampered)"
    db_session.commit()
    integ = client.get(f"/api/v1/reports/{rid}/integrity", headers=B).json()
    assert integ["verified"] is False and integ["offchain_match"] is False
    assert "INTEGRITY FAILURE" in integ["message"]


def test_rejected_and_disputed_outcomes(client, chain):
    r1 = _import(client)["report_id"]
    client.post(f"/api/v1/reports/{r1}/submit", headers=A)
    client.post(f"/api/v1/reports/{r1}/vote", json={"approve": False}, headers=B)
    res = client.post(f"/api/v1/reports/{r1}/vote", json={"approve": False}, headers=C).json()
    assert res["status"] == "REJECTED"
    r2 = _import(client, SECOND_REPORT, B)["report_id"]
    client.post(f"/api/v1/reports/{r2}/submit", headers=B)
    client.post(f"/api/v1/reports/{r2}/vote", json={"approve": True}, headers=A)
    res = client.post(f"/api/v1/reports/{r2}/vote", json={"approve": False}, headers=C).json()
    assert res["status"] == "DISPUTED"
    s = client.get(f"/api/v1/reports/{r2}/score", headers=A).json()
    assert s["v"] == 50.0
    # a vote on a finalised report is refused
    assert client.post(f"/api/v1/reports/{r1}/vote", json={"approve": True}, headers=B).status_code == 409


def test_incomplete_after_deadline(client, chain):
    rid = _import(client)["report_id"]
    client.post(f"/api/v1/reports/{rid}/submit", headers=A)
    client.post(f"/api/v1/reports/{rid}/vote", json={"approve": True}, headers=B)
    chain.now_offset = 8 * 24 * 3600
    r = client.post(f"/api/v1/reports/{rid}/finalize", headers=B)
    assert r.status_code == 200 and r.json()["status"] == "INCOMPLETE"
    rep_c = client.get("/api/v1/organizations/org-c/reputation", headers=A).json()
    assert rep_c["history"][0]["reason"] == "validator_absent"


# ------------------------------------------------------------------ external failures
def test_blockchain_unavailable_returns_503(client, chain):
    rid = _import(client)["report_id"]
    chain.down = True
    r = client.post(f"/api/v1/reports/{rid}/submit", headers=A)
    assert r.status_code == 503 and r.json()["error"]["code"] == "blockchain_error"
    # the report stays ANALYZED and can be submitted once the node is back
    chain.down = False
    assert client.get(f"/api/v1/reports/{rid}", headers=A).json()["status"] == "ANALYZED"
    assert client.post(f"/api/v1/reports/{rid}/submit", headers=A).status_code == 200


def test_misp_connection_error_does_not_block_analysis(client, monkeypatch):
    from app.core.config import get_settings
    from app.misp.factory import reset_misp_adapter

    settings = get_settings()
    monkeypatch.setattr(settings, "misp_mode", "real")
    monkeypatch.setattr(settings, "misp_url", "https://127.0.0.1:9")
    monkeypatch.setattr(settings, "misp_key", "x" * 40)
    monkeypatch.setattr(settings, "misp_timeout_s", 2.0)
    reset_misp_adapter()
    rep = _import(client)
    assert rep["status"] == "ANALYZED"
    assert rep["details"]["misp"]["sync_status"] == "FAILED" and rep["details"]["misp"]["error"]
    st = client.get("/api/v1/misp/status", headers=A).json()
    assert st["ok"] is False and st["configured_mode"] == "real"
    reset_misp_adapter()


def test_reports_listing_filters_and_iocs_search(client):
    _import(client)
    _import(client, SECOND_REPORT, B)
    lst = client.get("/api/v1/reports?category=phishing&limit=1", headers=A).json()
    assert lst["total"] == 2 and len(lst["items"]) == 1
    hits = client.get("/api/v1/iocs?q=payroll-update", headers=C).json()
    assert len({h["report_id"] for h in hits}) == 2
    orgs = client.get("/api/v1/organizations", headers=A).json()
    assert [o["code"] for o in orgs] == ["A", "B", "C"]
    model = client.get("/api/v1/ml/model", headers=A).json()
    assert model["available"] and "test" in model["metrics"]


def test_chain_restart_is_detected_not_misread(client, chain):
    """Regression: the in-memory Hardhat network restarted and redeployed at the same address."""
    old = _import(client)["report_id"]
    client.post(f"/api/v1/reports/{old}/submit", headers=A)
    client.post(f"/api/v1/reports/{old}/vote", json={"approve": True}, headers=B)
    chain.simulate_restart()
    # a new report now receives on-chain id 1, the id previously used by `old`
    new = _import(client, SECOND_REPORT, B)["report_id"]
    sub = client.post(f"/api/v1/reports/{new}/submit", headers=B).json()
    assert sub["chain_report_id"] == 1
    integ = client.get(f"/api/v1/reports/{old}/integrity", headers=A).json()
    assert integ["anchor_status"] == "anchor_lost" and integ["verified"] is None
    assert "previous instance" in integ["message"] and integ["offchain_match"] is True
    r = client.post(f"/api/v1/reports/{old}/vote", json={"approve": True}, headers=C)
    assert r.status_code == 409 and r.json()["error"]["code"] == "chain_anchor_mismatch"
    st = client.get(f"/api/v1/reports/{old}/status", headers=A).json()
    assert st["status"] == "PENDING" and "previous instance" in st["chain_error"]
    # the new report is unaffected
    assert client.get(f"/api/v1/reports/{new}/integrity", headers=A).json()["verified"] is True
    # listings never present the old anchor as valid on the new chain
    anchors = {r["report_id"]: r["chain_anchor"] for r in client.get("/api/v1/reports", headers=A).json()["items"]}
    assert anchors[old] == "previous_instance" and anchors[new] == "current"
    assert client.get(f"/api/v1/reports/{old}", headers=A).json()["chain_anchor"] == "previous_instance"
    assert client.get("/api/v1/stats/dashboard", headers=A).json()["anchors_on_previous_instance"] == 1
    health = client.get("/api/v1/health").json()["components"]["ethereum"]
    assert health.get("reports_on_previous_instance", 0) in (0, 1)  # fake chain has no deployment block
