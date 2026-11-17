"""Unit tests: reliability score (S = 0.30R + 0.30Q + 0.40V) and dynamic reputation safeguards."""
import pytest

from app.models.entities import Organization, Report, ReportStatus, ReputationEvent, Vote
from app.services import reputation as rep
from app.services.scoring import compute_quality, compute_score, compute_validation


def _org(db, oid="org-a", code="A", r=50.0):
    org = db.get(Organization, oid)
    org.reputation = r
    return org


def _report(db, status=ReportStatus.ANALYZED, rid="CTI-T1"):
    rpt = Report(id=rid, title="Synthetic report title", text="word " * 200, text_fingerprint=rid,
                 submitter_id="org-a", source_type="manual", source="unit test", tlp="TLP:GREEN", status=status,
                 category="phishing", category_probabilities={"phishing": 0.8, "malware": 0.1, "ransomware": 0.05,
                                                              "exploitation": 0.05},
                 classifier={"method": "logistic_regression"}, anomalies=[])
    db.add(rpt)
    db.flush()
    db.refresh(rpt)
    return rpt


def test_validation_component_policy(db_session):
    r = _report(db_session)
    assert compute_validation(r)["value"] == 50.0 and not compute_validation(r)["final"]
    r.status = ReportStatus.PENDING
    db_session.add(Vote(report_id=r.id, org_id="org-b", approve=True))
    db_session.flush()
    db_session.refresh(r)
    v = compute_validation(r, {"eligible_validators": 2})
    assert v["value"] == 75.0 and not v["final"]
    db_session.add(Vote(report_id=r.id, org_id="org-c", approve=True))
    r.status = ReportStatus.VALIDATED
    db_session.flush()
    db_session.refresh(r)
    v = compute_validation(r, {"eligible_validators": 2})
    assert v["value"] == 100.0 and v["final"]


def test_disputed_and_rejected_values(db_session):
    r = _report(db_session, ReportStatus.DISPUTED)
    db_session.add_all([Vote(report_id=r.id, org_id="org-b", approve=True),
                        Vote(report_id=r.id, org_id="org-c", approve=False)])
    db_session.flush()
    db_session.refresh(r)
    assert compute_validation(r, {"eligible_validators": 2})["value"] == 50.0
    r2 = _report(db_session, ReportStatus.REJECTED, rid="CTI-T2")
    db_session.add_all([Vote(report_id=r2.id, org_id="org-b", approve=False),
                        Vote(report_id=r2.id, org_id="org-c", approve=False)])
    db_session.flush()
    db_session.refresh(r2)
    assert compute_validation(r2, {"eligible_validators": 2})["value"] == 0.0


def test_score_formula_and_explanations(db_session):
    _org(db_session, r=60.0)
    r = _report(db_session)
    r.quality = compute_quality(r)
    res = compute_score(db_session, r, trigger="test", persist=False)
    expected = 0.30 * 60.0 + 0.30 * res["q"] + 0.40 * 50.0
    assert res["score"] == pytest.approx(expected, abs=0.01)
    d = res["details"]
    assert {"R", "Q", "V", "contributions", "disclaimer"} <= set(d)
    assert "probabilite" in d["disclaimer"] and not res["is_final"]
    assert all("explanation" in c for c in d["Q"]["components"])


def test_quality_penalised_by_anomalies(db_session):
    r = _report(db_session)
    base = compute_quality(r)["value"]
    r.anomalies = [{"code": "malformed_iocs", "severity": "medium", "message": "x", "details": {}},
                   {"code": "category_mismatch", "severity": "medium", "message": "y", "details": {}},
                   {"code": "documentation_range", "severity": "info", "message": "z", "details": {}}]
    q = compute_quality(r)
    assert q["penalty"] == 14.0 and q["value"] == pytest.approx(max(0, base - 14.0))
    r.anomalies = [{"code": f"a{i}", "severity": "high", "message": "", "details": {}} for i in range(10)]
    assert compute_quality(r)["penalty"] == 40.0  # penalty cap


def test_reputation_damping_and_bounds(db_session):
    org = _org(db_session, r=85.0)
    ev = rep.apply_change(db_session, org, 5.0, "test", "gain near the cap")
    assert ev.applied_delta == pytest.approx(1.0)  # damping (90-85)/40 clipped to 0.2 -> 5 x 0.2
    assert org.reputation <= rep.CAP
    org2 = _org(db_session, "org-b", "B", r=11.0)
    rep.apply_change(db_session, org2, -5.0, "test", "loss near the floor")
    assert org2.reputation >= rep.FLOOR


def test_reputation_per_event_and_daily_caps(db_session):
    org = _org(db_session, r=50.0)
    ev = rep.apply_change(db_session, org, 20.0, "test", "huge raw delta")
    assert ev.applied_delta == pytest.approx(rep.PER_EVENT_CAP)
    ev2 = rep.apply_change(db_session, org, 20.0, "test", "second burst")
    ev3 = rep.apply_change(db_session, org, 20.0, "test", "third burst")
    total = sum(abs(e.applied_delta) for e in (ev, ev2, ev3))
    assert total <= rep.DAILY_CAP + 1e-6
    assert ev3.applied_delta == 0
    assert "24h movement cap" in ev3.explanation


def test_reputation_finalization_rules(db_session):
    r = _report(db_session, ReportStatus.VALIDATED)
    r.quality = {"value": 80.0}
    db_session.add_all([Vote(report_id=r.id, org_id="org-b", approve=True),
                        Vote(report_id=r.id, org_id="org-c", approve=False)])
    db_session.flush()
    db_session.refresh(r)
    events = rep.apply_finalization(db_session, r, ["org-b", "org-c"])
    by_org = {e.org_id: e for e in events}
    assert by_org["org-a"].applied_delta > 0          # submitter rewarded (validated, good quality)
    assert by_org["org-b"].applied_delta == pytest.approx(1.0)   # aligned validator
    assert by_org["org-c"].applied_delta == pytest.approx(-1.0)  # contrary validator
    assert db_session.query(ReputationEvent).count() == 3
    assert all(e.explanation for e in events)
