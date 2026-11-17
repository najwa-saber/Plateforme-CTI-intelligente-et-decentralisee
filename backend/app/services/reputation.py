"""Dynamic, explainable and bounded reputation of organisations (CDC 10.2, prompt section 13).

Two levels are kept and displayed side by side:
* protocol reputation (on-chain, CTIValidation.sol): fixed bounded deltas driven only by
  validation outcomes - tamper-evident;
* analytical reputation (off-chain, this module): also uses the QUALITY of submitted
  reports; it is the R component of the reliability score.

Rules applied at the finalisation of a report (single trigger -> no double counting):
  submitter  VALIDATED  : raw = +2 + 3 (Q-50)/50     ([-1, +5])
             REJECTED   : raw = -4 + 1 (Q-50)/50     ([-5, -3])
             DISPUTED   : raw = 0.5 (Q-50)/50        ([-0.5, +0.5])
             INCOMPLETE : 0
  validator  vote aligned with the final majority : +1 ; contrary : -1 ; (DISPUTED: 0)
             eligible but did not vote            : -0.5 (VALIDATED / REJECTED / INCOMPLETE)
Safeguards:
  * neutral start 50, floor 10 (no permanent exclusion), cap 90 (no permanent domination);
  * damping: gains shrink near the cap, losses shrink near the floor (min factor 0.2);
  * per-event cap |delta| <= 5;
  * rolling 24 h cap: an organisation cannot move by more than 10 points per day
    (limits bursts of self-serving submissions or collusive votes);
  * self-validation is impossible (enforced on-chain and in the API).
Every change is stored in reputation_events with a human-readable explanation.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.entities import Organization, Report, ReportStatus, ReputationEvent

NEUTRAL, FLOOR, CAP = 50.0, 10.0, 90.0
PER_EVENT_CAP = 5.0
DAILY_CAP = 10.0
MIN_DAMPING = 0.2


def _damping(current: float, raw: float) -> float:
    if raw >= 0:
        factor = (CAP - current) / (CAP - NEUTRAL)
    else:
        factor = (current - FLOOR) / (NEUTRAL - FLOOR)
    return max(MIN_DAMPING, min(1.0, factor))


def _recent_movement(db: Session, org_id: str, now: datetime) -> float:
    since = now - timedelta(hours=24)
    total = db.scalar(select(func.coalesce(func.sum(func.abs(ReputationEvent.applied_delta)), 0.0))
                      .where(ReputationEvent.org_id == org_id, ReputationEvent.created_at >= since))
    return float(total or 0.0)


def apply_change(db: Session, org: Organization, raw: float, reason: str, explanation: str,
                 report: Report | None = None, details: dict | None = None,
                 onchain_value: float | None = None) -> ReputationEvent | None:
    now = datetime.now(timezone.utc)
    old = float(org.reputation)
    damping = _damping(old, raw)
    applied = raw * damping
    notes = []
    if abs(applied) > PER_EVENT_CAP:
        applied = PER_EVENT_CAP if applied > 0 else -PER_EVENT_CAP
        notes.append(f"per-event cap +/-{PER_EVENT_CAP}")
    budget = max(0.0, DAILY_CAP - _recent_movement(db, org.id, now))
    if abs(applied) > budget:
        applied = budget if applied > 0 else -budget
        notes.append(f"24h movement cap {DAILY_CAP} (remaining budget {budget:.2f})")
    new = min(CAP, max(FLOOR, old + applied))
    if new != old + applied:
        notes.append(f"bounded to [{FLOOR}, {CAP}]")
    applied = new - old
    full_expl = (f"{explanation} Raw delta {raw:+.2f} x damping {damping:.2f}"
                 + (f" ({'; '.join(notes)})" if notes else "") + f" -> {applied:+.2f} ({old:.2f} -> {new:.2f}).")
    event = ReputationEvent(org_id=org.id, report_id=report.id if report else None, old_value=round(old, 2),
                            new_value=round(new, 2), raw_delta=round(raw, 3), applied_delta=round(applied, 3),
                            reason=reason, explanation=full_expl,
                            details={**(details or {}), "damping": round(damping, 3), "safeguards": notes},
                            onchain_value=onchain_value)
    org.reputation = round(new, 2)
    db.add(event)
    db.flush()  # make the movement visible to the 24h cap of the next change in the same transaction
    return event


def apply_finalization(db: Session, report: Report, eligible_org_ids: list[str],
                       onchain_reputations: dict[str, float] | None = None) -> list[ReputationEvent]:
    """Update reputations after a report reached a final status."""
    onchain_reputations = onchain_reputations or {}
    status = report.status
    q = float((report.quality or {}).get("value", 50.0))
    events: list[ReputationEvent] = []
    submitter = report.submitter
    qf = (q - 50.0) / 50.0
    if status == ReportStatus.VALIDATED:
        raw, why = 2.0 + 3.0 * qf, f"Report {report.id} VALIDATED by peers (quality Q={q:.0f})."
    elif status == ReportStatus.REJECTED:
        raw, why = -4.0 + 1.0 * qf, f"Report {report.id} REJECTED by peers (quality Q={q:.0f})."
    elif status == ReportStatus.DISPUTED:
        raw, why = 0.5 * qf, f"Report {report.id} DISPUTED (no majority); only quality Q={q:.0f} is considered."
    else:
        raw, why = 0.0, f"Report {report.id} INCOMPLETE (deadline reached): submitter reputation unchanged."
    if raw != 0.0:
        ev = apply_change(db, submitter, raw, f"submission_{status.lower()}", why, report,
                          {"quality": q, "status": status}, onchain_reputations.get(submitter.id))
        if ev:
            events.append(ev)

    votes = {v.org_id: v for v in report.votes}
    for org_id in eligible_org_ids:
        org = db.get(Organization, org_id)
        if org is None or org_id == submitter.id:
            continue
        vote = votes.get(org_id)
        if vote is None:
            if status in (ReportStatus.VALIDATED, ReportStatus.REJECTED, ReportStatus.INCOMPLETE):
                ev = apply_change(db, org, -0.5, "validator_absent",
                                  f"{org.name} was an eligible validator of {report.id} but did not vote.",
                                  report, {"status": status}, onchain_reputations.get(org_id))
                events.append(ev)
            continue
        if status not in (ReportStatus.VALIDATED, ReportStatus.REJECTED):
            continue
        aligned = vote.approve == (status == ReportStatus.VALIDATED)
        ev = apply_change(
            db, org, 1.0 if aligned else -1.0, "validator_aligned" if aligned else "validator_misaligned",
            f"{org.name} voted {'APPROVE' if vote.approve else 'REJECT'} on {report.id}, final decision {status}"
            f" ({'consistent' if aligned else 'contrary'}).",
            report, {"vote": vote.approve, "status": status}, onchain_reputations.get(org_id))
        events.append(ev)
    return [e for e in events if e is not None]
