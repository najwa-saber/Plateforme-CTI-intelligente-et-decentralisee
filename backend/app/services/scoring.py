"""Explainable reliability score (CDC 10.1):  S = 0.30 R + 0.30 Q + 0.40 V, all in [0, 100].

* R - reputation of the source organisation (off-chain dynamic reputation, see reputation.py);
* Q - quality of the information (IOC validity/richness, ATT&CK context, classifier
      confidence, metadata completeness, substance) minus inconsistency penalties;
* V - result of the collaborative validation (votes recorded on Ethereum).

Policy for incomplete validation (prompt section 12):
  - not submitted / no vote      -> V = 50 (neutral), score flagged PROVISIONAL;
  - PENDING                      -> V = 50 + 50 (approvals - rejections) / eligible, PROVISIONAL;
  - VALIDATED/REJECTED/INCOMPLETE-> same formula on the final votes, FINAL;
  - DISPUTED                     -> V = 50 + 50 (approvals - rejections) / eligible = 50 for 1/1.
The score is an explainable reliability indicator, NOT a probability of veracity.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import Report, ReportStatus, ScoreSnapshot
from app.nlp.consistency import SEVERITY_PENALTY, penalty

DISCLAIMER = ("Indicateur de fiabilite explicable (0-100). Ce n'est pas une probabilite de veracite : "
              "il combine la reputation de la source, la qualite des informations et le resultat des votes.")


def _r(x: float) -> float:
    return round(float(x), 2)


def compute_quality(report: Report) -> dict:
    iocs = [i for i in report.iocs]
    usable = [i for i in iocs if i.status != "malformed"]
    components: list[dict] = []

    # 1. IOC validity (25)
    if iocs:
        validity = sum(1.0 if i.status == "valid" else 0.5 if i.status == "suspicious" else 0.0 for i in iocs) / len(iocs)
        why = f"{sum(i.status == 'valid' for i in iocs)} valid, {sum(i.status == 'suspicious' for i in iocs)} " \
              f"suspicious, {sum(i.status == 'malformed' for i in iocs)} malformed out of {len(iocs)}"
    else:
        validity, why = 0.0, "no indicator extracted"
    components.append({"name": "ioc_validity", "weight": 25, "value": _r(validity), "points": _r(25 * validity),
                       "explanation": why})

    # 2. IOC richness (15)
    types = {i.ioc_type for i in usable}
    richness = 0.6 * min(1.0, len(usable) / 5) + 0.4 * min(1.0, len(types) / 3)
    components.append({"name": "ioc_richness", "weight": 15, "value": _r(richness), "points": _r(15 * richness),
                       "explanation": f"{len(usable)} usable IOC(s) of {len(types)} type(s) "
                                      f"(saturation at 5 IOCs / 3 types)"})

    # 3. ATT&CK context (15) - weak similarity suggestions are not counted
    strong = [m for m in report.mitre_matches if m.method in ("rule", "declared") and m.confidence > 0]
    mitre_v = min(1.0, len(strong) / 3)
    components.append({"name": "mitre_context", "weight": 15, "value": _r(mitre_v), "points": _r(15 * mitre_v),
                       "explanation": f"{len(strong)} technique(s) supported by textual evidence (saturation at 3)"})

    # 4. classification confidence (15)
    probs = report.category_probabilities or {}
    method = (report.classifier or {}).get("method")
    conf = max(probs.values()) if probs else 0.0
    if method == "keyword_baseline":
        conf *= 0.5
    components.append({"name": "classification_confidence", "weight": 15, "value": _r(conf), "points": _r(15 * conf),
                       "explanation": f"max class probability {max(probs.values()) if probs else 0:.2f} "
                                      f"({method or 'not classified'})"})

    # 5. metadata completeness (15)
    meta_items = {
        "source": (0.30, bool(report.source)),
        "published_at": (0.25, report.published_at is not None),
        "source_url": (0.15, bool(report.source_url)),
        "tlp": (0.15, bool(report.tlp)),
        "title": (0.15, bool(report.title and len(report.title) >= 8)),
    }
    meta_v = sum(w for w, ok in meta_items.values() if ok)
    components.append({"name": "metadata_completeness", "weight": 15, "value": _r(meta_v), "points": _r(15 * meta_v),
                       "explanation": "present: " + ", ".join(k for k, (_, ok) in meta_items.items() if ok)
                                      + ("; missing: " + ", ".join(k for k, (_, ok) in meta_items.items() if not ok)
                                         if not all(ok for _, ok in meta_items.values()) else "")})

    # 6. substance (15)
    words = len(report.text.split())
    subst = min(1.0, words / 150)
    components.append({"name": "text_substance", "weight": 15, "value": _r(subst), "points": _r(15 * subst),
                       "explanation": f"{words} words (saturation at 150)"})

    gross = sum(c["points"] for c in components)
    anomalies = report.anomalies or []
    pen = penalty(anomalies)
    q = max(0.0, min(100.0, gross - pen))
    return {
        "value": _r(q),
        "gross": _r(gross),
        "penalty": _r(pen),
        "components": components,
        "penalties": [
            {"code": a["code"], "severity": a["severity"], "points": SEVERITY_PENALTY.get(a["severity"], 0.0),
             "message": a["message"]}
            for a in anomalies if SEVERITY_PENALTY.get(a["severity"], 0.0) > 0
        ],
        "penalty_cap": 40.0,
    }


def compute_validation(report: Report, chain_view: dict | None = None) -> dict:
    status = report.status
    approvals = sum(1 for v in report.votes if v.approve)
    rejections = sum(1 for v in report.votes if not v.approve)
    eligible = (chain_view or {}).get("eligible_validators")
    if not eligible:
        eligible = max(1, len({v.org_id for v in report.votes}) or 2)
    if status in (ReportStatus.IMPORTED, ReportStatus.ANALYZED):
        return {"value": 50.0, "status": "NOT_SUBMITTED", "approvals": 0, "rejections": 0, "eligible": None,
                "final": False, "explanation": "Not submitted for collaborative validation: neutral value 50 "
                                                "(provisional)."}
    v = 50.0 + 50.0 * (approvals - rejections) / eligible
    v = max(0.0, min(100.0, v))
    final = status in ReportStatus.FINAL
    explanation = (f"{approvals} approval(s), {rejections} rejection(s) out of {eligible} eligible validator(s): "
                   f"V = 50 + 50 x ({approvals} - {rejections}) / {eligible} = {v:.1f}")
    if status == ReportStatus.PENDING:
        explanation += " - votes in progress, provisional value."
    elif status == ReportStatus.INCOMPLETE:
        explanation += " - voting deadline reached without majority (validation incomplete)."
    elif status == ReportStatus.DISPUTED:
        explanation += " - validators disagree (no majority)."
    return {"value": _r(v), "status": status, "approvals": approvals, "rejections": rejections,
            "eligible": eligible, "final": final, "explanation": explanation}


def compute_score(db: Session, report: Report, trigger: str, chain_view: dict | None = None,
                  persist: bool = True) -> dict:
    s = get_settings()
    r_value = float(report.submitter.reputation)
    q = compute_quality(report)
    v = compute_validation(report, chain_view)
    score = s.score_weight_r * r_value + s.score_weight_q * q["value"] + s.score_weight_v * v["value"]
    level = "elevee" if score >= 70 else "moyenne" if score >= 45 else "faible"
    details = {
        "formula": f"S = {s.score_weight_r:.2f} R + {s.score_weight_q:.2f} Q + {s.score_weight_v:.2f} V",
        "weights": {"R": s.score_weight_r, "Q": s.score_weight_q, "V": s.score_weight_v},
        "R": {"value": _r(r_value), "explanation": f"Current reputation of {report.submitter.name} "
                                                    f"(neutral start 50, bounded 10-90)"},
        "Q": q,
        "V": v,
        "contributions": {"R": _r(s.score_weight_r * r_value), "Q": _r(s.score_weight_q * q["value"]),
                          "V": _r(s.score_weight_v * v["value"])},
        "anomalies": report.anomalies or [],
        "level": level,
        "final": v["final"],
        "disclaimer": DISCLAIMER,
    }
    result = {"score": _r(score), "r": _r(r_value), "q": q["value"], "v": v["value"], "is_final": v["final"],
              "validation_status": v["status"], "details": details}
    if persist:
        snap = ScoreSnapshot(report_id=report.id, score=result["score"], r=result["r"], q=result["q"],
                             v=result["v"], is_final=result["is_final"], validation_status=v["status"],
                             details=details, trigger=trigger)
        db.add(snap)
    return result
