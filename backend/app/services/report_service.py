"""Report lifecycle orchestration: import -> NLP -> dedup -> ML -> MITRE -> anomalies ->
quality/score -> correlation -> MISP. Blockchain steps are in validation_service.py.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.core.canonical import text_fingerprint
from app.core.config import get_settings
from app.core.errors import ConflictError, MispError, NotFoundError
from app.correlation.engine import CorrelationEngine, report_features, strength_label
from app.misp.base import MispEventPayload
from app.misp.factory import get_misp_adapter
from app.misp.simulated import bind_session
from app.mitre.enricher import get_enricher
from app.ml.classifier import get_classifier
from app.ml.preprocess import clean_text
from app.models.entities import (
    IOC,
    Correlation,
    MitreMatch,
    Organization,
    Report,
    ReportStatus,
)
from app.nlp.consistency import detect_anomalies
from app.nlp.ioc_extractor import ExtractedIOC, get_extractor, merge_declared_iocs
from app.services.scoring import compute_quality, compute_score

logger = logging.getLogger("cti.reports")


def new_report_id() -> str:
    return "CTI-" + secrets.token_hex(5).upper()


def _parse_date(value) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def get_report(db: Session, report_id: str) -> Report:
    report = db.scalar(
        select(Report).where(Report.id == report_id).options(
            selectinload(Report.iocs), selectinload(Report.mitre_matches), selectinload(Report.votes),
            selectinload(Report.scores))
    )
    if report is None:
        raise NotFoundError(f"Report {report_id} not found")
    return report


# ============================================================================ import
def create_report(db: Session, org: Organization, *, title: str, text: str, source_type: str,
                  filename: str | None = None, source: str | None = None, source_url: str | None = None,
                  published_at=None, language: str = "en", tlp: str = "TLP:GREEN",
                  declared_category: str | None = None, declared_mitre: list[str] | None = None,
                  declared_iocs: list[dict] | None = None, is_synthetic: bool = False,
                  extra: dict | None = None) -> Report:
    fp = text_fingerprint(text)
    existing = db.scalar(select(Report).where(Report.text_fingerprint == fp))
    if existing is not None:
        raise ConflictError("Duplicate report: identical content already imported",
                            {"existing_report_id": existing.id, "submitted_by": existing.submitter_id})
    report = Report(
        id=new_report_id(), title=title.strip()[:300], text=text, text_fingerprint=fp, submitter_id=org.id,
        source_type=source_type, original_filename=filename, source=source or f"{org.name} ({source_type})",
        source_url=source_url, published_at=_parse_date(published_at), language=language or "en",
        tlp=(tlp or "TLP:GREEN").upper(), declared_category=declared_category, declared_mitre=declared_mitre or None,
        is_synthetic=is_synthetic,
        extra_metadata={**(extra or {}), "declared_iocs": declared_iocs or []},
        status=ReportStatus.IMPORTED,
    )
    db.add(report)
    db.flush()
    return report


# ============================================================================ analysis
def _near_duplicates(db: Session, report: Report) -> list[dict]:
    threshold = get_settings().near_duplicate_threshold
    others = db.execute(select(Report.id, Report.title, Report.text).where(Report.id != report.id)).all()
    if not others:
        return []
    docs = [clean_text(f"{report.title}. {report.text}")] + [clean_text(f"{t}. {x}") for _, t, x in others]
    try:
        m = TfidfVectorizer(sublinear_tf=True).fit_transform(docs)
    except ValueError:
        return []
    sims = cosine_similarity(m[0], m[1:]).ravel()
    return [{"report_id": others[i][0], "similarity": round(float(s), 3)}
            for i, s in enumerate(sims) if s >= threshold]


def _known_iocs(db: Session, report: Report, values: list[tuple[str, str]]) -> dict[tuple[str, str], list[dict]]:
    if not values:
        return {}
    rows = db.execute(
        select(IOC.ioc_type, IOC.value, IOC.report_id, Report.status)
        .join(Report, Report.id == IOC.report_id)
        .where(IOC.report_id != report.id, IOC.value.in_([v for _, v in values]))
    ).all()
    out: dict[tuple[str, str], list[dict]] = {}
    for t, v, rid, status in rows:
        out.setdefault((t, v), []).append({"report_id": rid, "status": status})
    return out


def run_extraction(text: str, declared_iocs: list[dict] | None = None):
    result = get_extractor().extract(text)
    if declared_iocs:
        result = merge_declared_iocs(result, declared_iocs)
    return result


def preview_analysis(title: str, text: str) -> dict:
    """Stateless analysis (UI preview before import): nothing is stored."""
    extraction = run_extraction(text)
    prediction = get_classifier().predict(title, text).to_dict()
    mitre = [m.to_dict() for m in get_enricher().enrich(title, text)]
    iocs = [i.to_dict() for i in extraction.iocs]
    anomalies = detect_anomalies(iocs=iocs, text=text, prediction=prediction, declared_category=None,
                                 mitre=mitre, published_at=None, near_duplicates=[], rejected_overlap={})
    return {"iocs": iocs, "extraction_stats": extraction.stats, "classification": prediction,
            "mitre_techniques": mitre, "anomalies": anomalies, "persisted": False}


def analyze_report(db: Session, report: Report, push_misp: bool | None = None) -> dict:
    if report.status not in (ReportStatus.IMPORTED, ReportStatus.ANALYZED):
        raise ConflictError("Report already submitted on-chain: re-analysis would break its fingerprint",
                            {"status": report.status})
    settings = get_settings()
    declared_iocs = (report.extra_metadata or {}).get("declared_iocs") or []
    extraction = run_extraction(report.text, declared_iocs)

    # duplicates across the platform (other reports) and in MISP
    usable: list[ExtractedIOC] = [i for i in extraction.iocs if i.status != "malformed"]
    known = _known_iocs(db, report, [(i.ioc_type, i.value) for i in usable])
    misp_known: dict[str, bool] = {}
    misp_lookup_error = None
    try:
        adapter = get_misp_adapter()
        with bind_session(db):
            for i in usable[:50]:
                misp_known[i.value] = bool(adapter.search_ioc(i.value))
    except MispError as exc:
        misp_lookup_error = exc.message

    # replace previous analysis
    report.iocs.clear()
    report.mitre_matches.clear()
    db.flush()
    for i in extraction.iocs:
        refs = known.get((i.ioc_type, i.value), [])
        report.iocs.append(IOC(
            ioc_type=i.ioc_type, value=i.value[:2048], raw_value=i.raw_value[:2048], status=i.status,
            flags=i.flags, provenance=i.provenance, context=(i.context or "")[:1000], occurrences=i.occurrences,
            defanged=i.defanged, confidence=i.confidence,
            known_in_reports=[r["report_id"] for r in refs] or None,
            known_in_misp=misp_known.get(i.value) if i.value in misp_known else None,
        ))

    prediction = get_classifier().predict(report.title, report.text).to_dict()
    report.category = prediction["category"]
    report.category_probabilities = prediction["probabilities"]
    report.classifier = {k: prediction[k] for k in ("method", "model_version", "explanation", "low_confidence")}

    mitre = get_enricher().enrich(report.title, report.text, declared=report.declared_mitre or [])
    for m in mitre:
        report.mitre_matches.append(MitreMatch(
            technique_id=m.technique_id, name=m.name[:200], tactics=m.tactics, method=m.method,
            confidence=m.confidence, justification=m.justification, evidence=m.evidence, url=m.url))

    rejected_overlap: dict[str, list[str]] = {}
    for (t, v), refs in known.items():
        rej = [r["report_id"] for r in refs if r["status"] == ReportStatus.REJECTED]
        if rej:
            rejected_overlap[v] = rej
    ioc_dicts = [i.to_dict() for i in extraction.iocs]
    anomalies = detect_anomalies(
        iocs=ioc_dicts, text=report.text, prediction=prediction, declared_category=report.declared_category,
        mitre=[m.to_dict() for m in mitre], published_at=report.published_at,
        near_duplicates=_near_duplicates(db, report), rejected_overlap=rejected_overlap)
    report.anomalies = anomalies
    report.status = ReportStatus.ANALYZED
    report.analyzed_at = datetime.now(timezone.utc)
    db.flush()
    db.refresh(report)
    report.quality = compute_quality(report)
    score = compute_score(db, report, trigger="analysis")
    correlations = recompute_correlations(db, report)

    duplicates = {
        "within_report": extraction.stats.get("duplicates_removed", 0),
        "known_in_other_reports": [{"type": t, "value": v, "reports": [r["report_id"] for r in refs]}
                                   for (t, v), refs in known.items()],
        "known_in_misp": [v for v, k in misp_known.items() if k],
        "misp_lookup_error": misp_lookup_error,
    }
    report.extra_metadata = {**(report.extra_metadata or {}), "extraction_stats": extraction.stats,
                             "duplicates": duplicates}

    misp_result = None
    if push_misp if push_misp is not None else settings.misp_auto_push:
        misp_result = push_to_misp(db, report)
    db.commit()
    return {"report": report, "score": score, "correlations": correlations, "duplicates": duplicates,
            "extraction_stats": extraction.stats, "misp": misp_result}


# ============================================================================ MISP
def push_to_misp(db: Session, report: Report, force: bool = False) -> dict:
    if report.misp_sync_status == "SYNCED" and not force:
        return {"status": "SYNCED", "event_id": report.misp_event_id, "mode": report.misp_mode,
                "message": "already synchronised"}
    payload = MispEventPayload(
        report_id=report.id, title=report.title, description=report.text, submitter=report.submitter.name,
        tlp=report.tlp, category=report.category,
        published_at=report.published_at.isoformat() if report.published_at else None, source=report.source,
        iocs=[{"type": i.ioc_type, "value": i.value, "status": i.status, "context": i.context,
               "confidence": i.confidence, "flags": i.flags} for i in report.iocs],
        mitre=[{"technique_id": m.technique_id, "name": m.name, "method": m.method, "confidence": m.confidence}
               for m in report.mitre_matches],
        tags=[f'cti-platform:status="{report.status}"'],
    )
    try:
        adapter = get_misp_adapter()
        with bind_session(db):
            res = adapter.push_report(payload)
        report.misp_mode = adapter.mode
        report.misp_event_id = res["event_id"]
        report.misp_event_uuid = res["event_uuid"]
        report.misp_sync_status = "SYNCED"
        report.misp_error = None
        report.misp_synced_at = datetime.now(timezone.utc)
        return {"status": "SYNCED", "mode": adapter.mode, **res}
    except MispError as exc:
        logger.warning("MISP push failed for %s: %s", report.id, exc.message)
        report.misp_sync_status = "FAILED"
        report.misp_error = exc.message[:500]
        return {"status": "FAILED", "error": exc.message, "details": exc.details}


def tag_misp_event(report: Report, tags: list[str], db: Session | None = None) -> str | None:
    """Best effort: add validation metadata to the MISP event (never blocks the workflow)."""
    if not report.misp_event_id:
        return "no MISP event"
    try:
        adapter = get_misp_adapter()
        if db is not None:
            with bind_session(db):
                adapter.add_tags(report.misp_event_uuid or report.misp_event_id, tags)
        else:
            adapter.add_tags(report.misp_event_uuid or report.misp_event_id, tags)
        return None
    except Exception as exc:  # noqa: BLE001 - MISP is optional at this stage
        logger.warning("MISP tagging failed for %s: %s", report.id, getattr(exc, "message", exc))
        return getattr(exc, "message", str(exc))


# ============================================================================ correlation
def recompute_correlations(db: Session, report: Report, engine: CorrelationEngine | None = None) -> list[dict]:
    engine = engine or CorrelationEngine()
    others = db.scalars(select(Report).where(Report.id != report.id, Report.status != ReportStatus.IMPORTED)
                        .options(selectinload(Report.iocs), selectinload(Report.mitre_matches))).all()
    target = report_features(report)
    results = engine.correlate(target, [report_features(o) for o in others])
    db.query(Correlation).filter((Correlation.report_a_id == report.id) | (Correlation.report_b_id == report.id)) \
        .delete(synchronize_session=False)
    for r in results:
        a, b = sorted([report.id, r["report_id"]])
        db.add(Correlation(report_a_id=a, report_b_id=b, score=r["score"], components=r["components"],
                           evidence=r["evidence"], strength=r["strength"]))
    db.flush()
    return results


def correlations_for(db: Session, report: Report, min_score: float | None = None, weights: dict | None = None) -> dict:
    """Stored correlations, or an on-the-fly recomputation when custom weights/threshold are requested."""
    from app.correlation.engine import CorrelationWeights

    if weights and any(v is not None for v in weights.values()):
        engine = CorrelationEngine(CorrelationWeights.from_settings(**weights), threshold=min_score)
        others = db.scalars(select(Report).where(Report.id != report.id, Report.status != ReportStatus.IMPORTED)
                            .options(selectinload(Report.iocs), selectinload(Report.mitre_matches))).all()
        items = engine.correlate(report_features(report), [report_features(o) for o in others])
        return {"report_id": report.id, "weights": engine.weights.as_dict(), "threshold": engine.threshold,
                "recomputed": True, "correlations": items}
    engine = CorrelationEngine()
    threshold = engine.threshold if min_score is None else min_score
    rows = db.scalars(select(Correlation).where(
        ((Correlation.report_a_id == report.id) | (Correlation.report_b_id == report.id)) & (Correlation.score >= threshold)
    ).order_by(Correlation.score.desc())).all()
    items = []
    for c in rows:
        other = c.report_b_id if c.report_a_id == report.id else c.report_a_id
        items.append({"report_id": other, "score": c.score, "strength": strength_label(c.score, engine.threshold),
                      "components": c.components, "evidence": c.evidence})
    return {"report_id": report.id, "weights": engine.weights.as_dict(), "threshold": threshold,
            "recomputed": False, "correlations": items}


def recompute_all_correlations(db: Session) -> int:
    reports = db.scalars(select(Report).where(Report.status != ReportStatus.IMPORTED)
                         .options(selectinload(Report.iocs), selectinload(Report.mitre_matches))).all()
    db.query(Correlation).delete(synchronize_session=False)
    engine = CorrelationEngine()
    feats = [report_features(r) for r in reports]
    sims = engine.text_similarity_matrix(feats)
    count = 0
    for i in range(len(feats)):
        for j in range(i + 1, len(feats)):
            res = engine.pair(feats[i], feats[j], float(sims[i, j]) if sims is not None else 0.0)
            if res["score"] >= engine.threshold:
                a, b = sorted([feats[i].report_id, feats[j].report_id])
                db.add(Correlation(report_a_id=a, report_b_id=b, score=res["score"], components=res["components"],
                                   evidence=res["evidence"], strength=strength_label(res["score"], engine.threshold)))
                count += 1
    db.commit()
    return count
