"""Health, statistics, ML/MITRE information, IOC search, MISP, blockchain and correlation graph endpoints."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.blockchain.client import get_chain_client
from app.core.config import get_settings
from app.core.errors import AppError, MispError, NotFoundError
from app.core.security import get_current_org
from app.database.session import get_db
from app.misp.factory import get_misp_adapter, reset_misp_adapter
from app.mitre.catalog import get_catalog
from app.mitre.enricher import get_enricher
from app.ml.classifier import get_classifier
from app.models.entities import (
    IOC,
    AuditLog,
    ChainTransaction,
    Correlation,
    MitreMatch,
    Organization,
    Report,
    ReportStatus,
    ScoreSnapshot,
)
from app.services import report_service as rs
from app.services.audit import audit
from app.services.validation_service import anchor_states

router = APIRouter(tags=["system"])


@router.get("/health", summary="Liveness probe")
def liveness():
    return {"status": "ok"}


@router.get("/api/v1/health", summary="Etat des composants (DB, ML, MITRE, MISP, Ethereum)")
def health(db: Session = Depends(get_db)):
    settings = get_settings()
    components: dict = {}
    try:
        db.execute(select(1))
        components["database"] = {"ok": True, "engine": "sqlite" if settings.is_sqlite else "postgresql"}
    except Exception as exc:  # pragma: no cover
        components["database"] = {"ok": False, "error": type(exc).__name__}
    clf = get_classifier()
    components["ml"] = {"ok": clf.available, "version": clf.version, "error": clf.load_error}
    cat = get_catalog()
    components["mitre"] = {"ok": len(cat) > 0, "attack_version": cat.attack_version, "techniques": len(cat),
                           "rules": len(get_enricher().rules)}
    try:
        components["misp"] = {"ok": True, **get_misp_adapter().health()}
    except MispError as exc:
        components["misp"] = {"ok": False, "mode": settings.misp_mode, "error": exc.message}
    chain = get_chain_client().health()
    components["ethereum"] = {"ok": bool(chain.get("connected") and chain.get("contract_deployed")), **chain}
    if chain.get("chain_instance"):
        anchored = db.execute(select(Report.chain_instance).where(Report.chain_report_id.is_not(None))).scalars().all()
        stale = sum(1 for inst in anchored if inst != chain["chain_instance"])
        components["ethereum"]["reports_anchored"] = len(anchored)
        components["ethereum"]["reports_on_previous_instance"] = stale
        if stale:
            components["ethereum"]["warning"] = (
                f"{stale} report(s) were anchored on a previous instance of the local Hardhat network "
                "(in-memory chain restarted): their on-chain verification is no longer possible. "
                "See docs/07_troubleshooting.md (chain reset).")
    overall = all(c.get("ok") for c in components.values())
    return {"status": "ok" if overall else "degraded", "version": settings.app_version, "components": components}


@router.get("/api/v1/stats/dashboard", summary="Indicateurs du tableau de bord")
def dashboard(org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    by_status = dict(db.execute(select(Report.status, func.count()).group_by(Report.status)).all())
    by_category = dict(db.execute(select(Report.category, func.count()).where(Report.category.is_not(None))
                                  .group_by(Report.category)).all())
    ioc_by_type = dict(db.execute(select(IOC.ioc_type, func.count()).where(IOC.status != "malformed")
                                  .group_by(IOC.ioc_type)).all())
    ioc_by_status = dict(db.execute(select(IOC.status, func.count()).group_by(IOC.status)).all())
    unique_iocs = db.scalar(select(func.count()).select_from(
        select(IOC.ioc_type, IOC.value).where(IOC.status != "malformed").distinct().subquery()))
    top_mitre = db.execute(select(MitreMatch.technique_id, MitreMatch.name, func.count().label("n"))
                           .where(MitreMatch.method != "similarity")
                           .group_by(MitreMatch.technique_id, MitreMatch.name).order_by(func.count().desc())
                           .limit(10)).all()
    shared = db.execute(select(IOC.ioc_type, IOC.value, func.count(func.distinct(IOC.report_id)).label("n"))
                        .where(IOC.status != "malformed").group_by(IOC.ioc_type, IOC.value)
                        .having(func.count(func.distinct(IOC.report_id)) > 1)
                        .order_by(func.count(func.distinct(IOC.report_id)).desc()).limit(10)).all()
    timeline = Counter()
    for (created,) in db.execute(select(Report.created_at)).all():
        if created:
            timeline[created.date().isoformat()] += 1
    latest_scores = db.execute(select(ScoreSnapshot.report_id, ScoreSnapshot.score, ScoreSnapshot.is_final)
                               .order_by(ScoreSnapshot.id)).all()
    last = {}
    for rid, score, final in latest_scores:
        last[rid] = (score, final)
    orgs = db.scalars(select(Organization).order_by(Organization.code)).all()
    anchored = db.scalars(select(Report).where(Report.chain_report_id.is_not(None))).all()
    anchors = anchor_states(anchored)
    anchor_counts = Counter(v for v in anchors.values() if v)
    anomalies = Counter()
    for (anoms,) in db.execute(select(Report.anomalies)).all():
        for a in anoms or []:
            anomalies[a["code"]] += 1
    return {
        "reports_total": sum(by_status.values()),
        "reports_by_status": by_status,
        "validated": by_status.get(ReportStatus.VALIDATED, 0),
        "anchors_on_previous_instance": anchor_counts.get("previous_instance", 0),
        "validated_on_previous_instance": sum(
            1 for r in anchored if r.status == ReportStatus.VALIDATED and anchors.get(r.id) == "previous_instance"),
        "rejected": by_status.get(ReportStatus.REJECTED, 0),
        "pending": by_status.get(ReportStatus.PENDING, 0),
        "disputed": by_status.get(ReportStatus.DISPUTED, 0),
        "reports_by_category": by_category,
        "iocs_total": sum(ioc_by_type.values()),
        "iocs_unique": unique_iocs,
        "iocs_by_type": ioc_by_type,
        "iocs_by_status": ioc_by_status,
        "shared_iocs": [{"type": t, "value": v, "reports": n} for t, v, n in shared],
        "top_mitre": [{"technique_id": t, "name": n, "count": c} for t, n, c in top_mitre],
        "correlations_total": db.scalar(select(func.count()).select_from(Correlation)),
        "transactions_total": db.scalar(select(func.count()).select_from(ChainTransaction)),
        "scores": [{"report_id": k, "score": v[0], "is_final": v[1]} for k, v in last.items()],
        "anomalies_by_code": dict(anomalies),
        "timeline": [{"date": d, "reports": n} for d, n in sorted(timeline.items())],
        "organizations": [{"id": o.id, "code": o.code, "name": o.name, "reputation": o.reputation} for o in orgs],
        "misp_mode": next(iter(db.execute(select(Report.misp_mode).where(Report.misp_mode.is_not(None))
                                          .order_by(Report.misp_synced_at.desc()).limit(1)).scalars()), None),
    }


@router.get("/api/v1/ml/model", summary="Modele ML charge et metriques d'evaluation")
def ml_model(_: Organization = Depends(get_current_org)):
    return get_classifier().info()


@router.get("/api/v1/mitre/info", summary="Catalogue MITRE ATT&CK charge")
def mitre_info(_: Organization = Depends(get_current_org)):
    cat = get_catalog()
    enr = get_enricher()
    return {"source": cat.source, "attack_version": cat.attack_version, "techniques": len(cat),
            "rules": [{"technique_id": r.technique_id, "patterns": list(r.patterns), "base_confidence": r.base_confidence,
                       "rationale": r.rationale} for r, _ in enr.rules],
            "ignored_rules": enr.invalid_rules}


@router.get("/api/v1/mitre/techniques/{technique_id}", summary="Detail d'une technique ATT&CK")
def mitre_technique(technique_id: str, _: Organization = Depends(get_current_org)):
    t = get_catalog().get(technique_id)
    if t is None:
        raise NotFoundError("Technique not found in the ATT&CK catalogue")
    return t


@router.get("/api/v1/iocs", summary="Rechercher des IOC")
def search_iocs(q: str | None = Query(None, max_length=256), ioc_type: str | None = None,
                limit: int = Query(100, ge=1, le=1000), org: Organization = Depends(get_current_org),
                db: Session = Depends(get_db)):
    stmt = select(IOC, Report.title, Report.status, Report.submitter_id, Report.tlp).join(Report)
    if q:
        stmt = stmt.where(IOC.value.ilike(f"%{q.lower()}%"))
    if ioc_type:
        stmt = stmt.where(IOC.ioc_type == ioc_type)
    rows = db.execute(stmt.order_by(IOC.id.desc()).limit(limit)).all()
    return [{"type": i.ioc_type, "value": i.value, "status": i.status, "flags": i.flags or [],
             "confidence": i.confidence, "report_id": i.report_id, "report_title": title, "report_status": st,
             "submitter": sub} for i, title, st, sub, tlp in rows if tlp != "TLP:RED" or sub == org.id]


@router.get("/api/v1/correlations/graph", summary="Graphe des correlations entre rapports")
def correlation_graph(min_score: float = Query(0.0, ge=0, le=1), org: Organization = Depends(get_current_org),
                      db: Session = Depends(get_db)):
    reports = db.scalars(select(Report).where(Report.status != ReportStatus.IMPORTED)).all()
    visible = {r.id: r for r in reports if r.tlp != "TLP:RED" or r.submitter_id == org.id}
    edges = [c for c in db.scalars(select(Correlation).where(Correlation.score >= min_score)).all()
             if c.report_a_id in visible and c.report_b_id in visible]
    return {
        "nodes": [{"id": r.id, "title": r.title, "category": r.category, "status": r.status,
                   "submitter": r.submitter.code} for r in visible.values()],
        "edges": [{"source": c.report_a_id, "target": c.report_b_id, "score": c.score, "strength": c.strength,
                   "components": c.components, "shared_iocs": c.evidence.get("shared_iocs", []),
                   "shared_mitre": c.evidence.get("shared_mitre", []), "reasons": c.evidence.get("reasons", [])}
                  for c in edges],
        "interpretation": "Edges are potential relations supported by evidence, not proof of a common campaign.",
    }


@router.post("/api/v1/correlations/recompute", summary="Recalculer toutes les correlations")
def recompute(request: Request, org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    n = rs.recompute_all_correlations(db)
    audit(db, "correlations.recompute", org_id=org.id, details={"pairs": n}, request=request)
    db.commit()
    return {"correlations": n}


# ------------------------------------------------------------------------------ MISP
@router.get("/api/v1/misp/status", summary="Etat de la connexion MISP (reel ou simule)")
def misp_status(_: Organization = Depends(get_current_org), db: Session = Depends(get_db), reprobe: bool = False):
    if reprobe:
        reset_misp_adapter()
    sync = dict(db.execute(select(Report.misp_sync_status, func.count()).group_by(Report.misp_sync_status)).all())
    try:
        return {"ok": True, **get_misp_adapter().health(), "configured_mode": get_settings().misp_mode,
                "sync_status": sync}
    except MispError as exc:
        return {"ok": False, "configured_mode": get_settings().misp_mode, "error": exc.message, "sync_status": sync}


@router.get("/api/v1/misp/events", summary="Evenements MISP")
def misp_events(limit: int = Query(50, ge=1, le=500), _: Organization = Depends(get_current_org)):
    adapter = get_misp_adapter()
    return {"mode": adapter.mode, "events": adapter.list_events(limit)}


@router.get("/api/v1/misp/events/{event_ref}", summary="Detail d'un evenement MISP")
def misp_event(event_ref: str, _: Organization = Depends(get_current_org)):
    adapter = get_misp_adapter()
    return {"mode": adapter.mode, "event": adapter.get_event(event_ref)}


@router.get("/api/v1/misp/search", summary="Rechercher un IOC dans MISP")
def misp_search(value: str = Query(..., min_length=3, max_length=2048), _: Organization = Depends(get_current_org)):
    adapter = get_misp_adapter()
    return {"mode": adapter.mode, "value": value, "matches": adapter.search_ioc(value)}


# ------------------------------------------------------------------------------ blockchain
@router.get("/api/v1/blockchain/status", summary="Etat du noeud Ethereum et du contrat")
def blockchain_status(_: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    client = get_chain_client()
    info = client.health()
    orgs = []
    for o in db.scalars(select(Organization).order_by(Organization.code)).all():
        entry = {"code": o.code, "name": o.name, "eth_address": o.eth_address, "offchain_reputation": o.reputation}
        if o.eth_address and info.get("contract_deployed"):
            try:
                entry["onchain"] = client.get_organization(o.eth_address)
            except AppError as exc:
                entry["onchain"] = {"error": exc.message}
        orgs.append(entry)
    info["organizations"] = orgs
    return info


@router.get("/api/v1/blockchain/transactions", summary="Historique des transactions Ethereum")
def blockchain_transactions(report_id: str | None = None, limit: int = Query(100, ge=1, le=1000),
                            _: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    stmt = select(ChainTransaction).order_by(ChainTransaction.id.desc()).limit(limit)
    if report_id:
        stmt = stmt.where(ChainTransaction.report_id == report_id)
    orgs = {o.id: o.code for o in db.scalars(select(Organization)).all()}
    return [{"id": t.id, "report_id": t.report_id, "org": orgs.get(t.org_id), "action": t.action,
             "tx_hash": t.tx_hash, "block_number": t.block_number, "gas_used": t.gas_used, "status": t.status,
             "events": t.events, "created_at": t.created_at} for t in db.scalars(stmt).all()]


@router.get("/api/v1/audit", summary="Journal d'audit de l'organisation authentifiee")
def audit_log(limit: int = Query(100, ge=1, le=1000), org: Organization = Depends(get_current_org),
              db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditLog).where(AuditLog.org_id == org.id).order_by(AuditLog.id.desc()).limit(limit)).all()
    return [{"action": a.action, "target": a.target, "outcome": a.outcome, "details": a.details,
             "request_id": a.request_id, "at": a.created_at} for a in rows]
