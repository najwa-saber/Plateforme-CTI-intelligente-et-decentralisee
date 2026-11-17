"""/api/v1/reports - import, analysis, MISP, Ethereum validation, integrity, score, correlations."""
from __future__ import annotations



from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.blockchain.client import get_chain_client
from app.core.config import get_settings
from app.core.errors import AppError, BadRequestError, PayloadTooLargeError
from app.core.security import ensure_can_read, ensure_owner, get_current_org
from app.database.session import get_db
from app.misp.factory import get_misp_adapter
from app.misp.base import MISP_TO_IOC
from app.models.entities import Organization, Report
from app.nlp.document_parser import parse_upload
from app.schemas.api import AnalyzeRequest, AnalyzeResponse, Paginated, ReportCreate, VoteRequest
from app.services import report_service as rs
from app.services import validation_service as vs
from app.services.audit import audit
from app.services.scoring import compute_score
from app.services.serializers import analyze_response, report_detail, report_summary

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def _load(db: Session, report_id: str, org: Organization) -> Report:
    report = rs.get_report(db, report_id)
    ensure_can_read(org, report)
    return report


def _audited(db: Session, request: Request, org: Organization, action: str, target: str | None, fn):
    try:
        result = fn()
    except AppError as exc:
        db.rollback()
        audit(db, action, org_id=org.id, target=target, outcome="denied" if exc.status_code < 500 else "error",
              details={"code": exc.code, "message": exc.message}, request=request)
        db.commit()
        raise
    audit(db, action, org_id=org.id, target=target, request=request)
    db.commit()
    return result


# ------------------------------------------------------------------------------ import
@router.post("", status_code=status.HTTP_201_CREATED, summary="Importer un rapport (saisie manuelle / JSON)")
def import_report(body: ReportCreate, request: Request, analyze: bool = Query(True),
                  org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    def run():
        report = rs.create_report(
            db, org, title=body.title, text=body.text, source_type="manual" if not body.iocs else "json",
            source=body.source, source_url=body.source_url, published_at=body.published_at, language=body.language,
            tlp=body.tlp, declared_category=body.category, declared_mitre=body.mitre_techniques,
            declared_iocs=[i.model_dump() for i in body.iocs], is_synthetic=body.is_synthetic)
        if analyze:
            res = rs.analyze_report(db, report)
            return analyze_response(res["report"], res)
        db.commit()
        return report_detail(report)

    return _audited(db, request, org, "report.import", None, run)


@router.post("/upload", status_code=status.HTTP_201_CREATED, summary="Importer un fichier TXT, PDF ou JSON")
async def upload_report(request: Request, file: UploadFile = File(...), tlp: str = Form("TLP:GREEN"),
                        source: str | None = Form(None), analyze: bool = Form(True),
                        org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    settings = get_settings()
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise PayloadTooLargeError(f"File exceeds {settings.max_upload_mb} MB")
    tlp = tlp.upper()
    if tlp not in {"TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}:
        raise BadRequestError("Invalid TLP value")

    def run():
        doc = parse_upload(file.filename, data)
        meta = doc.metadata
        report = rs.create_report(
            db, org, title=doc.title, text=doc.text, source_type=doc.source_type, filename=doc.filename,
            source=(source or meta.get("source")), source_url=meta.get("source_url"),
            published_at=meta.get("published_at"), language=meta.get("language", "en"),
            tlp=meta.get("tlp", tlp), declared_category=meta.get("category"),
            declared_mitre=meta.get("mitre_techniques") or [], declared_iocs=doc.declared_iocs,
            is_synthetic=str(meta.get("source", "")).lower() == "synthetic",
            extra={"file_metadata": {k: v for k, v in meta.items() if k not in ("mitre_techniques",)}})
        if analyze:
            res = rs.analyze_report(db, report)
            return analyze_response(res["report"], res)
        db.commit()
        return report_detail(report)

    return _audited(db, request, org, "report.upload", file.filename, run)


@router.post("/analyze", response_model=AnalyzeResponse, status_code=status.HTTP_201_CREATED,
             summary="Analyser un rapport (import + pipeline complet, ou apercu si persist=false)")
def analyze_new(body: AnalyzeRequest, request: Request, org: Organization = Depends(get_current_org),
                db: Session = Depends(get_db)):
    if not body.persist:
        preview = rs.preview_analysis(body.title, body.text)
        return {"report_id": None, "category": preview["classification"]["category"],
                "iocs": [{"type": i["ioc_type"], "value": i["value"], "status": i["status"]}
                         for i in preview["iocs"] if i["status"] != "malformed"],
                "mitre_techniques": [m["technique_id"] for m in preview["mitre_techniques"] if m["method"] != "similarity"],
                "status": "PREVIEW", "details": preview}

    def run():
        report = rs.create_report(db, org, title=body.title, text=body.text, source_type="manual", source=body.source,
                                  source_url=body.source_url, published_at=body.published_at, tlp=body.tlp)
        res = rs.analyze_report(db, report)
        return analyze_response(res["report"], res)

    return _audited(db, request, org, "report.analyze", None, run)


@router.post("/import-misp/{event_ref}", status_code=status.HTTP_201_CREATED,
             summary="Importer un evenement MISP existant comme rapport CTI")
def import_from_misp(event_ref: str, request: Request, org: Organization = Depends(get_current_org),
                     db: Session = Depends(get_db)):
    def run():
        adapter = get_misp_adapter()
        ev = adapter.get_event(event_ref)
        texts = [a["value"] for a in ev.get("attributes", []) if a.get("type") in ("text", "comment")]
        declared = [{"type": MISP_TO_IOC[a["type"]], "value": a["value"], "context": f"MISP attribute {a['type']}"}
                    for a in ev.get("attributes", []) if a.get("type") in MISP_TO_IOC]
        body = "\n\n".join(texts) or ev.get("info", "")
        if len(body) < 20:
            body = f"{ev.get('info', '')}. MISP event {ev.get('uuid')} with {len(declared)} indicator(s)."
        report = rs.create_report(db, org, title=ev.get("info", "MISP event")[:300], text=body, source_type="misp",
                                  source=f"MISP ({adapter.mode}) event {ev.get('id')}", declared_iocs=declared,
                                  extra={"misp_origin": {"id": ev.get("id"), "uuid": ev.get("uuid"),
                                                         "mode": adapter.mode}})
        res = rs.analyze_report(db, report, push_misp=False)
        return analyze_response(res["report"], res)

    return _audited(db, request, org, "report.import_misp", event_ref, run)


# ------------------------------------------------------------------------------ read
@router.get("", response_model=Paginated, summary="Lister les rapports")
def list_reports(status_: str | None = Query(None, alias="status"), category: str | None = None,
                 submitter: str | None = None, q: str | None = Query(None, max_length=200),
                 limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                 org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    stmt = select(Report).where(or_(Report.tlp != "TLP:RED", Report.submitter_id == org.id))
    if status_:
        stmt = stmt.where(Report.status == status_.upper())
    if category:
        stmt = stmt.where(Report.category == category)
    if submitter:
        stmt = stmt.where(Report.submitter_id == submitter)
    if q:
        stmt = stmt.where(or_(Report.title.ilike(f"%{q}%"), Report.id.ilike(f"%{q}%")))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Report.created_at.desc()).limit(limit).offset(offset).options(
        selectinload(Report.iocs), selectinload(Report.mitre_matches), selectinload(Report.votes),
        selectinload(Report.scores))).all()
    anchors = vs.anchor_states(rows)
    return {"total": total, "limit": limit, "offset": offset,
            "items": [report_summary(r, anchors.get(r.id)) for r in rows]}


@router.get("/{report_id}", summary="Consulter un rapport")
def get_report(report_id: str, org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    report = _load(db, report_id, org)
    return report_detail(report, vs.anchor_states([report]).get(report.id))


@router.post("/{report_id}/analyze", summary="(Re)lancer l'analyse d'un rapport importe")
def reanalyze(report_id: str, request: Request, org: Organization = Depends(get_current_org),
              db: Session = Depends(get_db)):
    def run():
        report = _load(db, report_id, org)
        ensure_owner(org, report, "analyse")
        res = rs.analyze_report(db, report)
        return analyze_response(res["report"], res)

    return _audited(db, request, org, "report.reanalyze", report_id, run)


@router.post("/{report_id}/misp", summary="Synchroniser (ou re-synchroniser) le rapport dans MISP")
def sync_misp(report_id: str, request: Request, force: bool = False, org: Organization = Depends(get_current_org),
              db: Session = Depends(get_db)):
    def run():
        report = _load(db, report_id, org)
        ensure_owner(org, report, "synchronise")
        return rs.push_to_misp(db, report, force=force)

    return _audited(db, request, org, "report.misp_sync", report_id, run)


# ------------------------------------------------------------------------------ blockchain
@router.post("/{report_id}/submit", summary="Soumettre l'empreinte SHA-256 sur Ethereum")
def submit_report(report_id: str, request: Request, org: Organization = Depends(get_current_org),
                  db: Session = Depends(get_db)):
    return _audited(db, request, org, "report.submit", report_id,
                    lambda: vs.submit(db, org, _load(db, report_id, org)))


@router.post("/{report_id}/vote", summary="Enregistrer un vote (organisation validatrice)")
def vote_report(report_id: str, body: VoteRequest, request: Request, org: Organization = Depends(get_current_org),
                db: Session = Depends(get_db)):
    return _audited(db, request, org, "report.vote", report_id,
                    lambda: vs.vote(db, org, _load(db, report_id, org), body.approve, body.comment))


@router.post("/{report_id}/finalize", summary="Finaliser le statut (regle de majorite du smart contract)")
def finalize_report(report_id: str, request: Request, org: Organization = Depends(get_current_org),
                    db: Session = Depends(get_db)):
    return _audited(db, request, org, "report.finalize", report_id,
                    lambda: vs.finalize(db, org, _load(db, report_id, org)))


@router.get("/{report_id}/status", summary="Statut off-chain et on-chain")
def report_status(report_id: str, org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    report = _load(db, report_id, org)
    chain = None
    chain_error = None
    preview = None
    if report.chain_report_id is not None:
        try:
            chain = vs.sync_from_chain(db, report)
            can, outcome = get_chain_client().preview_finalization(report.chain_report_id)
            preview = {"can_finalize": can, "outcome": outcome}
        except AppError as exc:
            chain_error = exc.message
    votes = [{"org": v.organization.code, "approve": v.approve, "tx_hash": v.tx_hash, "at": v.created_at}
             for v in report.votes]
    eligible = [o.code for o in db.scalars(select(Organization)).all() if o.id != report.submitter_id]
    return {"report_id": report.id, "status": report.status, "chain": chain, "chain_error": chain_error,
            "finalization_preview": preview, "votes": votes, "eligible_validators": eligible,
            "can_vote": report.status == "PENDING" and org.id != report.submitter_id
            and all(v.org_id != org.id for v in report.votes)}


@router.get("/{report_id}/integrity", summary="Verifier l'integrite (hash recalcule vs empreinte on-chain)")
def report_integrity(report_id: str, org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    return vs.verify_integrity(db, _load(db, report_id, org))


@router.get("/{report_id}/chain-events", summary="Historique des evenements Solidity du rapport")
def chain_events(report_id: str, org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    report = _load(db, report_id, org)
    if report.chain_report_id is None:
        return {"report_id": report.id, "events": []}
    client = get_chain_client()
    try:
        vs.anchored_view(client, report)
    except vs.ChainAnchorMismatch as exc:
        return {"report_id": report.id, "chain_report_id": report.chain_report_id, "events": [],
                "warning": exc.message, "details": exc.details}
    return {"report_id": report.id, "chain_report_id": report.chain_report_id,
            "events": client.report_events(report.chain_report_id)}


# ------------------------------------------------------------------------------ score / correlation
@router.get("/{report_id}/score", summary="Score de fiabilite explicable (S = 0.30R + 0.30Q + 0.40V)")
def report_score(report_id: str, org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    report = _load(db, report_id, org)
    current = compute_score(db, report, trigger="consultation", persist=False)
    history = [{"score": s.score, "r": s.r, "q": s.q, "v": s.v, "is_final": s.is_final, "trigger": s.trigger,
                "validation_status": s.validation_status, "computed_at": s.computed_at} for s in report.scores]
    return {"report_id": report.id, **current, "history": history}


@router.get("/{report_id}/correlations", summary="Correlations potentielles avec d'autres rapports")
def report_correlations(report_id: str, min_score: float | None = Query(None, ge=0, le=1),
                        w_ioc: float | None = Query(None, ge=0), w_mitre: float | None = Query(None, ge=0),
                        w_text: float | None = Query(None, ge=0), w_time: float | None = Query(None, ge=0),
                        w_category: float | None = Query(None, ge=0),
                        org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    report = _load(db, report_id, org)
    weights = {"ioc": w_ioc, "mitre": w_mitre, "text": w_text, "time": w_time, "category": w_category}
    try:
        return rs.correlations_for(db, report, min_score=min_score, weights=weights)
    except ValueError as exc:
        raise BadRequestError(str(exc)) from exc


