"""/api/v1/organizations - organisations A/B/C and their dynamic reputation."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.blockchain.client import get_chain_client
from app.core.errors import AppError, NotFoundError
from app.core.security import get_current_org
from app.database.session import get_db
from app.models.entities import Organization, Report, ReportStatus, ReputationEvent, Vote
from app.services import reputation as rep

router = APIRouter(prefix="/api/v1/organizations", tags=["organizations"])


def _org_stats(db: Session, org: Organization) -> dict:
    submitted = dict(db.execute(select(Report.status, func.count()).where(Report.submitter_id == org.id)
                                .group_by(Report.status)).all())
    votes = db.scalar(select(func.count()).select_from(Vote).where(Vote.org_id == org.id))
    return {"reports_by_status": submitted, "reports_total": sum(submitted.values()), "votes_cast": votes,
            "validated": submitted.get(ReportStatus.VALIDATED, 0), "rejected": submitted.get(ReportStatus.REJECTED, 0)}


def _onchain(org: Organization) -> dict | None:
    if not org.eth_address:
        return None
    try:
        return get_chain_client().get_organization(org.eth_address)
    except AppError as exc:
        return {"error": exc.message}


@router.get("", summary="Lister les organisations")
def list_organizations(org: Organization = Depends(get_current_org), db: Session = Depends(get_db)):
    out = []
    for o in db.scalars(select(Organization).order_by(Organization.code)).all():
        out.append({"id": o.id, "code": o.code, "name": o.name, "eth_address": o.eth_address,
                    "reputation": o.reputation, "is_active": o.is_active, "onchain": _onchain(o),
                    "stats": _org_stats(db, o), "is_me": o.id == org.id})
    return out


@router.get("/me", summary="Organisation authentifiee")
def me(org: Organization = Depends(get_current_org)):
    return {"id": org.id, "code": org.code, "name": org.name, "eth_address": org.eth_address,
            "reputation": org.reputation}


@router.get("/{org_id}/reputation", summary="Reputation dynamique et historique explique")
def reputation(org_id: str, limit: int = Query(200, ge=1, le=1000), _: Organization = Depends(get_current_org),
               db: Session = Depends(get_db)):
    target = db.get(Organization, org_id) or db.scalar(select(Organization).where(Organization.code == org_id.upper()))
    if target is None:
        raise NotFoundError("Organisation not found")
    events = db.scalars(select(ReputationEvent).where(ReputationEvent.org_id == target.id)
                        .order_by(ReputationEvent.id.desc()).limit(limit)).all()
    return {
        "organization": {"id": target.id, "code": target.code, "name": target.name, "eth_address": target.eth_address},
        "reputation": target.reputation,
        "onchain": _onchain(target),
        "policy": {"neutral": rep.NEUTRAL, "floor": rep.FLOOR, "cap": rep.CAP, "per_event_cap": rep.PER_EVENT_CAP,
                   "daily_cap": rep.DAILY_CAP, "min_damping": rep.MIN_DAMPING,
                   "description": rep.__doc__.strip()},
        "stats": _org_stats(db, target),
        "history": [{"id": e.id, "report_id": e.report_id, "old": e.old_value, "new": e.new_value,
                     "raw_delta": e.raw_delta, "applied_delta": e.applied_delta, "reason": e.reason,
                     "explanation": e.explanation, "details": e.details, "onchain_value": e.onchain_value,
                     "at": e.created_at} for e in events],
    }
