"""SIMULATED MISP adapter - temporary development fallback (CDC 7.3).

Events are stored in the application database with a MISP-like JSON structure.
Every response carries ``mode = "simulated"`` and the UI displays a warning banner:
data from this adapter must never be presented as coming from a real MISP instance.
"""
from __future__ import annotations

import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.errors import NotFoundError
from app.database.session import SessionLocal
from app.misp.base import IOC_TO_MISP, MispAdapter, MispEventPayload, superseded_tags
from app.models.entities import SimulatedMispEvent

# When the caller binds its own SQLAlchemy session, simulated events are written in the SAME
# transaction as the report (atomicity, and no second writer on SQLite).
_bound_session: ContextVar = ContextVar("misp_simulated_session", default=None)


@contextmanager
def bind_session(db):
    token = _bound_session.set(db)
    try:
        yield
    finally:
        _bound_session.reset(token)


@contextmanager
def _session(write: bool = False):
    bound = _bound_session.get()
    if bound is not None:
        yield bound
        if write:
            bound.flush()
        return
    with SessionLocal() as db:
        yield db
        if write:
            db.commit()


class SimulatedMispAdapter(MispAdapter):
    mode = "simulated"

    def __init__(self, reason: str | None = None) -> None:
        self.reason = reason

    def health(self) -> dict:
        with _session() as db:
            count = db.query(SimulatedMispEvent).count()
        return {"mode": self.mode, "reachable": True, "version": "simulated-adapter", "events": count,
                "warning": "Simulated MISP adapter - development fallback, not a real MISP instance",
                "reason": self.reason}

    def push_report(self, payload: MispEventPayload) -> dict:
        ev_uuid = str(uuid.uuid4())
        attributes = [{"type": "text", "category": "Other", "value": payload.description[:60000],
                       "to_ids": False, "comment": f"CTI report text - source: {payload.source or 'n/a'}"}]
        for ioc in payload.iocs:
            if ioc.get("status") == "malformed" or ioc["type"] not in IOC_TO_MISP:
                continue
            misp_type, category = IOC_TO_MISP[ioc["type"]]
            attributes.append({"type": misp_type, "category": category, "value": ioc["value"], "to_ids": False,
                               "comment": f"status={ioc.get('status')} confidence={ioc.get('confidence')}"})
        event = {
            "uuid": ev_uuid,
            "info": f"[{payload.report_id}] {payload.title}"[:250],
            "date": datetime.now(timezone.utc).date().isoformat(),
            "threat_level_id": payload.threat_level(),
            "analysis": 1,
            "distribution": 1,
            "published": False,
            "org": payload.submitter,
            "tags": payload.all_tags(),
            "attributes": attributes,
        }
        with _session(write=True) as db:
            row = SimulatedMispEvent(uuid=ev_uuid, info=event["info"], payload=event)
            db.add(row)
            db.flush()
            return {"event_id": str(row.id), "event_uuid": ev_uuid, "attribute_count": len(attributes) - 1,
                    "tags": event["tags"]}

    def _find(self, db, event_ref: str) -> SimulatedMispEvent:
        row = None
        if str(event_ref).isdigit():
            row = db.get(SimulatedMispEvent, int(event_ref))
        if row is None:
            row = db.scalar(select(SimulatedMispEvent).where(SimulatedMispEvent.uuid == str(event_ref)))
        if row is None:
            raise NotFoundError("Simulated MISP event not found")
        return row

    def add_tags(self, event_ref: str, tags: list[str]) -> None:
        with _session(write=True) as db:
            row = self._find(db, event_ref)
            payload = dict(row.payload)
            current = payload.get("tags", [])
            stale = set(superseded_tags(current, tags))
            payload["tags"] = list(dict.fromkeys([*(t for t in current if t not in stale), *tags]))
            row.payload = payload

    def search_ioc(self, value: str) -> list[dict]:
        out = []
        with _session() as db:
            for row in db.scalars(select(SimulatedMispEvent)):
                for a in row.payload.get("attributes", []):
                    if a["type"] != "text" and a["value"] == value:
                        out.append({"event_id": str(row.id), "event_uuid": row.uuid, "event_info": row.info,
                                    "type": a["type"], "value": a["value"]})
        return out

    def _summary(self, row: SimulatedMispEvent) -> dict:
        p = row.payload
        return {"id": str(row.id), "uuid": row.uuid, "info": row.info, "date": p.get("date"),
                "threat_level_id": p.get("threat_level_id"), "analysis": p.get("analysis"),
                "published": p.get("published", False),
                "attribute_count": len([a for a in p.get("attributes", []) if a["type"] != "text"]),
                "tags": p.get("tags", []), "org": p.get("org")}

    def list_events(self, limit: int = 50) -> list[dict]:
        with _session() as db:
            rows = db.scalars(select(SimulatedMispEvent).order_by(SimulatedMispEvent.id.desc()).limit(limit)).all()
            return [self._summary(r) for r in rows]

    def get_event(self, event_ref: str) -> dict:
        with _session() as db:
            row = self._find(db, event_ref)
            data = self._summary(row)
            data["attributes"] = row.payload.get("attributes", [])
            return data
