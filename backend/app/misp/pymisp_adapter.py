"""Adapter for a REAL MISP instance through PyMISP (MISP REST API, API-key authentication)."""
from __future__ import annotations

import logging
import warnings

from app.core.config import Settings
from app.core.errors import MispError, NotFoundError
from app.misp.base import IOC_TO_MISP, MispAdapter, MispEventPayload, superseded_tags

logger = logging.getLogger("cti.misp")


def _summarise_event(ev) -> dict:
    tags = [t.name for t in getattr(ev, "tags", [])]
    attrs = getattr(ev, "attributes", [])
    return {
        "id": str(ev.id), "uuid": str(ev.uuid), "info": ev.info, "date": str(getattr(ev, "date", "")),
        "threat_level_id": getattr(ev, "threat_level_id", None), "analysis": getattr(ev, "analysis", None),
        "published": bool(getattr(ev, "published", False)),
        "attribute_count": len(attrs) or int(getattr(ev, "attribute_count", 0) or 0),
        "tags": tags,
        "org": getattr(getattr(ev, "Orgc", None), "name", None),
    }


class PyMispAdapter(MispAdapter):
    mode = "real"

    def __init__(self, settings: Settings) -> None:
        if not settings.misp_key:
            raise MispError("MISP_KEY is not configured")
        self.settings = settings
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from pymisp import PyMISP
            from pymisp.exceptions import PyMISPError

            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")  # self-signed certificate warnings in the lab
                    self._client = PyMISP(self.settings.misp_url, self.settings.misp_key,
                                          ssl=self.settings.misp_verify_ssl, timeout=self.settings.misp_timeout_s)
            except (PyMISPError, OSError, ValueError) as exc:
                raise MispError("Unable to connect to MISP", {"reason": type(exc).__name__}) from exc
        return self._client

    @staticmethod
    def _check(resp, action: str):
        if isinstance(resp, dict) and resp.get("errors"):
            errors = resp["errors"]
            if isinstance(errors, (tuple, list)) and errors and errors[0] == 404:
                raise NotFoundError(f"MISP object not found ({action})")  # unknown event: 404, not 503
            raise MispError(f"MISP refused {action}", {"misp_errors": str(errors)[:300]})
        return resp

    def health(self) -> dict:
        try:
            version = self.client.misp_instance_version
            if isinstance(version, dict) and version.get("errors"):
                raise MispError("MISP authentication failed")
            return {"mode": self.mode, "reachable": True, "url": self.settings.misp_url,
                    "version": version.get("version") if isinstance(version, dict) else str(version)}
        except (MispError, NotFoundError):
            raise
        except Exception as exc:
            raise MispError("MISP is unreachable", {"reason": type(exc).__name__}) from exc

    def push_report(self, payload: MispEventPayload) -> dict:
        from pymisp import MISPEvent

        ev = MISPEvent()
        ev.info = f"[{payload.report_id}] {payload.title}"[:250]
        ev.distribution = self.settings.misp_distribution
        ev.threat_level_id = payload.threat_level()
        ev.analysis = 1  # ongoing: collaborative validation not finished yet
        for tag in payload.all_tags():
            ev.add_tag(tag)
        ev.add_attribute("text", payload.description[:60000], category="Other", to_ids=False,
                         comment=f"CTI report text - source: {payload.source or 'n/a'}")
        count = 0
        for ioc in payload.iocs:
            if ioc.get("status") == "malformed" or ioc["type"] not in IOC_TO_MISP:
                continue
            misp_type, category = IOC_TO_MISP[ioc["type"]]
            comment = f"status={ioc.get('status')} confidence={ioc.get('confidence')} flags={','.join(ioc.get('flags') or [])}"
            # to_ids stays False: extraction is not proof of maliciousness (set after validation if desired)
            ev.add_attribute(misp_type, ioc["value"], category=category, to_ids=False, comment=comment[:250])
            count += 1
        try:
            created = self._check(self.client.add_event(ev, pythonify=True), "event creation")
        except (MispError, NotFoundError):
            raise
        except Exception as exc:
            raise MispError("MISP event creation failed", {"reason": type(exc).__name__}) from exc
        return {"event_id": str(created.id), "event_uuid": str(created.uuid), "attribute_count": count,
                "tags": payload.all_tags()}

    def add_tags(self, event_ref: str, tags: list[str]) -> None:
        try:
            ev = self.client.get_event(event_ref, pythonify=True)
            self._check(ev, "event lookup")
            for old in superseded_tags([t.name for t in ev.tags], tags):
                self._check(self.client.untag(ev.uuid, old), "untagging")
            for tag in tags:
                self._check(self.client.tag(ev.uuid, tag), "tagging")
        except (MispError, NotFoundError):
            raise
        except Exception as exc:
            raise MispError("MISP tagging failed", {"reason": type(exc).__name__}) from exc

    def search_ioc(self, value: str) -> list[dict]:
        try:
            attrs = self._check(self.client.search(controller="attributes", value=value, pythonify=True,
                                                   limit=50), "search")
        except (MispError, NotFoundError):
            raise
        except Exception as exc:
            raise MispError("MISP search failed", {"reason": type(exc).__name__}) from exc
        out = []
        for a in attrs or []:
            ev = getattr(a, "Event", None)
            out.append({"event_id": str(a.event_id), "event_uuid": str(getattr(ev, "uuid", "")) if ev else None,
                        "event_info": getattr(ev, "info", None) if ev else None, "type": a.type, "value": a.value})
        return out

    def list_events(self, limit: int = 50) -> list[dict]:
        try:
            events = self._check(self.client.search(controller="events", limit=limit, page=1, pythonify=True,
                                                    metadata=False), "event listing")
        except (MispError, NotFoundError):
            raise
        except Exception as exc:
            raise MispError("MISP event listing failed", {"reason": type(exc).__name__}) from exc
        return [_summarise_event(e) for e in events or []]

    def get_event(self, event_ref: str) -> dict:
        try:
            ev = self._check(self.client.get_event(event_ref, pythonify=True), "event lookup")
        except (MispError, NotFoundError):
            raise
        except Exception as exc:
            raise MispError("MISP event lookup failed", {"reason": type(exc).__name__}) from exc
        data = _summarise_event(ev)
        data["attributes"] = [
            {"type": a.type, "category": a.category, "value": a.value, "to_ids": a.to_ids, "comment": a.comment}
            for a in ev.attributes
        ]
        return data
