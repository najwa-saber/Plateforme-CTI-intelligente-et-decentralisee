"""ORM -> JSON-ready dictionaries (consistent API responses)."""
from __future__ import annotations

from app.models.entities import IOC, Organization, Report, ReportStatus


def org_brief(org: Organization) -> dict:
    return {"id": org.id, "code": org.code, "name": org.name}


def ioc_dict(i: IOC) -> dict:
    return {"type": i.ioc_type, "value": i.value, "raw_value": i.raw_value, "status": i.status, "flags": i.flags or [],
            "provenance": i.provenance, "context": i.context, "occurrences": i.occurrences, "defanged": i.defanged,
            "confidence": i.confidence, "malicious_label": i.malicious_label,
            "known_in_reports": i.known_in_reports or [], "known_in_misp": i.known_in_misp}


def latest_score(report: Report) -> dict | None:
    if not report.scores:
        return None
    s = report.scores[-1]
    return {"score": s.score, "r": s.r, "q": s.q, "v": s.v, "is_final": s.is_final,
            "validation_status": s.validation_status, "computed_at": s.computed_at, "trigger": s.trigger}


def report_summary(report: Report, chain_anchor: str | None = None) -> dict:
    score = latest_score(report)
    return {
        "report_id": report.id, "title": report.title, "status": report.status, "category": report.category,
        "submitter": org_brief(report.submitter), "tlp": report.tlp, "source_type": report.source_type,
        "created_at": report.created_at, "published_at": report.published_at,
        "ioc_count": len([i for i in report.iocs if i.status != "malformed"]),
        "mitre_count": len(report.mitre_matches),
        "score": score["score"] if score else None, "score_final": score["is_final"] if score else None,
        "misp_sync_status": report.misp_sync_status, "misp_mode": report.misp_mode,
        "chain_report_id": report.chain_report_id, "is_synthetic": report.is_synthetic,
        "chain_anchor": chain_anchor,
        "votes": {"approve": sum(v.approve for v in report.votes), "reject": sum(not v.approve for v in report.votes)},
    }


def report_detail(report: Report, chain_anchor: str | None = None) -> dict:
    meta = dict(report.extra_metadata or {})
    meta.pop("declared_iocs", None)
    return {
        **report_summary(report, chain_anchor),
        "text": report.text,
        "source": report.source, "source_url": report.source_url, "language": report.language,
        "original_filename": report.original_filename,
        "declared_category": report.declared_category, "declared_mitre": report.declared_mitre or [],
        "classification": {
            "category": report.category, "probabilities": report.category_probabilities or {},
            **(report.classifier or {}),
        },
        "iocs": [ioc_dict(i) for i in report.iocs],
        "mitre": [
            {"technique_id": m.technique_id, "name": m.name, "tactics": m.tactics, "method": m.method,
             "confidence": m.confidence, "justification": m.justification, "evidence": m.evidence or [],
             "url": m.url} for m in report.mitre_matches
        ],
        "anomalies": report.anomalies or [],
        "quality": report.quality,
        "analysis_metadata": meta,
        "misp": {"mode": report.misp_mode, "event_id": report.misp_event_id, "event_uuid": report.misp_event_uuid,
                 "sync_status": report.misp_sync_status, "error": report.misp_error,
                 "synced_at": report.misp_synced_at},
        "blockchain": {"content_hash": report.content_hash, "canonical_version": report.canonical_version,
                       "chain_report_id": report.chain_report_id, "contract": report.chain_contract,
                       "submitted_at": report.submitted_at, "finalized_at": report.finalized_at},
        "votes_detail": [{"org": org_brief(v.organization), "approve": v.approve, "comment": v.comment,
                          "tx_hash": v.tx_hash, "created_at": v.created_at} for v in report.votes],
        "score_detail": latest_score(report),
        "score_history": [{"score": s.score, "r": s.r, "q": s.q, "v": s.v, "is_final": s.is_final,
                           "trigger": s.trigger, "computed_at": s.computed_at} for s in report.scores],
        "is_final": report.status in ReportStatus.FINAL,
        "analyzed_at": report.analyzed_at, "updated_at": report.updated_at,
    }


def analyze_response(report: Report, extra: dict) -> dict:
    """CDC 8.3 contract (report_id, category, iocs, mitre_techniques, status) + details."""
    detail = report_detail(report)
    return {
        "report_id": report.id,
        "category": report.category,
        "iocs": [{"type": i["type"], "value": i["value"], "status": i["status"]} for i in detail["iocs"]
                 if i["status"] != "malformed"],
        "mitre_techniques": [m["technique_id"] for m in detail["mitre"] if m["method"] != "similarity"],
        "status": report.status,
        "details": detail,
        "duplicates": extra.get("duplicates"),
        "extraction_stats": extra.get("extraction_stats"),
        "correlations": extra.get("correlations", []),
        "score": extra.get("score"),
        "misp": extra.get("misp"),
    }
