"""Journal of sensitive operations (NF04 traceability), stored in the application database."""
from __future__ import annotations

import logging

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.entities import AuditLog

logger = logging.getLogger("cti.audit")


def audit(db: Session, action: str, *, org_id: str | None = None, target: str | None = None,
          outcome: str = "success", details: dict | None = None, request: Request | None = None) -> None:
    entry = AuditLog(
        org_id=org_id, action=action, target=target, outcome=outcome, details=details or {},
        client_ip=(request.client.host if request and request.client else None),
        request_id=getattr(request.state, "request_id", None) if request else None,
    )
    db.add(entry)
    logger.info("audit action=%s org=%s target=%s outcome=%s", action, org_id, target, outcome)
