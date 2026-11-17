"""Organisation authentication (API keys) and authorisation helpers.

Each simulated organisation (A, B, C) owns a random API key provided through the
environment (.env, never committed). Only the SHA-256 digest of the key is stored in
the database; comparison is constant-time. The key is sent in the ``X-API-Key`` header.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import Depends, Request
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AuthenticationError, ForbiddenError
from app.database.session import get_db
from app.models.entities import Organization, Report

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Organisation API key")


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    return "cti_" + secrets.token_urlsafe(32)


def get_current_org(request: Request, api_key: str | None = Depends(api_key_header),
                    db: Session = Depends(get_db)) -> Organization:
    if not api_key or len(api_key) < 16 or len(api_key) > 256:
        raise AuthenticationError("Missing or invalid API key (header X-API-Key)")
    digest = hash_api_key(api_key)
    org = db.scalar(select(Organization).where(Organization.api_key_hash == digest))
    if org is None or not hmac.compare_digest(org.api_key_hash, digest):
        raise AuthenticationError("Invalid API key")
    if not org.is_active:
        raise ForbiddenError("Organisation is deactivated")
    request.state.org_id = org.id
    return org


def ensure_can_read(org: Organization, report: Report) -> None:
    """TLP:RED reports are visible to their submitter only (sharing restricted to authorised orgs)."""
    if (report.tlp or "").upper() == "TLP:RED" and report.submitter_id != org.id:
        raise ForbiddenError("TLP:RED report: access restricted to the submitting organisation")


def ensure_owner(org: Organization, report: Report, action: str) -> None:
    if report.submitter_id != org.id:
        raise ForbiddenError(f"Only the submitting organisation can {action} this report")
