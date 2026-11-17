"""Idempotent seeding of the three simulated organisations (A, B, C)."""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_api_key
from app.models.entities import Organization

logger = logging.getLogger("cti.seed")


def seed_organizations(db: Session, chain_client=None) -> list[Organization]:
    settings = get_settings()
    orgs = []
    for cfg in settings.organisations():
        org = db.get(Organization, cfg.org_id)
        if not cfg.api_key:
            logger.warning("No API key configured for organisation %s (ORG_%s_API_KEY): it cannot authenticate",
                           cfg.code, cfg.code)
        key_hash = hash_api_key(cfg.api_key) if cfg.api_key else f"disabled-{cfg.code}"
        if org is None:
            org = Organization(id=cfg.org_id, code=cfg.code, name=cfg.name, api_key_hash=key_hash,
                               eth_account_index=cfg.account_index, reputation=50.0)
            db.add(org)
            logger.info("organisation %s created", cfg.org_id)
        else:
            org.name = cfg.name
            org.api_key_hash = key_hash
            org.eth_account_index = cfg.account_index
        if chain_client is not None:
            try:
                org.eth_address = chain_client.address_for(cfg)
                info = chain_client.get_organization(org.eth_address)
                org.onchain_registered = bool(info.get("registered"))
            except Exception as exc:  # chain not ready: retried by /blockchain/status and on demand
                logger.warning("Ethereum account for %s not resolved yet: %s", cfg.code, getattr(exc, "message", exc))
        orgs.append(org)
    db.commit()
    return orgs
