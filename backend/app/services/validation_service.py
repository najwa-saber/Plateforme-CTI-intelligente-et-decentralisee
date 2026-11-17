"""Collaborative validation workflow on Ethereum: submit -> vote -> finalize, integrity checks."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.blockchain.client import get_chain_client
from app.core.canonical import CANONICAL_VERSION, canonical_payload, sha256_hex
from app.core.config import OrgConfig, get_settings
from app.core.errors import BlockchainError, ConflictError, ContractRevertError, ForbiddenError
from app.models.entities import ChainTransaction, Organization, Report, ReportStatus, Vote
from app.services.report_service import tag_misp_event
from app.services.reputation import apply_finalization
from app.services.scoring import compute_score

logger = logging.getLogger("cti.validation")


def org_config(org: Organization) -> OrgConfig:
    for cfg in get_settings().organisations():
        if cfg.org_id == org.id:
            return cfg
    raise ForbiddenError("Organisation has no blockchain identity configured")


def canonical_hash(report: Report) -> tuple[str, dict]:
    payload = canonical_payload(
        report_id=report.id, title=report.title, text=report.text, source=report.source,
        published_at=report.published_at.date().isoformat() if report.published_at else None,
        tlp=report.tlp, submitter_code=report.submitter.code,
        iocs=[(i.ioc_type, i.value) for i in report.iocs if i.status != "malformed"],
    )
    return sha256_hex(payload), payload


class ChainAnchorMismatch(ConflictError):
    """The report's on-chain anchor does not exist on the running chain (local network was reset)."""

    code = "chain_anchor_mismatch"


def anchored_view(client, report: Report) -> dict:
    """Read the on-chain record of a report AFTER checking that it really is this report's anchor.

    Guards against the in-memory Hardhat network being restarted: the contract is redeployed at the
    same address and on-chain ids restart at 1, so ``chain_report_id`` alone could point to another
    report. Checks: same chain instance (when known), record exists, externalId == report id.
    A differing fingerprint with the same externalId is NOT treated here: it is an integrity failure.
    """
    current = client.instance_id() if hasattr(client, "instance_id") else None
    details = {"report_id": report.id, "chain_report_id": report.chain_report_id,
               "anchored_instance": report.chain_instance, "current_instance": current}
    if report.chain_instance and current and report.chain_instance != current:
        raise ChainAnchorMismatch("Report anchored on a previous instance of the local Ethereum network "
                                  "(Hardhat was restarted): its on-chain record no longer exists", details)
    try:
        chain = client.get_report(report.chain_report_id)
    except ContractRevertError as exc:
        raise ChainAnchorMismatch("On-chain record not found on the running network (chain reset?)", details) from exc
    if chain.get("external_id") not in (None, report.id):
        raise ChainAnchorMismatch("On-chain id now belongs to another report: the local network was reset",
                                  {**details, "onchain_external_id": chain.get("external_id")})
    submitter = getattr(report.submitter, "eth_address", None)
    if submitter and chain.get("submitter") and chain["submitter"].lower() != submitter.lower():
        raise ChainAnchorMismatch("On-chain record was submitted by another account than the report's organisation",
                                  {**details, "onchain_submitter": chain["submitter"]})
    return chain


ANCHOR_CURRENT, ANCHOR_PREVIOUS, ANCHOR_UNKNOWN = "current", "previous_instance", "unknown"


def anchor_states(reports: list[Report]) -> dict[str, str | None]:
    """Anchor state of each report (read-only): None = never submitted, 'current' = record present on the
    running chain, 'previous_instance' = anchored on a chain instance that no longer exists (Hardhat restarted),
    'unknown' = Ethereum node unreachable. One instance lookup; legacy rows without chain_instance are checked
    individually against the contract (externalId)."""
    out: dict[str, str | None] = {r.id: None for r in reports}
    anchored = [r for r in reports if r.chain_report_id is not None]
    if not anchored:
        return out
    client = get_chain_client()
    try:
        current = client.instance_id() if hasattr(client, "instance_id") else None
    except BlockchainError:
        return {**out, **{r.id: ANCHOR_UNKNOWN for r in anchored}}
    for r in anchored:
        if r.chain_instance and current:
            out[r.id] = ANCHOR_CURRENT if r.chain_instance == current else ANCHOR_PREVIOUS
            continue
        try:
            anchored_view(client, r)
            out[r.id] = ANCHOR_CURRENT
        except ChainAnchorMismatch:
            out[r.id] = ANCHOR_PREVIOUS
        except BlockchainError:
            out[r.id] = ANCHOR_UNKNOWN
    return out


def _record_tx(db: Session, report: Report | None, org: Organization | None, action: str, tx) -> ChainTransaction:
    client = get_chain_client()
    try:
        instance = client.instance_id() if hasattr(client, "instance_id") else None
    except BlockchainError:
        instance = None
    row = ChainTransaction(report_id=report.id if report else None, org_id=org.id if org else None, action=action,
                           tx_hash=tx.tx_hash, block_number=tx.block_number, gas_used=tx.gas_used,
                           status=tx.status, events=tx.events, chain_instance=instance)
    db.add(row)
    return row


def _org_by_address(db: Session, address: str) -> Organization | None:
    return db.scalar(select(Organization).where(Organization.eth_address.ilike(address)))


def _ensure_identity(db: Session, org: Organization) -> None:
    if org.eth_address:
        return
    client = get_chain_client()
    org.eth_address = client.address_for(org_config(org))
    db.flush()


def submit(db: Session, org: Organization, report: Report) -> dict:
    if report.submitter_id != org.id:
        raise ForbiddenError("Only the submitting organisation can submit this report for validation")
    if report.status == ReportStatus.IMPORTED:
        raise ConflictError("Report must be analysed before submission (POST /reports/{id}/analyze)")
    if report.status != ReportStatus.ANALYZED or report.chain_report_id is not None:
        raise ConflictError("Report already submitted on-chain", {"status": report.status,
                                                                 "chain_report_id": report.chain_report_id})
    if (report.tlp or "").upper() == "TLP:RED":
        raise ConflictError("TLP:RED reports cannot be shared for collaborative validation")
    _ensure_identity(db, org)
    digest, payload = canonical_hash(report)
    client = get_chain_client()
    instance_before = client.instance_id() if hasattr(client, "instance_id") else None
    chain_id, tx = client.submit_report(org_config(org), digest, report.id)
    instance_after = client.instance_id() if hasattr(client, "instance_id") else None
    if instance_before != instance_after:
        raise BlockchainError("The Ethereum network was restarted during submission; resubmit the report",
                              {"before": instance_before, "after": instance_after})
    report.content_hash = digest
    report.canonical_version = CANONICAL_VERSION
    report.chain_report_id = chain_id
    report.chain_contract = client.contract.address if getattr(client, "contract", None) is not None else None
    report.chain_instance = instance_after
    report.submitted_at = datetime.now(timezone.utc)
    report.status = ReportStatus.PENDING
    _record_tx(db, report, org, "submit", tx)
    misp_warning = tag_misp_event(report, [f'cti-platform:sha256="{digest}"', 'cti-platform:status="PENDING"',
                                           f'cti-platform:chain-report-id="{chain_id}"'], db)
    score = compute_score(db, report, trigger="submission")
    db.commit()
    return {"report_id": report.id, "chain_report_id": chain_id, "content_hash": digest,
            "canonical_version": CANONICAL_VERSION, "canonical_payload_keys": sorted(payload),
            "transaction": tx.to_dict(), "status": report.status, "score": score, "misp_warning": misp_warning}


def vote(db: Session, org: Organization, report: Report, approve: bool, comment: str | None) -> dict:
    if report.status != ReportStatus.PENDING or report.chain_report_id is None:
        raise ConflictError("Report is not open for voting", {"status": report.status})
    if report.submitter_id == org.id:
        raise ForbiddenError("Self-validation is forbidden: the submitter cannot vote on its own report")
    if db.scalar(select(Vote).where(Vote.report_id == report.id, Vote.org_id == org.id)):
        raise ConflictError("This organisation has already voted on this report")
    _ensure_identity(db, org)
    client = get_chain_client()
    anchored_view(client, report)
    tx = client.vote(org_config(org), report.chain_report_id, approve)
    db.add(Vote(report_id=report.id, org_id=org.id, approve=approve, comment=(comment or None), tx_hash=tx.tx_hash))
    _record_tx(db, report, org, "vote", tx)
    db.flush()
    db.refresh(report)
    result = {"report_id": report.id, "vote": "APPROVE" if approve else "REJECT", "transaction": tx.to_dict(),
              "finalized": False}
    can, outcome = client.preview_finalization(report.chain_report_id)
    result["finalization_preview"] = {"can_finalize": can, "outcome": outcome}
    if can and get_settings().eth_auto_finalize:
        result["finalization"] = finalize(db, org, report, commit=False)
        result["finalized"] = True
    else:
        compute_score(db, report, trigger="vote")
    db.commit()
    result["status"] = report.status
    return result


def finalize(db: Session, org: Organization, report: Report, commit: bool = True) -> dict:
    if report.chain_report_id is None:
        raise ConflictError("Report was never submitted on-chain")
    if report.status != ReportStatus.PENDING:
        raise ConflictError("Report already finalised", {"status": report.status})
    _ensure_identity(db, org)
    client = get_chain_client()
    anchored_view(client, report)
    tx = client.finalize(org_config(org), report.chain_report_id)
    _record_tx(db, report, org, "finalize", tx)
    out = _apply_final_state(db, report, client)
    out["transaction"] = tx.to_dict()
    if commit:
        db.commit()
    return out


def _apply_final_state(db: Session, report: Report, client) -> dict:
    chain = client.get_report(report.chain_report_id)
    report.status = chain["status"]
    report.finalized_at = datetime.now(timezone.utc)
    eligible_addrs = client.get_eligible_validators(report.chain_report_id) \
        if hasattr(client, "get_eligible_validators") else []
    eligible_ids = []
    onchain_rep: dict[str, float] = {}
    for org in db.scalars(select(Organization)).all():
        if org.eth_address:
            try:
                onchain_rep[org.id] = client.get_reputation(org.eth_address)
            except BlockchainError:
                pass
            if any(a.lower() == org.eth_address.lower() for a in eligible_addrs):
                eligible_ids.append(org.id)
    if not eligible_ids:  # fallback: all organisations except the submitter
        eligible_ids = [o.id for o in db.scalars(select(Organization)).all() if o.id != report.submitter_id]
    db.flush()
    db.refresh(report)
    rep_events = apply_finalization(db, report, eligible_ids, onchain_rep)
    misp_warning = tag_misp_event(report, [f'cti-platform:status="{report.status}"'], db)
    score = compute_score(db, report, trigger="finalization", chain_view=chain)
    return {"report_id": report.id, "status": report.status, "chain": chain, "score": score,
            "reputation_events": [{"org_id": e.org_id, "old": e.old_value, "new": e.new_value,
                                   "delta": e.applied_delta, "explanation": e.explanation} for e in rep_events],
            "misp_warning": misp_warning}


def sync_from_chain(db: Session, report: Report) -> dict | None:
    """Reconcile the off-chain status with the contract (e.g. finalised directly on-chain)."""
    if report.chain_report_id is None:
        return None
    client = get_chain_client()
    chain = anchored_view(client, report)
    if report.status == ReportStatus.PENDING and chain["status"] in ReportStatus.FINAL:
        _apply_final_state(db, report, client)
        db.commit()
    return chain


def verify_integrity(db: Session, report: Report) -> dict:
    digest, _ = canonical_hash(report)
    out = {"report_id": report.id, "canonical_version": report.canonical_version or CANONICAL_VERSION,
           "recomputed_hash": digest, "stored_hash": report.content_hash,
           "offchain_match": report.content_hash == digest if report.content_hash else None,
           "onchain_hash": None, "onchain_match": None}
    out["anchor_status"] = "not_anchored" if report.chain_report_id is None else "ok"
    if report.chain_report_id is not None:
        client = get_chain_client()
        try:
            chain = anchored_view(client, report)
        except ChainAnchorMismatch as exc:
            out.update(anchor_status="anchor_lost", verified=None, anchor_details=exc.details,
                       message="On-chain verification impossible: " + exc.message + ". Off-chain check: the "
                               "recomputed hash " + ("matches" if out["offchain_match"] else "DOES NOT match")
                               + " the fingerprint recorded at submission.")
            return out
        out["onchain_hash"] = chain["content_hash"].removeprefix("0x")
        out["onchain_match"] = client.verify_integrity(report.chain_report_id, digest)
    out["verified"] = bool(out["onchain_match"]) if report.chain_report_id is not None else None
    out["message"] = (
        "Report not yet anchored on Ethereum" if report.chain_report_id is None else
        "Integrity verified: the off-chain report matches the on-chain fingerprint" if out["verified"] else
        "INTEGRITY FAILURE: the off-chain report differs from the fingerprint stored on Ethereum"
    )
    return out
