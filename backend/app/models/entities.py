"""ORM models (off-chain application data, PostgreSQL)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ReportStatus:
    IMPORTED = "IMPORTED"
    ANALYZED = "ANALYZED"
    PENDING = "PENDING"  # submitted on-chain, votes in progress
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    DISPUTED = "DISPUTED"
    INCOMPLETE = "INCOMPLETE"

    FINAL = {VALIDATED, REJECTED, DISPUTED, INCOMPLETE}
    ALL = [IMPORTED, ANALYZED, PENDING, VALIDATED, REJECTED, DISPUTED, INCOMPLETE]


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # org-a
    code: Mapped[str] = mapped_column(String(4), unique=True, index=True)  # A
    name: Mapped[str] = mapped_column(String(120))
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    eth_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    eth_account_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reputation: Mapped[float] = mapped_column(Float, default=50.0)
    onchain_registered: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        # An on-chain record is identified by (chain instance, on-chain id): ids restart at 1 when the in-memory
        # Hardhat network restarts. Partial index -> historical rows recorded before migration 0002 (NULL instance)
        # are left untouched.
        Index("uq_reports_chain_anchor", "chain_instance", "chain_report_id", unique=True,
              postgresql_where=text("chain_instance IS NOT NULL AND chain_report_id IS NOT NULL"),
              sqlite_where=text("chain_instance IS NOT NULL AND chain_report_id IS NOT NULL")),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # CTI-XXXXXXXXXX
    title: Mapped[str] = mapped_column(String(300))
    text: Mapped[str] = mapped_column(Text)
    text_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    # provenance / metadata
    submitter_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    source_type: Mapped[str] = mapped_column(String(16))  # txt | pdf | json | manual | misp
    original_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    language: Mapped[str] = mapped_column(String(8), default="en")
    tlp: Mapped[str] = mapped_column(String(16), default="TLP:GREEN")
    declared_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    declared_mitre: Mapped[list | None] = mapped_column(JSON, nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    extra_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # analysis
    status: Mapped[str] = mapped_column(String(16), default=ReportStatus.IMPORTED, index=True)
    category: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    category_probabilities: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    classifier: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    anomalies: Mapped[list | None] = mapped_column(JSON, nullable=True)
    quality: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # MISP
    misp_mode: Mapped[str | None] = mapped_column(String(16), nullable=True)  # real | simulated
    misp_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    misp_event_uuid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    misp_sync_status: Mapped[str] = mapped_column(String(16), default="NOT_SYNCED")
    misp_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    misp_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Integrity / Ethereum
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    canonical_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    chain_report_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    chain_contract: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # hash of the contract deployment block: identifies the chain instance the report is anchored on
    chain_instance: Mapped[str | None] = mapped_column(String(66), nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    submitter: Mapped[Organization] = relationship(lazy="joined")
    iocs: Mapped[list["IOC"]] = relationship(back_populates="report", cascade="all, delete-orphan",
                                             order_by="IOC.id")
    mitre_matches: Mapped[list["MitreMatch"]] = relationship(back_populates="report",
                                                             cascade="all, delete-orphan",
                                                             order_by="MitreMatch.id")
    votes: Mapped[list["Vote"]] = relationship(back_populates="report", cascade="all, delete-orphan",
                                               order_by="Vote.id")
    scores: Mapped[list["ScoreSnapshot"]] = relationship(back_populates="report", cascade="all, delete-orphan",
                                                         order_by="ScoreSnapshot.id")


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("report_id", "ioc_type", "value", name="uq_ioc_report_type_value"),
        Index("ix_ioc_type_value", "ioc_type", "value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id", ondelete="CASCADE"), index=True)
    ioc_type: Mapped[str] = mapped_column(String(16))  # ipv4 | domain | url | md5 | sha256
    value: Mapped[str] = mapped_column(String(2048))  # normalised value
    raw_value: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(16))  # valid | suspicious | malformed
    flags: Mapped[list | None] = mapped_column(JSON, nullable=True)
    provenance: Mapped[str] = mapped_column(String(32), default="extracted")  # extracted | declared | misp
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    defanged: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    malicious_label: Mapped[str] = mapped_column(String(16), default="unknown")  # malicious|benign|unknown
    known_in_reports: Mapped[list | None] = mapped_column(JSON, nullable=True)
    known_in_misp: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    report: Mapped[Report] = relationship(back_populates="iocs")


class MitreMatch(Base):
    __tablename__ = "mitre_matches"
    __table_args__ = (UniqueConstraint("report_id", "technique_id", name="uq_mitre_report_technique"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(String(16), index=True)
    name: Mapped[str] = mapped_column(String(200))
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    method: Mapped[str] = mapped_column(String(16))  # rule | similarity | declared
    confidence: Mapped[float] = mapped_column(Float)
    justification: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list | None] = mapped_column(JSON, nullable=True)
    url: Mapped[str | None] = mapped_column(String(255), nullable=True)

    report: Mapped[Report] = relationship(back_populates="mitre_matches")


class Vote(Base):
    __tablename__ = "votes"
    __table_args__ = (UniqueConstraint("report_id", "org_id", name="uq_vote_report_org"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    approve: Mapped[bool] = mapped_column(Boolean)
    comment: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    report: Mapped[Report] = relationship(back_populates="votes")
    organization: Mapped[Organization] = relationship(lazy="joined")


class ChainTransaction(Base):
    __tablename__ = "chain_transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str | None] = mapped_column(ForeignKey("reports.id", ondelete="SET NULL"), nullable=True,
                                                  index=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(32))  # register | submit | vote | finalize
    tx_hash: Mapped[str] = mapped_column(String(66))
    chain_instance: Mapped[str | None] = mapped_column(String(66), nullable=True, index=True)
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gas_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16))  # success | failed
    events: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ScoreSnapshot(Base):
    __tablename__ = "score_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id", ondelete="CASCADE"), index=True)
    score: Mapped[float] = mapped_column(Float)
    r: Mapped[float] = mapped_column(Float)
    q: Mapped[float] = mapped_column(Float)
    v: Mapped[float] = mapped_column(Float)
    is_final: Mapped[bool] = mapped_column(Boolean, default=False)
    validation_status: Mapped[str] = mapped_column(String(16))
    details: Mapped[dict] = mapped_column(JSON)
    trigger: Mapped[str] = mapped_column(String(32))
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    report: Mapped[Report] = relationship(back_populates="scores")


class ReputationEvent(Base):
    __tablename__ = "reputation_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    report_id: Mapped[str | None] = mapped_column(ForeignKey("reports.id", ondelete="SET NULL"), nullable=True)
    old_value: Mapped[float] = mapped_column(Float)
    new_value: Mapped[float] = mapped_column(Float)
    raw_delta: Mapped[float] = mapped_column(Float)
    applied_delta: Mapped[float] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(String(64))
    explanation: Mapped[str] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    onchain_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Correlation(Base):
    __tablename__ = "correlations"
    __table_args__ = (UniqueConstraint("report_a_id", "report_b_id", name="uq_correlation_pair"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_a_id: Mapped[str] = mapped_column(ForeignKey("reports.id", ondelete="CASCADE"), index=True)
    report_b_id: Mapped[str] = mapped_column(ForeignKey("reports.id", ondelete="CASCADE"), index=True)
    score: Mapped[float] = mapped_column(Float)
    components: Mapped[dict] = mapped_column(JSON)
    evidence: Mapped[dict] = mapped_column(JSON)
    strength: Mapped[str] = mapped_column(String(16))
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SimulatedMispEvent(Base):
    """Storage of the *simulated* MISP adapter (development fallback only)."""

    __tablename__ = "misp_simulated_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(64), unique=True)
    info: Mapped[str] = mapped_column(String(500))
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
