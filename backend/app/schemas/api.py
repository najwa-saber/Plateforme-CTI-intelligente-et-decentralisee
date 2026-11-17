"""Pydantic schemas (request validation + OpenAPI documentation)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Category = Literal["phishing", "ransomware", "malware", "exploitation"]
TLP = Literal["TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
IOCType = Literal["ipv4", "domain", "url", "md5", "sha256"]


class DeclaredIOC(BaseModel):
    type: IOCType
    value: str = Field(min_length=1, max_length=2048)
    context: str | None = Field(default=None, max_length=1000)


class ReportCreate(BaseModel):
    """Manual entry / structured JSON import of a CTI report."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"example": {
        "title": "Phishing campaign", "text": "A phishing campaign used attack.example to harvest credentials...",
        "source": "Organisation A SOC", "tlp": "TLP:GREEN"}})

    title: str = Field(min_length=3, max_length=300)
    text: str = Field(min_length=20, max_length=200_000)
    source: str | None = Field(default=None, max_length=255)
    source_url: str | None = Field(default=None, max_length=1024)
    published_at: datetime | None = None
    language: str = Field(default="en", min_length=2, max_length=8)
    tlp: TLP = "TLP:GREEN"
    category: Category | None = Field(default=None, description="Declared category (optional, compared to ML)")
    mitre_techniques: list[str] = Field(default_factory=list, max_length=100)
    iocs: list[DeclaredIOC] = Field(default_factory=list, max_length=5000)
    is_synthetic: bool = False

    @field_validator("source_url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        if v and not v.lower().startswith(("http://", "https://")):
            raise ValueError("source_url must be an http(s) URL")
        return v

    @field_validator("mitre_techniques")
    @classmethod
    def _mitre(cls, v: list[str]) -> list[str]:
        import re

        for t in v:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", t.strip().upper()):
                raise ValueError(f"invalid ATT&CK technique id: {t}")
        return [t.strip().upper() for t in v]


class AnalyzeRequest(BaseModel):
    """CDC 8.2: POST /api/v1/reports/analyze  {title, text} -> import + full analysis."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"example": {
        "title": "Phishing campaign", "text": "A phishing campaign used attack.example to steal credentials..."}})

    title: str = Field(min_length=3, max_length=300)
    text: str = Field(min_length=20, max_length=200_000)
    source: str | None = Field(default=None, max_length=255)
    source_url: str | None = Field(default=None, max_length=1024)
    published_at: datetime | None = None
    tlp: TLP = "TLP:GREEN"
    persist: bool = Field(default=True, description="false = preview only, nothing is stored")


class VoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra={"example": {"approve": True,
                                                                            "comment": "IOCs confirmed in our telemetry"}})
    approve: bool
    comment: str | None = Field(default=None, max_length=1000)


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    type: str
    value: str
    raw_value: str | None = None
    status: str
    flags: list[str] | None = None
    provenance: str | None = None
    context: str | None = None
    occurrences: int | None = None
    defanged: bool | None = None
    confidence: float | None = None
    known_in_reports: list[str] | None = None
    known_in_misp: bool | None = None


class AnalyzeResponse(BaseModel):
    """CDC 8.3 response, extended with explainability details."""

    model_config = ConfigDict(extra="allow")
    report_id: str | None
    category: str | None
    iocs: list[dict]
    mitre_techniques: list[str]
    status: str


class ReportSummary(BaseModel):
    model_config = ConfigDict(extra="allow")
    report_id: str
    title: str
    status: str
    category: str | None
    submitter: dict
    created_at: datetime | None
    ioc_count: int
    score: float | None


class Paginated(BaseModel):
    model_config = ConfigDict(extra="allow")
    total: int
    limit: int
    offset: int
    items: list[dict]


class OrganizationOut(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    code: str
    name: str
    eth_address: str | None
    reputation: float
