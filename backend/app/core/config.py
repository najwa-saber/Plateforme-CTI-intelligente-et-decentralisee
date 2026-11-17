"""Application configuration (12-factor: everything comes from environment / .env)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_DIR = BACKEND_DIR.parent


class OrgConfig:
    """Static description of a simulated organisation (A, B, C)."""

    def __init__(self, code: str, name: str, api_key: str, account_index: int,
                 private_key: str | None = None, address: str | None = None) -> None:
        self.code = code
        self.name = name
        self.api_key = api_key
        self.account_index = account_index
        self.private_key = private_key or None
        self.address = address or None

    @property
    def org_id(self) -> str:
        return f"org-{self.code.lower()}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(PROJECT_DIR / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- general ---
    app_name: str = "Intelligent Decentralized CTI Platform"
    app_version: str = "1.0.0"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:8501"

    # --- database ---
    database_url: str = "sqlite:///./cti_dev.db"

    # --- uploads ---
    max_upload_mb: float = 5.0
    max_pdf_pages: int = 60
    max_report_chars: int = 200_000

    # --- organisations (simulated A/B/C) ---
    org_a_name: str = "Organisation A"
    org_b_name: str = "Organisation B"
    org_c_name: str = "Organisation C"
    org_a_api_key: str = Field(default="", repr=False)
    org_b_api_key: str = Field(default="", repr=False)
    org_c_api_key: str = Field(default="", repr=False)
    org_a_account_index: int = 1
    org_b_account_index: int = 2
    org_c_account_index: int = 3
    org_a_private_key: str = Field(default="", repr=False)
    org_b_private_key: str = Field(default="", repr=False)
    org_c_private_key: str = Field(default="", repr=False)

    # --- MISP ---
    misp_mode: Literal["real", "simulated", "auto"] = "auto"
    misp_url: str = "https://localhost"
    misp_key: str = Field(default="", repr=False)
    misp_verify_ssl: bool = False
    misp_timeout_s: float = 15.0
    misp_auto_push: bool = True
    misp_distribution: int = 1  # 0 org only, 1 community, 2 connected, 3 all

    # --- Ethereum ---
    eth_rpc_url: str = "http://127.0.0.1:8545"
    eth_deployment_file: str = str(PROJECT_DIR / "blockchain" / "deployments" / "localhost.json")
    eth_tx_timeout_s: float = 60.0
    eth_auto_finalize: bool = True

    # --- ML / MITRE ---
    model_path: str = str(BACKEND_DIR / "app" / "ml" / "artifacts" / "classifier.joblib")
    model_metrics_path: str = str(BACKEND_DIR / "app" / "ml" / "artifacts" / "metrics.json")
    mitre_catalog_path: str = str(BACKEND_DIR / "app" / "mitre" / "data" / "enterprise_techniques.json")
    mitre_similarity_threshold: float = 0.12
    mitre_max_similarity_suggestions: int = 3

    # --- scoring (CDC 10.1: S = 0.30R + 0.30Q + 0.40V) ---
    score_weight_r: float = 0.30
    score_weight_q: float = 0.30
    score_weight_v: float = 0.40

    # --- correlation ---
    corr_weight_ioc: float = 0.45
    corr_weight_mitre: float = 0.20
    corr_weight_text: float = 0.20
    corr_weight_time: float = 0.10
    corr_weight_category: float = 0.05
    corr_threshold: float = 0.30
    corr_time_decay_days: float = 30.0
    near_duplicate_threshold: float = 0.92

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def max_upload_bytes(self) -> int:
        return int(self.max_upload_mb * 1024 * 1024)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def organisations(self) -> list[OrgConfig]:
        return [
            OrgConfig("A", self.org_a_name, self.org_a_api_key, self.org_a_account_index, self.org_a_private_key),
            OrgConfig("B", self.org_b_name, self.org_b_api_key, self.org_b_account_index, self.org_b_private_key),
            OrgConfig("C", self.org_c_name, self.org_c_api_key, self.org_c_account_index, self.org_c_private_key),
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
