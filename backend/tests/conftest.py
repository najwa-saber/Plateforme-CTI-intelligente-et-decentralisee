"""Test configuration: isolated SQLite database, simulated MISP, in-memory chain double."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

_TMP = tempfile.mkdtemp(prefix="cti-tests-")
TEST_KEYS = {"A": "test-key-organisation-A-0123456789", "B": "test-key-organisation-B-0123456789",
             "C": "test-key-organisation-C-0123456789"}
os.environ.update({
    "ENVIRONMENT": "test",
    "DATABASE_URL": f"sqlite:///{Path(_TMP, 'test.db').as_posix()}",
    "ORG_A_API_KEY": TEST_KEYS["A"], "ORG_B_API_KEY": TEST_KEYS["B"], "ORG_C_API_KEY": TEST_KEYS["C"],
    "MISP_MODE": "simulated",
    "ETH_DEPLOYMENT_FILE": str(Path(_TMP, "missing-deployment.json")),
    "LOG_LEVEL": "WARNING",
})

from app.core.config import get_settings  # noqa: E402

get_settings.cache_clear()

from app.blockchain.client import set_chain_client  # noqa: E402
from app.database.session import Base, get_engine, init_engine  # noqa: E402
from app.misp.factory import reset_misp_adapter  # noqa: E402
from tests.fakes import FakeChain  # noqa: E402


@pytest.fixture()
def chain() -> FakeChain:
    fake = FakeChain()
    set_chain_client(fake)
    return fake


@pytest.fixture()
def client(chain):
    """Fresh database + FastAPI TestClient for every test."""
    from fastapi.testclient import TestClient

    from app.models import entities  # noqa: F401

    init_engine(os.environ["DATABASE_URL"])
    Base.metadata.drop_all(get_engine())
    Base.metadata.create_all(get_engine())
    reset_misp_adapter()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


def headers(code: str) -> dict:
    return {"X-API-Key": TEST_KEYS[code]}


@pytest.fixture()
def db_session(client):
    from app.database.session import SessionLocal

    with SessionLocal() as s:
        yield s


PHISHING_REPORT = {
    "title": "Credential phishing campaign against finance teams",
    "text": ("Finance employees received phishing emails impersonating the payroll service. The link pointed to "
             "hxxps://payroll-update-portal[.]example/login, a fake login page hosted on 203.0.113.10. "
             "The sender domain payroll-update-portal.example was registered two days before the campaign. "
             "Stolen credentials were posted to the collector and later reused. An HTML attachment with MD5 "
             "5d41402abc4b2a76b9719d911017c592 was also observed in a second wave. Users who clicked the link "
             "entered their corporate password on the cloned portal."),
    "source": "Organisation A SOC",
    "published_at": "2026-10-20T00:00:00Z",
    "tlp": "TLP:GREEN",
}

SECOND_REPORT = {
    "title": "Follow-up: payroll phishing infrastructure reused",
    "text": ("The domain payroll-update-portal.example seen in the earlier payroll phishing wave is now used to "
             "host a fake document sharing page. Victims are lured by emails about a bonus payment and asked to "
             "enter their credentials. New hosting at 203.0.113.11. Analysts recommend blocking the domain."),
    "source": "Organisation B CERT",
    "published_at": "2026-10-25T00:00:00Z",
}
