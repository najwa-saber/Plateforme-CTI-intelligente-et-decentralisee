"""Automated UI tests (Streamlit AppTest): the 8 pages in both themes, against the running API (read-only GETs).

Skipped when the API is unreachable or the organisation keys are not configured (.env).
Run from the project root:  .venv/Scripts/python -m pytest frontend/tests -q
"""
from __future__ import annotations

import sys
from html import escape as html_escape
from pathlib import Path

import pytest
import requests

FRONT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FRONT))

from components import api  # noqa: E402  (loads the project .env)
from streamlit import config as st_config  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

PAGES = {
    "dashboard.py": "Dashboard général", "import_cti.py": "Importation CTI", "analysis.py": "Analyse des menaces",
    "misp.py": "Gestion MISP", "blockchain.py": "Validation blockchain", "reliability.py": "Fiabilité & réputation",
    "correlation.py": "Corrélation intelligente", "documentation.py": "Documentation",
}


def _api_ready() -> bool:
    try:
        return requests.get(f"{api.API_URL}/health", timeout=3).ok and bool(api.ORGS["A"]["key"])
    except requests.RequestException:
        return False


pytestmark = pytest.mark.skipif(not _api_ready(), reason="API not reachable or ORG_A_API_KEY missing")


def _run(page: str, theme: str, org: str = "A") -> AppTest:
    at = AppTest.from_file(str(FRONT / "views" / page), default_timeout=120)
    at.query_params["theme"] = theme
    at.query_params["org"] = org
    return at.run()


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("page,title", list(PAGES.items()))
def test_page_renders_without_exception(page, title, theme):
    at = _run(page, theme)
    assert not at.exception, [e.value for e in at.exception]
    html = " ".join(m.value for m in at.markdown)
    assert html_escape(title) in html and "Connecté : Organisation A" in html  # header text is HTML-escaped
    assert st_config.get_option("theme.base") == theme          # native theme applied
    assert at.query_params["theme"] == [theme] or at.query_params["theme"] == theme  # persisted in the URL


def test_theme_tokens_switch_custom_css():
    dark = " ".join(m.value for m in _run("dashboard.py", "dark").markdown)
    light = " ".join(m.value for m in _run("dashboard.py", "light").markdown)
    assert "--cti-bg:#0b0b0d" in dark and "--cti-bg:#f6f5f1" in light


def test_organisation_from_url_is_used():
    html = " ".join(m.value for m in _run("dashboard.py", "dark", org="C").markdown)
    assert "Connecté : Organisation C" in html


def test_blockchain_page_shows_anchor_state():
    at = _run("blockchain.py", "dark")
    assert not at.exception
    frames = [df.value for df in at.dataframe]
    submitted = next((f for f in frames if "Ancrage" in f.columns), None)
    if submitted is None:
        pytest.skip("no report submitted on-chain in this environment")
    assert set(submitted["Ancrage"]) <= {"✔ chaîne actuelle", "⚠ instance précédente (non vérifiable)", "? nœud injoignable"}
