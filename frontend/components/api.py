"""Thin REST client used by the Streamlit pages (all business logic lives in FastAPI)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import requests
import streamlit as st

try:  # local runs: read the project .env (Docker passes real environment variables)
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
except ImportError:  # pragma: no cover
    pass

API_URL = os.environ.get("API_URL", "http://127.0.0.1:8000").rstrip("/")
PUBLIC_API_URL = os.environ.get("PUBLIC_API_URL", API_URL).rstrip("/")
MISP_PUBLIC_URL = os.environ.get("MISP_PUBLIC_URL", "https://localhost:8443")
ORGS = {
    code: {"code": code, "name": os.environ.get(f"ORG_{code}_NAME", f"Organisation {code}"),
           "key": os.environ.get(f"ORG_{code}_API_KEY", "")}
    for code in "ABC"
}


@dataclass
class ApiError(Exception):
    status: int
    code: str
    message: str
    details: dict

    def __str__(self) -> str:
        return f"[{self.status}] {self.message}"


def current_org() -> str:
    """Acting organisation: session state, initialised from the ?org= query parameter (survives reloads)."""
    if "org" not in st.session_state:
        qp = str(st.query_params.get("org", "A")).upper()
        st.session_state["org"] = qp if qp in ORGS else "A"
    return st.session_state["org"]


def _headers(org: str | None = None) -> dict:
    key = ORGS[org or current_org()]["key"]
    return {"X-API-Key": key} if key else {}


def _handle(resp: requests.Response):
    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text[:300]}
    if resp.status_code >= 400:
        err = body.get("error", {}) if isinstance(body, dict) else {}
        raise ApiError(resp.status_code, err.get("code", "http_error"), err.get("message", resp.reason),
                       err.get("details", {}))
    return body


def get(path: str, params: dict | None = None, org: str | None = None, timeout: int = 60):
    try:
        return _handle(requests.get(f"{API_URL}{path}", params=params, headers=_headers(org), timeout=timeout))
    except requests.RequestException as exc:
        raise ApiError(0, "unreachable", f"API unreachable ({API_URL})", {"reason": type(exc).__name__}) from exc


def post(path: str, json: dict | None = None, files=None, data=None, params=None, org: str | None = None,
         timeout: int = 180):
    try:
        return _handle(requests.post(f"{API_URL}{path}", json=json, files=files, data=data, params=params,
                                     headers=_headers(org), timeout=timeout))
    except requests.RequestException as exc:
        raise ApiError(0, "unreachable", f"API unreachable ({API_URL})", {"reason": type(exc).__name__}) from exc


@st.cache_data(ttl=5, show_spinner=False)
def cached_get(path: str, org: str, params: tuple = ()):
    return get(path, dict(params) if params else None, org=org)


@st.cache_data(ttl=15, show_spinner=False)
def health() -> dict:
    """Component health (cached 15 s: it probes MISP and Ethereum, too costly for every rerun)."""
    try:
        return requests.get(f"{API_URL}/api/v1/health", timeout=30).json()
    except requests.RequestException:
        return {"status": "unreachable", "components": {}}


def list_reports(limit: int = 500, **filters) -> list[dict]:
    params = tuple(sorted({"limit": limit, **{k: v for k, v in filters.items() if v}}.items()))
    return cached_get("/api/v1/reports", current_org(), params)["items"]


def clear_cache() -> None:
    cached_get.clear()
    health.clear()
