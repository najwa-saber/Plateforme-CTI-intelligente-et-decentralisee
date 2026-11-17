"""Dark / light themes: one visual identity (champagne gold), two complete palettes.

How it works
------------
* Native Streamlit components (tables, inputs, menus, alerts, tabs...) take their colours from
  the ``theme.*`` configuration, which Streamlit sends to the browser at the start of EVERY script
  run. Switching theme = updating these options with ``streamlit.config.set_option`` and
  re-running once: every native component follows, no CSS hack on canvas tables.
* Custom HTML (header, cards, badges, notes), Plotly figures and Graphviz diagrams read the
  tokens of the active theme through :func:`tokens`.
* Persistence: session state (navigation between the 8 pages), ``?theme=`` query parameter
  (reload / shareable link) and a small preference file (container restarts).

Limitation (documented): Streamlit theme options are process-wide, so the theme is a setting of the
running Streamlit server, shared by browser sessions connected to the same server.
"""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

import streamlit as st
from streamlit import config as st_config

THEMES = ("dark", "light")
DEFAULT_THEME = os.environ.get("CTI_DEFAULT_THEME", "dark")
PREF_FILE = Path(os.environ.get("CTI_THEME_FILE", Path.home() / ".cti_platform_theme.json"))

TOKENS: dict[str, dict] = {
    "dark": {
        "bg": "#0b0b0d", "surface": "#17181b", "surface2": "#1f2024", "sidebar": "#111214",
        "border": "#2e3036", "text": "#f2efe8", "muted": "#b9b5ab", "primary": "#d4b47a",
        "primary_strong": "#e6cc96", "on_primary": "#0b0b0d", "link": "#e2c58c",
        "header_bg": "linear-gradient(120deg, #141518 0%, #1d1c19 55%, #2e2719 100%)",
        "header_text": "#f2efe8", "header_sub": "#c9c3b5",
        "note_bg": "rgba(212,180,122,0.09)", "note_border": "#d4b47a", "note_text": "#efe6d2",
        "warn_bg": "rgba(232,162,74,0.12)", "warn_border": "#e8a24a", "warn_text": "#f6dcb5",
        "code_bg": "#1f2024", "grid": "#2a2c31", "shadow": "0 1px 2px rgba(0,0,0,0.5)",
        "status": {"IMPORTED": "#9aa0a8", "ANALYZED": "#b9a1f2", "PENDING": "#7fb0ff", "VALIDATED": "#5cc98f",
                   "REJECTED": "#ef7a6f", "DISPUTED": "#efab55", "INCOMPLETE": "#9aa0a8", "PREVIEW": "#6fcfdd"},
        "category": {"phishing": "#d4b47a", "ransomware": "#e07a6e", "malware": "#8fa6d9", "exploitation": "#6fc2ae"},
        "ioc_status": {"valid": "#5cc98f", "suspicious": "#efab55", "malformed": "#ef7a6f"},
        "severity": {"high": "#ef7a6f", "medium": "#efab55", "low": "#7fb0ff", "info": "#9aa0a8"},
        "org": {"A": "#d4b47a", "B": "#8fa6d9", "C": "#6fc2ae"},
        "neutral_bar": "#3a3c42",
        "gauge_steps": ["rgba(239,122,111,0.22)", "rgba(239,171,85,0.20)", "rgba(92,201,143,0.20)"],
        "heatmap": [[0.0, "#17181b"], [1.0, "#d4b47a"]],
    },
    "light": {
        "bg": "#f6f5f1", "surface": "#ffffff", "surface2": "#efede7", "sidebar": "#efede7",
        "border": "#e0ddd4", "text": "#121212", "muted": "#4b4b50", "primary": "#846629",
        "primary_strong": "#6b521f", "on_primary": "#ffffff", "link": "#765a22",
        "header_bg": "linear-gradient(120deg, #ffffff 0%, #faf6ec 55%, #f1e6cc 100%)",
        "header_text": "#121212", "header_sub": "#4b4b50",
        "note_bg": "#f8f3e7", "note_border": "#846629", "note_text": "#3a2f1a",
        "warn_bg": "#fff3df", "warn_border": "#b26a00", "warn_text": "#5c3a00",
        "code_bg": "#f1efe9", "grid": "#e7e4dc", "shadow": "0 1px 2px rgba(18,18,18,0.06)",
        "status": {"IMPORTED": "#596069", "ANALYZED": "#6a49be", "PENDING": "#2b59b7", "VALIDATED": "#186a41",
                   "REJECTED": "#a83226", "DISPUTED": "#884f00", "INCOMPLETE": "#596069", "PREVIEW": "#0c6775"},
        "category": {"phishing": "#9a7533", "ransomware": "#b94a3e", "malware": "#4d67a6", "exploitation": "#2f8a76"},
        "ioc_status": {"valid": "#186a41", "suspicious": "#884f00", "malformed": "#a83226"},
        "severity": {"high": "#a83226", "medium": "#884f00", "low": "#2b59b7", "info": "#596069"},
        "org": {"A": "#9a7533", "B": "#4d67a6", "C": "#2f8a76"},
        "neutral_bar": "#d9d5cb",
        "gauge_steps": ["rgba(184,55,42,0.14)", "rgba(163,95,0,0.14)", "rgba(29,127,78,0.14)"],
        "heatmap": [[0.0, "#ffffff"], [1.0, "#846629"]],
    },
}


def _streamlit_options(name: str) -> dict:
    t = TOKENS[name]
    return {
        "theme.base": name,
        "theme.primaryColor": t["primary"],
        "theme.backgroundColor": t["bg"],
        "theme.secondaryBackgroundColor": t["surface2"],
        "theme.textColor": t["text"],
        "theme.borderColor": t["border"],
        "theme.linkColor": t["link"],
        "theme.codeBackgroundColor": t["code_bg"],
        "theme.baseRadius": "0.6rem",
        "theme.showWidgetBorder": True,
        "theme.sidebar.backgroundColor": t["sidebar"],
        "theme.sidebar.secondaryBackgroundColor": t["surface"],
        "theme.sidebar.textColor": t["text"],
        "theme.sidebar.borderColor": t["border"],
        "theme.sidebar.primaryColor": t["primary"],
        "theme.sidebar.linkColor": t["link"],
    }


def _read_pref() -> str | None:
    try:
        value = json.loads(PREF_FILE.read_text(encoding="utf-8")).get("theme")
        return value if value in THEMES else None
    except (OSError, ValueError, AttributeError):
        return None


def _write_pref(name: str) -> None:
    try:
        PREF_FILE.write_text(json.dumps({"theme": name}), encoding="utf-8")
    except OSError:  # read-only filesystem: the query parameter still keeps the choice
        pass


def current() -> str:
    if "theme" not in st.session_state:
        qp = str(st.query_params.get("theme", "")).lower()
        st.session_state["theme"] = qp if qp in THEMES else (_read_pref() or DEFAULT_THEME)
    return st.session_state["theme"]


def tokens() -> dict:
    return TOKENS[current()]


def ensure_applied() -> None:
    """Apply the session's theme to the Streamlit configuration; re-run once if it changed."""
    name = current()
    st.query_params["theme"] = name
    wanted = _streamlit_options(name)
    if any(st_config.get_option(k) != v for k, v in wanted.items()):
        for k, v in wanted.items():
            st_config.set_option(k, v)
        _write_pref(name)
        st.rerun()  # the theme is sent to the browser at the start of a run


def _on_select() -> None:
    choice = st.session_state.get("theme_selector")
    if choice in THEMES:
        st.session_state["theme"] = choice


def selector() -> None:
    st.segmented_control(
        "Thème", list(THEMES), default=current(), key="theme_selector", on_change=_on_select,
        format_func=lambda t: "🌙 Sombre" if t == "dark" else "☀️ Clair",
        help="Bascule instantanée ; le choix est conservé entre les pages et après rechargement.",
    )


class Palette(Mapping):
    """Dict-like access to a colour family of the ACTIVE theme (e.g. STATUS_COLORS['VALIDATED'])."""

    def __init__(self, family: str) -> None:
        self.family = family

    def __getitem__(self, key):
        return tokens()[self.family][key]

    def __iter__(self):
        return iter(tokens()[self.family])

    def __len__(self) -> int:
        return len(tokens()[self.family])


def css() -> str:
    t = tokens()
    return f"""
<style>
:root {{
  --cti-bg:{t['bg']}; --cti-surface:{t['surface']}; --cti-surface2:{t['surface2']}; --cti-border:{t['border']};
  --cti-text:{t['text']}; --cti-muted:{t['muted']}; --cti-primary:{t['primary']}; --cti-on-primary:{t['on_primary']};
}}
.block-container {{ padding-top: 1.6rem; max-width: 1400px; }}
h1, h2, h3, h4 {{ color: var(--cti-text); letter-spacing: -0.01em; }}
.cti-header {{ display:flex; align-items:center; justify-content:space-between; gap:1rem; padding:1rem 1.25rem;
  border-radius:14px; margin-bottom:1.1rem; background:{t['header_bg']}; border:1px solid var(--cti-border);
  border-left:4px solid var(--cti-primary); box-shadow:{t['shadow']}; }}
.cti-header h1 {{ color:{t['header_text']}; margin:0; font-size:1.55rem; }}
.cti-header p {{ margin:0.15rem 0 0 0; color:{t['header_sub']}; font-size:0.92rem; }}
.cti-badge {{ display:inline-block; padding:0.1rem 0.55rem; border-radius:999px; font-size:0.78rem; font-weight:600;
  white-space:nowrap; border:1px solid currentColor; }}
.cti-org {{ display:inline-block; padding:0.2rem 0.7rem; border-radius:999px; font-size:0.8rem; font-weight:700;
  background:var(--cti-primary); color:var(--cti-on-primary); white-space:nowrap; }}
.cti-card {{ background:var(--cti-surface); border:1px solid var(--cti-border); border-radius:12px; padding:0.9rem 1rem;
  box-shadow:{t['shadow']}; height:100%; }}
.cti-card .label {{ color:var(--cti-muted); font-size:0.78rem; text-transform:uppercase; letter-spacing:0.05em; }}
.cti-card .value {{ font-size:1.7rem; font-weight:700; color:var(--cti-text); line-height:1.25; }}
.cti-card .sub {{ color:var(--cti-muted); font-size:0.8rem; }}
.cti-card .accent {{ display:block; width:28px; height:3px; border-radius:2px; background:var(--cti-primary); margin-bottom:0.45rem; }}
.cti-note {{ border-left:4px solid {t['note_border']}; background:{t['note_bg']}; color:{t['note_text']};
  padding:0.6rem 0.9rem; border-radius:6px; font-size:0.88rem; margin:0.4rem 0 0.8rem 0; }}
.cti-warn {{ border-left:4px solid {t['warn_border']}; background:{t['warn_bg']}; color:{t['warn_text']};
  padding:0.6rem 0.9rem; border-radius:6px; font-size:0.88rem; margin:0.4rem 0 0.8rem 0; }}
.cti-note a, .cti-warn a {{ color:{t['link']}; }}
.cti-note code, .cti-warn code {{ color:inherit; background:{t['code_bg']}; }}
.cti-hash {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:0.8rem; word-break:break-all;
  background:{t['code_bg']}; color:var(--cti-text); padding:0.25rem 0.45rem; border-radius:6px; border:1px solid var(--cti-border); }}
div[data-testid="stMetricValue"] {{ color: var(--cti-text); }}
/* native alerts: keep the theme tint but guarantee text contrast */
div[data-testid="stAlert"] p, div[data-testid="stAlert"] li {{ color: var(--cti-text) !important; }}
/* primary buttons: dark text on champagne in dark mode, white in light mode */
button[kind="primary"], button[data-testid="stBaseButton-primary"] {{ color: var(--cti-on-primary) !important; }}
button[kind="primary"] p, button[data-testid="stBaseButton-primary"] p {{ color: var(--cti-on-primary) !important; }}
/* segmented control (theme selector): the selected option keeps its gold frame but uses the body text colour
   (native gold-on-gold-tint is below WCAG AA in the light theme) */
button[data-testid^="stBaseButton-segmented_control"] p {{ color: var(--cti-text) !important; }}
.cti-hash {{ display:inline-block; max-width:100%; }}
@media (max-width: 800px) {{ .cti-header {{ flex-direction:column; align-items:flex-start; }}
  .cti-badge {{ white-space:normal; overflow-wrap:anywhere; max-width:100%; }} }}
@media (max-width: 1200px) {{
  [data-testid="stHorizontalBlock"] {{ flex-wrap:wrap; }}
  [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:has(.cti-card) {{ min-width:min(100%, 140px); }}
  [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:not(:has(.cti-card)) {{ min-width:min(100%, 260px); }} }}
</style>
"""
