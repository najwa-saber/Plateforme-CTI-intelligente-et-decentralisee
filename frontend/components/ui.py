"""Shared UI elements: theme, sidebar (organisation selector), badges, cards, report picker."""
from __future__ import annotations

import html

import streamlit as st

from components import api, theme

# Colour families resolve against the ACTIVE theme at access time (see components/theme.py)
STATUS_COLORS = theme.Palette("status")
CATEGORY_COLORS = theme.Palette("category")
IOC_STATUS_COLORS = theme.Palette("ioc_status")
SEVERITY_COLORS = theme.Palette("severity")
CATEGORY_LABELS = {"phishing": "Phishing", "ransomware": "Ransomware", "malware": "Malware",
                   "exploitation": "Exploitation de vulnérabilités"}


def setup(title: str, subtitle: str) -> None:
    theme.ensure_applied()
    st.markdown(theme.css(), unsafe_allow_html=True)
    sidebar()
    org = api.ORGS[api.current_org()]
    st.markdown(
        f"<div class='cti-header'><div><h1>{html.escape(title)}</h1><p>{html.escape(subtitle)}</p></div>"
        f"<div><span class='cti-org'>Connecté : {html.escape(org['name'])}</span></div></div>",
        unsafe_allow_html=True)


def sidebar() -> None:
    with st.sidebar:
        st.markdown("### 🛡️ CTI Platform")
        st.caption("Plateforme CTI intelligente et décentralisée")
        theme.selector()
        codes = list(api.ORGS)
        current = api.current_org()
        choice = st.radio("Agir en tant que", codes, index=codes.index(current), horizontal=True,
                          format_func=lambda c: f"Org {c}", key="org_radio",
                          help="Simulation de trois organisations indépendantes : chaque choix utilise la clé API "
                               "et le compte Ethereum de l'organisation.")
        if choice != current:
            st.session_state["org"] = choice
            st.query_params["org"] = choice
            api.clear_cache()
            st.rerun()
        st.query_params["org"] = api.current_org()
        if not api.ORGS[choice]["key"]:
            st.error(f"Clé API de l'organisation {choice} absente (ORG_{choice}_API_KEY).")
        h = api.health()
        comps = h.get("components", {})
        st.markdown("**État des services**")
        for name, label in (("database", "PostgreSQL"), ("ml", "Modèle ML"), ("mitre", "MITRE ATT&CK"),
                            ("misp", "MISP"), ("ethereum", "Ethereum")):
            c = comps.get(name, {})
            ok = c.get("ok")
            extra = ""
            if name == "misp" and c:
                extra = f" · {'RÉEL' if c.get('mode') == 'real' else 'SIMULÉ'}"
            st.markdown(f"{'🟢' if ok else '🔴'} {label}{extra}")
        if comps.get("misp", {}).get("mode") == "simulated":
            st.warning("MISP simulé : adaptateur de développement, pas une instance MISP réelle.")
        if comps.get("ethereum", {}).get("warning"):
            st.warning(comps["ethereum"]["warning"])
        if h.get("status") == "unreachable":
            st.error(f"API injoignable ({api.API_URL})")
        if st.button("↻ Rafraîchir les données", use_container_width=True):
            api.clear_cache()
            st.rerun()
        st.caption(f"API : {api.PUBLIC_API_URL} · [Swagger]({api.PUBLIC_API_URL}/docs)")


def badge(text: str, color: str | None = None) -> str:
    """Outlined badge: coloured text on a tint of the same colour (readable in both themes)."""
    color = color or STATUS_COLORS.get(text) or theme.tokens()["muted"]
    return (f"<span class='cti-badge' style='color:{color};background:{color}1f'>"
            # ':' escaped: Streamlit markdown would read "tlp:green" as a colour directive
            f"{html.escape(str(text)).replace(':', '&#58;')}</span>")


def status_badge(status: str) -> str:
    return badge(status, STATUS_COLORS.get(status))


def card(label: str, value, sub: str = "") -> str:
    return (f"<div class='cti-card'><span class='accent'></span><div class='label'>{html.escape(label)}</div>"
            f"<div class='value'>{html.escape(str(value))}</div><div class='sub'>{html.escape(sub)}</div></div>")


def cards(items: list[tuple[str, object, str]]) -> None:
    cols = st.columns(len(items))
    for col, (label, value, sub) in zip(cols, items):
        col.markdown(card(label, value, sub), unsafe_allow_html=True)


def note(text: str, warn: bool = False) -> None:
    st.markdown(f"<div class='{'cti-warn' if warn else 'cti-note'}'>{text}</div>", unsafe_allow_html=True)


def show_error(exc: Exception) -> None:
    if isinstance(exc, api.ApiError):
        st.error(f"{exc.message} (HTTP {exc.status}, {exc.code})")
        if exc.details:
            with st.expander("Détails de l'erreur"):
                st.json(exc.details)
    else:
        st.error(str(exc))


def report_picker(label: str = "Rapport", key: str = "report_pick", statuses: list[str] | None = None,
                  default: str | None = None) -> str | None:
    try:
        reports = api.list_reports()
    except api.ApiError as exc:
        show_error(exc)
        return None
    if statuses:
        reports = [r for r in reports if r["status"] in statuses]
    if not reports:
        st.info("Aucun rapport disponible pour cette vue.")
        return None
    ids = [r["report_id"] for r in reports]
    labels = {r["report_id"]: f"{r['report_id']} · {r['title'][:70]} · {r['status']} · Org {r['submitter']['code']}"
              for r in reports}
    pre = default or st.session_state.get("selected_report") or st.query_params.get("report")
    index = ids.index(pre) if pre in ids else 0
    choice = st.selectbox(label, ids, index=index, format_func=lambda i: labels[i], key=key)
    st.session_state["selected_report"] = choice
    st.query_params["report"] = choice  # deep link: the URL identifies the report shown
    return choice
