"""Gestion MISP: connection mode, events, attributes, tags, synchronisation status."""
import pandas as pd
import streamlit as st

from components import api, ui

ui.setup("Gestion MISP", "Référentiel CTI : événements, attributs, tags et synchronisation (PyMISP)")

try:
    status = api.get("/api/v1/misp/status")
except api.ApiError as exc:
    ui.show_error(exc)
    st.stop()

mode = status.get("mode") or status.get("configured_mode")
c1, c2, c3, c4 = st.columns(4)
c1.markdown(ui.card("Mode", "MISP réel" if mode == "real" else "Simulé", f"configuré : {status.get('configured_mode')}"),
            unsafe_allow_html=True)
c2.markdown(ui.card("Connexion", "OK" if status.get("ok") else "KO", status.get("url") or status.get("error") or ""),
            unsafe_allow_html=True)
c3.markdown(ui.card("Version", status.get("version", "-"), "instance MISP"), unsafe_allow_html=True)
sync = status.get("sync_status", {})
c4.markdown(ui.card("Rapports synchronisés", sync.get("SYNCED", 0),
                    f"{sync.get('FAILED', 0)} échec(s) · {sync.get('NOT_SYNCED', 0)} non synchronisé(s)"),
            unsafe_allow_html=True)
if mode == "simulated":
    ui.note("⚠️ <b>Données issues de l'adaptateur MISP simulé</b> (solution temporaire de développement). "
            f"Raison : {status.get('reason') or '-'}. Démarrez MISP avec <code>docker compose --profile misp up -d</code>.",
            warn=True)
else:
    ui.note(f"Données lues en direct sur l'instance MISP réelle via PyMISP. Interface web : "
            f"<a href='{api.MISP_PUBLIC_URL}' target='_blank'>{api.MISP_PUBLIC_URL}</a> (certificat auto-signé de laboratoire).")
if st.button("Re-tester la connexion MISP"):
    api.get("/api/v1/misp/status", params={"reprobe": "true"})
    api.clear_cache()
    st.rerun()

tab_events, tab_search, tab_sync = st.tabs(["📚 Événements", "🔎 Recherche d'IOC", "🔄 Synchronisation"])

with tab_events:
    try:
        events = api.get("/api/v1/misp/events", params={"limit": 100})
    except api.ApiError as exc:
        ui.show_error(exc)
        events = {"events": []}
    evs = events.get("events", [])
    if not evs:
        st.info("Aucun événement.")
    else:
        st.dataframe(pd.DataFrame([{"ID": e["id"], "Info": e["info"], "Date": e["date"], "Attributs": e["attribute_count"],
                                    "Niveau menace": e["threat_level_id"], "Publié": e["published"],
                                    "Tags": ", ".join(e["tags"][:6])} for e in evs]),
                     hide_index=True, use_container_width=True)
        ev_id = st.selectbox("Détail de l'événement", [e["id"] for e in evs],
                             format_func=lambda i: next(f"#{e['id']} {e['info']}" for e in evs if e["id"] == i))
        if ev_id:
            try:
                ev = api.get(f"/api/v1/misp/events/{ev_id}")["event"]
                st.markdown("**Tags**: " + " ".join(ui.badge(t) for t in ev["tags"]), unsafe_allow_html=True)
                attrs = [a for a in ev["attributes"] if a["type"] != "text"]
                st.dataframe(pd.DataFrame([{"Type": a["type"], "Catégorie": a["category"], "Valeur": a["value"],
                                            "to_ids": a["to_ids"], "Commentaire": a.get("comment")} for a in attrs]),
                             hide_index=True, use_container_width=True)
                text = next((a["value"] for a in ev["attributes"] if a["type"] == "text"), None)
                if text:
                    with st.expander("Description (attribut text)"):
                        st.write(text)
            except api.ApiError as exc:
                ui.show_error(exc)
        ui.note("Les attributs sont créés avec <code>to_ids=false</code> : l'extraction n'est pas une preuve de "
                "malveillance. Le statut de validation collaborative est ajouté en tag après finalisation.")

with tab_search:
    value = st.text_input("Valeur d'IOC à rechercher dans MISP", placeholder="ex. secure-hr-portal.example")
    if value and len(value) >= 3:
        try:
            res = api.get("/api/v1/misp/search", params={"value": value})
            if res["matches"]:
                st.dataframe(pd.DataFrame(res["matches"]), hide_index=True, use_container_width=True)
            else:
                st.info("Aucune correspondance.")
        except api.ApiError as exc:
            ui.show_error(exc)

with tab_sync:
    try:
        reports = api.list_reports()
    except api.ApiError as exc:
        ui.show_error(exc)
        reports = []
    if reports:
        st.dataframe(pd.DataFrame([{"Rapport": r["report_id"], "Titre": r["title"], "Org": r["submitter"]["code"],
                                    "Synchronisation": r["misp_sync_status"], "Mode": r["misp_mode"] or "-"}
                                   for r in reports]), hide_index=True, use_container_width=True)
        mine = [r["report_id"] for r in reports if r["submitter"]["code"] == api.current_org()
                and r["misp_sync_status"] != "SYNCED" and r["status"] != "IMPORTED"]
        if mine:
            target = st.selectbox("(Re)synchroniser un de mes rapports", mine)
            if st.button("Synchroniser vers MISP"):
                try:
                    res = api.post(f"/api/v1/reports/{target}/misp")
                    api.clear_cache()
                    st.success(f"{res.get('status')} — événement {res.get('event_id')}") if res.get("status") == "SYNCED" \
                        else st.error(res.get("error"))
                except api.ApiError as exc:
                    ui.show_error(exc)
