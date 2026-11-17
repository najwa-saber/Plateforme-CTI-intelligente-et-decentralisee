"""Corrélation: graph of potential relations, shared IOCs / techniques, configurable score."""
import pandas as pd
import streamlit as st

from components import api, charts, ui

ui.setup("Corrélation intelligente", "Relations potentielles entre rapports : IOC, techniques ATT&CK, texte, temps, catégorie")

ui.note("Une corrélation est une <b>relation potentielle</b> appuyée par des éléments vérifiables ; elle ne prouve "
        "pas que deux rapports décrivent la même campagne.")

min_score = st.slider("Score minimal affiché dans le graphe", 0.0, 1.0, 0.3, 0.05)
try:
    graph = api.get("/api/v1/correlations/graph", params={"min_score": min_score})
except api.ApiError as exc:
    ui.show_error(exc)
    st.stop()

c1, c2 = st.columns([2, 1])
with c1:
    if graph["edges"]:
        st.plotly_chart(charts.correlation_graph(graph["nodes"], graph["edges"], st.session_state.get("selected_report")),
                        use_container_width=True)
    else:
        st.info("Aucune corrélation au-dessus du seuil.")
with c2:
    st.metric("Rapports reliés", len({e["source"] for e in graph["edges"]} | {e["target"] for e in graph["edges"]}))
    st.metric("Relations", len(graph["edges"]))
    if st.button("Recalculer toutes les corrélations"):
        try:
            n = api.post("/api/v1/correlations/recompute")["correlations"]
            st.success(f"{n} relation(s) au-dessus du seuil par défaut")
        except api.ApiError as exc:
            ui.show_error(exc)
    st.caption("Taille des arêtes ∝ score · couleur des nœuds = catégorie · contour = statut de validation")

if graph["edges"]:
    st.dataframe(pd.DataFrame([{"Rapport 1": e["source"], "Rapport 2": e["target"], "Score": e["score"],
                                "Force": e["strength"],
                                "IOC communs": ", ".join(f"{i['type']}:{i['value']}" for i in e["shared_iocs"]),
                                "ATT&CK communs": ", ".join(e["shared_mitre"]), "Justification": "; ".join(e["reasons"])}
                               for e in sorted(graph["edges"], key=lambda e: -e["score"])]),
                 hide_index=True, use_container_width=True,
                 column_config={"Score": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.2f")})

st.subheader("Rapports liés à un rapport — pondérations configurables")
rid = ui.report_picker(key="corr_pick")
if rid:
    with st.expander("Pondérations (normalisées automatiquement) et seuil", expanded=False):
        w1, w2, w3, w4, w5, w6 = st.columns(6)
        w_ioc = w1.number_input("IOC", 0.0, 1.0, 0.45, 0.05)
        w_mitre = w2.number_input("MITRE", 0.0, 1.0, 0.20, 0.05)
        w_text = w3.number_input("Texte TF-IDF", 0.0, 1.0, 0.20, 0.05)
        w_time = w4.number_input("Temps", 0.0, 1.0, 0.10, 0.05)
        w_cat = w5.number_input("Catégorie", 0.0, 1.0, 0.05, 0.05)
        thr = w6.number_input("Seuil", 0.0, 1.0, 0.30, 0.05)
        custom = st.checkbox("Recalculer avec ces paramètres")
    params = {"min_score": thr}
    if custom:
        params.update({"w_ioc": w_ioc, "w_mitre": w_mitre, "w_text": w_text, "w_time": w_time, "w_category": w_cat})
    try:
        corr = api.get(f"/api/v1/reports/{rid}/correlations", params=params)
    except api.ApiError as exc:
        ui.show_error(exc)
        st.stop()
    st.caption(f"Poids effectifs : {corr['weights']} · seuil {corr['threshold']}")
    if not corr["correlations"]:
        st.info("Aucun rapport lié au-dessus du seuil.")
    for c in corr["correlations"]:
        ev = c["evidence"]
        with st.expander(f"{c['report_id']} — score {c['score']:.2f} ({c['strength']})", expanded=True):
            comp = c["components"]
            cols = st.columns(5)
            for col, (k, label) in zip(cols, [("ioc", "IOC"), ("mitre", "ATT&CK"), ("text", "Texte"),
                                              ("time", "Proximité temporelle"), ("category", "Catégorie")]):
                col.metric(label, f"{comp[k]:.2f}")
            if ev["shared_iocs"]:
                st.markdown("**IOC communs** : " + ", ".join(f"`{i['type']}:{i['value']}`" for i in ev["shared_iocs"]))
            if ev["shared_mitre"]:
                st.markdown("**Techniques communes** : " + ", ".join(ev["shared_mitre"]))
            st.caption(" · ".join(ev["reasons"]) + f" — {ev['interpretation']}")
