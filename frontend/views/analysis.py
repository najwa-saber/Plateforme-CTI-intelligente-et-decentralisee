"""Analyse des menaces: ML classification, probabilities, IOCs, anomalies, ATT&CK techniques and justifications."""
import pandas as pd
import streamlit as st

from components import api, charts, ui

ui.setup("Analyse des menaces", "Classification ML, IOC, anomalies et enrichissement MITRE ATT&CK expliqués")

rid = ui.report_picker()
if not rid:
    st.stop()
try:
    r = api.get(f"/api/v1/reports/{rid}")
except api.ApiError as exc:
    ui.show_error(exc)
    st.stop()

st.markdown(f"### {r['title']}")
st.markdown(f"{ui.status_badge(r['status'])} &nbsp; Soumis par **Org {r['submitter']['code']}** · TLP {r['tlp']} · "
            f"source : {r.get('source') or '-'} · format {r['source_type']}"
            + (" · <b>données synthétiques</b>" if r.get("is_synthetic") else ""), unsafe_allow_html=True)
if r["submitter"]["code"] == api.current_org() and r["status"] in ("IMPORTED", "ANALYZED"):
    if st.button("↻ Relancer l'analyse"):
        try:
            api.post(f"/api/v1/reports/{rid}/analyze")
            api.clear_cache()
            st.rerun()
        except api.ApiError as exc:
            ui.show_error(exc)

tab_ml, tab_ioc, tab_mitre, tab_anom, tab_text = st.tabs(
    ["🤖 Classification", "🧬 IOC", "🎯 MITRE ATT&CK", "⚠️ Anomalies & qualité", "📄 Texte"])

with tab_ml:
    cls = r["classification"]
    if not cls.get("probabilities"):
        st.info("Rapport non analysé.")
    else:
        c1, c2 = st.columns([1.3, 1])
        c1.plotly_chart(charts.probabilities(cls["probabilities"], cls["category"]), use_container_width=True)
        with c2:
            st.metric("Catégorie prédite", ui.CATEGORY_LABELS.get(cls["category"], cls["category"]))
            st.caption(f"Méthode : {cls.get('method')} · modèle {cls.get('model_version')}")
            if cls.get("low_confidence"):
                ui.note("Confiance faible : la catégorie doit être confirmée par un analyste.", warn=True)
            if r.get("declared_category"):
                st.caption(f"Catégorie déclarée par la source : {r['declared_category']}")
        expl = cls.get("explanation") or []
        if expl and "weight" in expl[0]:
            st.markdown("**Termes du rapport qui ont le plus contribué à la décision** (tf-idf × coefficient)")
            st.plotly_chart(charts.bar_h([e["term"] for e in expl], [e["weight"] for e in expl],
                                         ui.CATEGORY_COLORS.get(cls["category"]), None, 260, "{:.3f}"),
                            use_container_width=True)
        ui.note("Modèle : TF-IDF (1-2 grammes) + régression logistique, entraîné sur un corpus synthétique de 80 "
                "rapports (voir Documentation). Les indicateurs sont masqués avant vectorisation.")

with tab_ioc:
    iocs = r["iocs"]
    if not iocs:
        st.info("Aucun IOC.")
    else:
        df = pd.DataFrame(iocs)
        c1, c2, c3 = st.columns(3)
        c1.metric("Valides", int((df["status"] == "valid").sum()))
        c2.metric("Suspects", int((df["status"] == "suspicious").sum()))
        c3.metric("Mal formés", int((df["status"] == "malformed").sum()))
        flt = st.multiselect("Filtrer par statut", ["valid", "suspicious", "malformed"],
                             default=["valid", "suspicious", "malformed"])
        view = df[df["status"].isin(flt)]
        st.dataframe(pd.DataFrame({
            "Type": view["type"], "Valeur normalisée": view["value"], "Valeur brute": view["raw_value"],
            "Statut": view["status"], "Drapeaux": view["flags"].apply(lambda f: ", ".join(f)),
            "Confiance extraction": view["confidence"], "Occurrences": view["occurrences"],
            "Défangé": view["defanged"], "Provenance": view["provenance"],
            "Déjà vu (rapports)": view["known_in_reports"].apply(lambda k: ", ".join(k)),
            "Connu MISP": view["known_in_misp"], "Contexte": view["context"],
        }), hide_index=True, use_container_width=True,
            column_config={"Confiance extraction": st.column_config.ProgressColumn(min_value=0, max_value=1,
                                                                                   format="%.2f")})
        stats = r.get("analysis_metadata", {}).get("extraction_stats", {})
        if stats.get("filtered"):
            with st.expander(f"{len(stats['filtered'])} candidat(s) écarté(s) (faux positifs probables)"):
                st.dataframe(pd.DataFrame(stats["filtered"]), hide_index=True, use_container_width=True)
        ui.note("Un IOC syntaxiquement valide n'est pas nécessairement malveillant. Les drapeaux signalent les "
                "éléments à vérifier (infrastructure légitime connue, adresses privées, plages de documentation...).")

with tab_mitre:
    mitre = r["mitre"]
    if not mitre:
        st.info("Aucune technique proposée.")
    else:
        tactics = {}
        for m in mitre:
            for t in m["tactics"]:
                tactics[t] = tactics.get(t, 0) + 1
        c1, c2 = st.columns([1.4, 1])
        with c1:
            for m in mitre:
                method = {"rule": "règle", "similarity": "similarité", "declared": "déclarée"}.get(m["method"], m["method"])
                with st.expander(f"{m['technique_id']} · {m['name']} — {method}, confiance {m['confidence']:.2f}"):
                    st.markdown(f"**Tactique(s)** : {', '.join(m['tactics']) or '-'}")
                    st.markdown(f"**Justification** : {m['justification']}")
                    for ev in m.get("evidence") or []:
                        if "sentence" in ev:
                            st.markdown(f"> …{ev['sentence']}…  \n<small>expression : <code>{ev['expression']}</code></small>",
                                        unsafe_allow_html=True)
                        elif "shared_terms" in ev:
                            st.caption(f"Similarité {ev['similarity']} · termes communs : {', '.join(ev['shared_terms'])}")
                    if m.get("url"):
                        st.markdown(f"[Fiche officielle MITRE ATT&CK]({m['url']})")
        c2.plotly_chart(charts.bar_h(list(tactics), list(tactics.values()), None, "Tactiques couvertes", 300,
                                     "{:.0f}"), use_container_width=True)
        ui.note("Une correspondance par mot-clé est une <b>proposition</b> vérifiable, pas une preuve de l'utilisation "
                "de la technique. Les suggestions « similarité » sont faibles et non exportées vers MISP.")

with tab_anom:
    anomalies = r["anomalies"]
    if anomalies:
        for a in anomalies:
            st.markdown(f"{ui.badge(a['severity'], ui.SEVERITY_COLORS.get(a['severity']))} **{a['code']}** — "
                        f"{a['message']}", unsafe_allow_html=True)
            if a.get("details"):
                with st.expander("détails", expanded=False):
                    st.json(a["details"])
    else:
        st.success("Aucune incohérence détectée.")
    q = r.get("quality")
    if q:
        st.markdown(f"#### Qualité des informations Q = {q['value']:.1f} / 100")
        st.dataframe(pd.DataFrame([{"Composante": c["name"], "Poids": c["weight"], "Valeur (0-1)": c["value"],
                                    "Points": c["points"], "Explication": c["explanation"]} for c in q["components"]]),
                     hide_index=True, use_container_width=True)
        st.caption(f"Brut {q['gross']:.1f} − pénalités {q['penalty']:.1f} (plafonnées à {q['penalty_cap']:.0f})")

with tab_text:
    st.text_area("Contenu du rapport", r["text"], height=380, disabled=True)
