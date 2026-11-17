"""Fiabilité et réputation: explained score per report, reputation history and comparison."""
import pandas as pd
import streamlit as st

from components import api, charts, theme, ui

ui.setup("Fiabilité & réputation", "Score explicable S = 0,30 R + 0,30 Q + 0,40 V et réputation dynamique des organisations")

tab_score, tab_rep = st.tabs(["📊 Score de fiabilité d'un rapport", "🏛️ Réputation des organisations"])

with tab_score:
    rid = ui.report_picker(key="rel_pick", statuses=["ANALYZED", "PENDING", "VALIDATED", "REJECTED", "DISPUTED",
                                                     "INCOMPLETE"])
    if rid:
        try:
            s = api.get(f"/api/v1/reports/{rid}/score")
        except api.ApiError as exc:
            ui.show_error(exc)
            st.stop()
        d = s["details"]
        c1, c2 = st.columns([1, 1.3])
        c1.plotly_chart(charts.gauge(s["score"], s["is_final"]), use_container_width=True)
        c2.plotly_chart(charts.contributions(d), use_container_width=True)
        ui.cards([("R · réputation source", f"{s['r']:.1f}", d["R"]["explanation"][:70]),
                  ("Q · qualité", f"{s['q']:.1f}", f"brut {d['Q']['gross']:.1f} − pénalités {d['Q']['penalty']:.1f}"),
                  ("V · validation", f"{s['v']:.1f}", s["validation_status"]),
                  ("Niveau", d["level"], "final" if s["is_final"] else "provisoire")])
        st.write("")
        st.markdown(f"**V** — {d['V']['explanation']}")
        st.markdown("**Q — détail des composantes**")
        st.dataframe(pd.DataFrame([{"Composante": c["name"], "Poids": c["weight"], "Valeur": c["value"],
                                    "Points": c["points"], "Explication": c["explanation"]}
                                   for c in d["Q"]["components"]]), hide_index=True, use_container_width=True)
        if d["Q"]["penalties"]:
            st.markdown("**Incohérences pénalisant Q**")
            st.dataframe(pd.DataFrame(d["Q"]["penalties"]), hide_index=True, use_container_width=True)
        if s["history"]:
            import plotly.graph_objects as go

            hist = s["history"]
            labels = [f"{i + 1}. {h['trigger']}" for i, h in enumerate(hist)]
            fig = go.Figure()
            tk = theme.tokens()
            for key, name, color in (("score", "S", tk["primary"]), ("r", "R", tk["org"]["B"]),
                                     ("q", "Q", tk["category"]["ransomware"]), ("v", "V", tk["status"]["VALIDATED"])):
                fig.add_scatter(x=labels, y=[h[key] for h in hist], name=name, mode="lines+markers",
                                line=dict(color=color, width=3 if key == "score" else 1.5))
            fig.update_layout(height=300, margin=dict(l=10, r=10, t=30, b=10), yaxis=dict(range=[0, 105]),
                              title="Historique du score (analyse, soumission, votes, finalisation)")
            charts.style(fig)
            st.plotly_chart(fig, use_container_width=True)
        ui.note(d["disclaimer"] + " Politique de validation incomplète : V = 50 (neutre) tant qu'aucun vote n'est "
                "enregistré, puis V = 50 + 50 × (oui − non) / éligibles ; le score reste « provisoire » jusqu'à la "
                "finalisation par le smart contract.")

with tab_rep:
    try:
        orgs = api.cached_get("/api/v1/organizations", api.current_org())
        details = {o["code"]: api.get(f"/api/v1/organizations/{o['id']}/reputation") for o in orgs}
    except api.ApiError as exc:
        ui.show_error(exc)
        st.stop()
    onchain = {o["code"]: (o.get("onchain") or {}).get("reputation") for o in orgs}
    c1, c2 = st.columns([1, 1.3])
    c1.plotly_chart(charts.reputation_bars([{"code": o["code"], "reputation": o["reputation"]} for o in orgs],
                                           onchain if any(v is not None for v in onchain.values()) else None),
                    use_container_width=True)
    c2.plotly_chart(charts.reputation_history({c: v["history"] for c, v in details.items()}), use_container_width=True)
    st.dataframe(pd.DataFrame([{
        "Organisation": f"Org {o['code']} — {o['name']}", "Réputation off-chain": o["reputation"],
        "Réputation on-chain": onchain.get(o["code"]), "Rapports": o["stats"]["reports_total"],
        "Validés": o["stats"]["validated"], "Rejetés": o["stats"]["rejected"], "Votes émis": o["stats"]["votes_cast"],
        "Adresse Ethereum": o["eth_address"]} for o in orgs]), hide_index=True, use_container_width=True)
    pick = st.selectbox("Historique détaillé", [o["code"] for o in orgs], format_func=lambda c: f"Org {c}")
    hist = details[pick]["history"]
    if hist:
        st.dataframe(pd.DataFrame([{"Date": h["at"], "Rapport": h["report_id"], "Raison": h["reason"],
                                    "Avant": h["old"], "Après": h["new"], "Δ appliqué": h["applied_delta"],
                                    "Δ brut": h["raw_delta"], "On-chain": h["onchain_value"],
                                    "Explication": h["explanation"]} for h in hist]),
                     hide_index=True, use_container_width=True)
    else:
        st.info("Aucune évolution : réputation neutre initiale (50).")
    with st.expander("Règles de réputation (garde-fous)"):
        st.code(details[pick]["policy"]["description"], language=None)
