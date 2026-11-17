"""Dashboard général."""
import pandas as pd
import streamlit as st

from components import api, charts, ui

ui.setup("Dashboard général", "Vue d'ensemble des renseignements partagés par les organisations A, B et C")

try:
    d = api.cached_get("/api/v1/stats/dashboard", api.current_org())
    orgs = api.cached_get("/api/v1/organizations", api.current_org())
except api.ApiError as exc:
    ui.show_error(exc)
    st.stop()

ui.cards([
    ("Rapports", d["reports_total"], f"{d['reports_by_status'].get('ANALYZED', 0)} analysés non soumis"),
    ("IOC", d["iocs_total"], f"{d['iocs_unique']} valeurs uniques"),
    ("Validés", d["validated"], (f"dont {d['validated_on_previous_instance']} sur instance précédente"
                                 if d.get("validated_on_previous_instance") else "majorité des validateurs")),
    ("Rejetés", d["rejected"], f"{d['disputed']} en désaccord"),
    ("En attente", d["pending"], "votes en cours"),
    ("Corrélations", d["correlations_total"], f"{d['transactions_total']} transactions Ethereum"),
])
st.write("")

c1, c2, c3 = st.columns([1, 1.2, 1.3])
c1.plotly_chart(charts.status_donut(d["reports_by_status"]), use_container_width=True)
c2.plotly_chart(charts.category_bars(d["reports_by_category"]), use_container_width=True)
onchain = {o["code"]: (o.get("onchain") or {}).get("reputation") for o in orgs}
c3.plotly_chart(charts.reputation_bars(d["organizations"], onchain if any(onchain.values()) else None),
                use_container_width=True)

c1, c2 = st.columns(2)
with c1:
    st.subheader("Indicateurs de compromission")
    types = d["iocs_by_type"]
    if types:
        st.plotly_chart(charts.bar_h([t.upper() for t in types], list(types.values()), None,
                                     "IOC par type", 240, "{:.0f}"), use_container_width=True)
    st.markdown("**IOC partagés par plusieurs rapports** (doublons inter-rapports)")
    if d["shared_iocs"]:
        st.dataframe(pd.DataFrame(d["shared_iocs"])[["reports", "type", "value"]].rename(
                         columns={"type": "Type", "value": "Valeur", "reports": "Nb rapports"}),
                     hide_index=True, use_container_width=True)
    else:
        st.caption("Aucun IOC partagé pour l'instant.")
with c2:
    st.subheader("Techniques MITRE ATT&CK les plus fréquentes")
    if d["top_mitre"]:
        tm = d["top_mitre"]
        st.plotly_chart(charts.bar_h([f"{t['technique_id']} {t['name']}" for t in tm], [t["count"] for t in tm],
                                     ui.CATEGORY_COLORS["malware"], None, 320, "{:.0f}"), use_container_width=True)
    st.markdown("**Incohérences détectées**")
    if d["anomalies_by_code"]:
        st.dataframe(pd.DataFrame([{"Anomalie": k, "Occurrences": v} for k, v in
                                   sorted(d["anomalies_by_code"].items(), key=lambda kv: -kv[1])]),
                     hide_index=True, use_container_width=True)

st.subheader("Derniers rapports")
try:
    reports = api.list_reports(limit=50)
except api.ApiError as exc:
    ui.show_error(exc)
    reports = []
if reports:
    df = pd.DataFrame([{
        "Rapport": r["report_id"], "Titre": r["title"], "Org": r["submitter"]["code"], "Statut": r["status"],
        "Catégorie": ui.CATEGORY_LABELS.get(r["category"], r["category"] or "-"), "IOC": r["ioc_count"],
        "Score": r["score"], "Final": "oui" if r["score_final"] else "provisoire", "MISP": r["misp_sync_status"],
        "Importé": pd.to_datetime(r["created_at"]).strftime("%Y-%m-%d %H:%M"),
    } for r in reports])
    st.dataframe(df, hide_index=True, use_container_width=True,
                 column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100,
                                                                        format="%.1f")})
else:
    st.info("Aucun rapport. Commencez par la page « Importation CTI ».")
ui.note("Le score de fiabilité est un indicateur explicable (0-100), pas une probabilité de véracité. "
        "La blockchain garantit l'intégrité et la traçabilité des validations, pas la véracité du renseignement.")
