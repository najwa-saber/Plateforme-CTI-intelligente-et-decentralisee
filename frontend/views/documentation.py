"""Documentation: architecture, pipeline, technical information, honest evaluation results and limits."""
import pandas as pd
import streamlit as st

from components import api, charts, theme, ui

ui.setup("Documentation", "Architecture, fonctionnement, informations techniques et limites du prototype")
T = theme.tokens()
NODE = (f'node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11, color="{T["primary"]}", '
        f'fillcolor="{T["surface"]}", fontcolor="{T["text"]}"]; '
        f'edge [color="{T["muted"]}", fontcolor="{T["muted"]}", fontname="Helvetica", fontsize=9]; '
        f'graph [fontcolor="{T["text"]}"];')

tab_arch, tab_flow, tab_ml, tab_tech, tab_lim = st.tabs(
    ["🏗️ Architecture", "🔁 Fonctionnement", "📈 Évaluation ML / NLP", "⚙️ Informations techniques", "🚧 Limites"])

with tab_arch:
    st.graphviz_chart("""
digraph G {
  rankdir=LR; bgcolor="transparent"; NODE_STYLE
  subgraph cluster_orgs { label="Organisations simulées"; style="rounded,dashed"; color="MUTED";
    A [label="Org A"]; B [label="Org B"]; C [label="Org C"]; }
  UI [label="Streamlit\\n(dashboard)", fillcolor="SURF2"];
  API [label="FastAPI\\norchestrateur\\n(auth X-API-Key)", fillcolor="SURF2", penwidth=2];
  subgraph cluster_ai { label="Analyse (off-chain)"; style="rounded"; color="PRIMARY";
    NLP [label="NLP\\nextraction IOC\\nnormalisation"]; DUP [label="Doublons &\\nincohérences"];
    ML [label="ML\\nTF-IDF + LogReg"]; MITRE [label="MITRE ATT&CK\\n(STIX officiel)"];
    SCORE [label="Score S\\nRéputation"]; CORR [label="Corrélation"]; }
  PG [label="PostgreSQL\\ndonnées applicatives", shape=cylinder, fillcolor="SURF2"];
  MISP [label="MISP (PyMISP)\\nréférentiel CTI", shape=cylinder, fillcolor="SURF2"];
  ETH [label="Ethereum (Hardhat)\\nCTIValidation.sol\\nempreintes, votes, statuts", shape=cylinder, fillcolor="SURF2"];
  A -> UI; B -> UI; C -> UI; UI -> API [label="REST/JSON"];
  API -> NLP -> DUP -> ML -> MITRE -> SCORE; API -> CORR;
  API -> PG [label="SQLAlchemy"]; API -> MISP [label="événements, attributs, tags"];
  API -> ETH [label="Web3.py\\nSHA-256, votes"];
}
""".replace("NODE_STYLE", NODE).replace("MUTED", T["muted"]).replace("SURF2", T["surface2"])
      .replace("PRIMARY", T["primary"]), use_container_width=True)
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### Off-chain (PostgreSQL + MISP)")
        st.markdown("- rapports CTI, descriptions, métadonnées, provenance\n- IOC normalisés et leur contexte\n"
                    "- résultats NLP / ML / MITRE, anomalies\n- scores, historique de réputation, corrélations, audit")
    with c2:
        st.markdown("#### On-chain (Ethereum)")
        st.markdown("- identifiant du rapport et empreinte SHA-256 du rapport canonisé\n- adresses des organisations\n"
                    "- votes, statut (PENDING / VALIDATED / REJECTED / DISPUTED / INCOMPLETE)\n"
                    "- réputation protocolaire bornée\n- événements Solidity (traçabilité)")
    ui.note("Aucun rapport complet ni information sensible n'est écrit sur la blockchain : seules des empreintes et des "
            "métadonnées techniques. La blockchain garantit l'intégrité et la traçabilité, pas la véracité.")

with tab_flow:
    st.graphviz_chart("""
digraph S { rankdir=TB; bgcolor="transparent"; NODE_STYLE
 r [label="1. Rapport CTI (TXT, PDF, JSON, saisie, événement MISP)"]; n [label="2. Extraction NLP des IOC (regex + validation)"];
 no [label="3. Normalisation (refang, minuscules, punycode, IP canonique)"]; d [label="4. Doublons (intra, inter-rapports, MISP)"];
 i [label="5. Incohérences (mal formés, infra légitime, catégorie...)"]; m [label="6. Classification ML + probabilités"];
 t [label="7. Enrichissement MITRE ATT&CK justifié"]; mi [label="8. Événement MISP (PyMISP)"];
 h [label="9. SHA-256 du rapport canonisé"]; e [label="10. submitReport() sur Ethereum"];
 v [label="11. voteReport() par les validateurs éligibles"]; f [label="12. finalizeReport() - règle de majorité"];
 s [label="13. Score S = 0,30R + 0,30Q + 0,40V"]; rp [label="14. Réputation (on-chain + analytique)"];
 c [label="15. Corrélations potentielles"]; u [label="16. Visualisation Streamlit"];
 r->n->no->d->i->m->t->mi->h->e->v->f->s->rp->c->u; }
""".replace("NODE_STYLE", NODE), use_container_width=True)

with tab_ml:
    try:
        info = api.cached_get("/api/v1/ml/model", api.current_org())
    except api.ApiError as exc:
        ui.show_error(exc)
        info = {}
    m = info.get("metrics")
    if m:
        t = m["test"]
        ui.cards([("Accuracy (test)", f"{t['accuracy']:.3f}", f"{m['dataset']['sizes']['test']} documents"),
                  ("Macro-F1 (test)", f"{t['macro_f1']:.3f}", f"précision {t['macro_precision']:.3f} · rappel {t['macro_recall']:.3f}"),
                  ("CV groupée 5 plis", f"{m['grouped_cross_validation']['macro_f1_mean']:.3f}",
                   f"± {m['grouped_cross_validation']['macro_f1_std']:.3f} (macro-F1)"),
                  ("C retenu", m["selected_C"], "sélection sur validation")])
        st.write("")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Métriques par catégorie (test)**")
            st.dataframe(pd.DataFrame(t["per_class"]).T.rename(columns={"f1-score": "F1"}), use_container_width=True)
            st.markdown("**Comparaison aux baselines (même jeu de test, macro-F1)**")
            st.dataframe(pd.DataFrame([{"Modèle": "TF-IDF + régression logistique (retenu)", "Macro-F1": t["macro_f1"]}] +
                                      [{"Modèle": k, "Macro-F1": v["macro_f1"]} for k, v in m["baselines_test"].items()]),
                         hide_index=True, use_container_width=True)
        with c2:
            import plotly.graph_objects as go

            cm = t["confusion_matrix"]
            fig = go.Figure(go.Heatmap(z=cm["matrix"], x=cm["labels"], y=cm["labels"], colorscale=T["heatmap"],
                                       text=cm["matrix"], texttemplate="%{text}", showscale=False,
                                       xgap=2, ygap=2, textfont=dict(size=15)))
            fig.update_layout(title="Matrice de confusion (test)", xaxis_title="Prédit", yaxis_title="Réel", height=330,
                              margin=dict(l=10, r=10, t=40, b=10), yaxis=dict(autorange="reversed"))
            charts.style(fig)
            st.plotly_chart(fig, use_container_width=True)
        st.markdown("**Erreurs sur le jeu de test**")
        st.dataframe(pd.DataFrame(m["test_errors"]), hide_index=True, use_container_width=True)
        with st.expander("Termes les plus discriminants par classe (coefficients)"):
            for cls, feats in m["top_features"].items():
                st.markdown(f"**{cls}** : " + ", ".join(f"{f} ({w})" for f, w in feats))
        for lim in m["limitations"]:
            st.caption("⚠️ " + lim)
    st.markdown("**Extraction des IOC** : évaluée sur les 182 IOC annotés du corpus et sur un jeu « challenge » "
                "indépendant — voir `docs/05_evaluation.md` et `docs/test-reports/`.")

with tab_tech:
    try:
        mitre = api.cached_get("/api/v1/mitre/info", api.current_org())
    except api.ApiError:
        mitre = {}
    st.markdown(f"""
| Composant | Technologie |
|---|---|
| API | FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, PostgreSQL 16 |
| NLP | expressions régulières + validation syntaxique (ipaddress, IANA TLD), refang, normalisation |
| ML | scikit-learn : TfidfVectorizer (1-2 grammes) + LogisticRegression, joblib |
| MITRE | ATT&CK Enterprise v{mitre.get('attack_version', '?')} (STIX 2.1 officiel), {mitre.get('techniques', '?')} techniques, {len(mitre.get('rules', []))} règles |
| CTI | MISP 2.5 (misp-docker) via PyMISP, adaptateur simulé de secours |
| Blockchain | Solidity 0.8.24, OpenZeppelin 5 (Ownable, Pausable), Hardhat, Web3.py |
| Interface | Streamlit, Plotly, NetworkX |
| Déploiement | Docker Compose (postgres, hardhat, backend, frontend, misp-*) |
""")
    st.markdown(f"- Documentation interactive de l'API : [{api.PUBLIC_API_URL}/docs]({api.PUBLIC_API_URL}/docs) "
                f"(Swagger) · [{api.PUBLIC_API_URL}/redoc]({api.PUBLIC_API_URL}/redoc)")
    st.markdown("- Authentification : en-tête `X-API-Key` (une clé par organisation, stockée hachée SHA-256)")
    st.markdown("- Codes HTTP : 400, 401, 403, 404, 409 (conflits, règles du contrat), 413, 422, 500, 503 (MISP/Ethereum)")

with tab_lim:
    st.markdown("""
- **Corpus synthétique** de 80 rapports rédigés pour le projet : les performances ML et NLP sont optimistes et ne
  démontrent pas une généralisation à des rapports réels ; 16 documents de test seulement (intervalle de confiance large).
- **IOC** : l'extraction identifie des formes syntaxiques ; elle ne prouve jamais la malveillance. Hors périmètre :
  IPv6, e-mails, SHA-1, chemins de fichiers, clés de registre.
- **MITRE** : règles par mots-clés (proposition vérifiable) + similarité avec les descriptions officielles (suggestion faible).
- **Blockchain** : réseau Hardhat local en mémoire (redémarrage = remise à zéro), un administrateur (owner) enregistre
  les organisations : gouvernance centralisée assumée pour le prototype ; pas de reproduction complète du Proof-of-Quality.
- **Réputation** : la règle « vote aligné sur la majorité » peut inciter au suivisme ; les bornes et plafonds limitent
  les manipulations évidentes mais pas une collusion de deux organisations sur trois.
- **Trois organisations** simulées dans une même interface (les trois clés API sont chargées par le frontend).
- **MISP** : instance de laboratoire avec certificat auto-signé (vérification TLS désactivée en local).
""")
