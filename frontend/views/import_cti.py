"""Importation CTI: upload TXT/PDF/JSON, manual entry, MISP event import, preview and full analysis."""
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from components import api, ui

ui.setup("Importation CTI", "Import de rapports, prévisualisation et analyse automatique (NLP → ML → MITRE → MISP)")

DEMO_DIRS = [Path(__file__).resolve().parents[1] / "demo_data", Path(__file__).resolve().parents[2] / "data" / "demo"]
DEMO_DIR = next((d for d in DEMO_DIRS if d.exists()), None)
TLPS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]


def show_analysis(res: dict) -> None:
    d = res.get("details", {})
    status = res.get("status")
    st.markdown(f"**Résultat** : {ui.status_badge(status)} &nbsp; Rapport **{res.get('report_id') or 'aperçu'}**",
                unsafe_allow_html=True)
    cls = d.get("classification", {})
    probs = cls.get("probabilities", {})
    ui.cards([("Catégorie (ML)", ui.CATEGORY_LABELS.get(res.get("category"), res.get("category") or "-"),
               cls.get("method", "")),
              ("Confiance", f"{max(probs.values()):.0%}" if probs else "-", "probabilité max."),
              ("IOC exploitables", len(res.get("iocs", [])), "hors mal formés"),
              ("Techniques ATT&CK", len(res.get("mitre_techniques", [])), "règles / déclarées")])
    iocs = d.get("iocs", [])
    if iocs:
        st.markdown("**IOC extraits et normalisés**")
        st.dataframe(pd.DataFrame([{
            "Type": i.get("type", i.get("ioc_type")), "Valeur normalisée": i["value"], "Brut": i.get("raw_value"),
            "Statut": i["status"], "Drapeaux": ", ".join(i.get("flags") or []), "Défangé": i.get("defanged"),
            "Occurrences": i.get("occurrences"), "Confiance extraction": i.get("confidence"),
            "Provenance": i.get("provenance"), "Déjà vu dans": ", ".join(i.get("known_in_reports") or []),
        } for i in iocs]), hide_index=True, use_container_width=True)
        ui.note("La confiance affichée est une confiance d'<b>extraction</b> : un IOC syntaxiquement valide "
                "n'est pas nécessairement malveillant.")
    mitre = d.get("mitre") or d.get("mitre_techniques") or []
    if mitre:
        st.markdown("**Techniques MITRE ATT&CK proposées**")
        st.dataframe(pd.DataFrame([{"ID": m["technique_id"], "Technique": m["name"], "Tactiques": ", ".join(m["tactics"]),
                                    "Méthode": m["method"], "Confiance": m["confidence"],
                                    "Justification": m["justification"]} for m in mitre]),
                     hide_index=True, use_container_width=True)
    anomalies = d.get("anomalies", [])
    if anomalies:
        st.markdown("**Incohérences / points à vérifier**")
        for a in anomalies:
            st.markdown(f"{ui.badge(a['severity'], ui.SEVERITY_COLORS.get(a['severity']))} {a['message']}",
                        unsafe_allow_html=True)
    dup = res.get("duplicates")
    if dup:
        st.markdown(f"**Doublons** : {dup.get('within_report', 0)} occurrence(s) répétée(s) dans le rapport · "
                    f"{len(dup.get('known_in_other_reports', []))} IOC déjà présents dans d'autres rapports · "
                    f"{len(dup.get('known_in_misp', []))} déjà connus dans MISP")
    misp = res.get("misp") or d.get("misp")
    if misp and misp.get("status") or (misp and misp.get("sync_status")):
        mode = misp.get("mode")
        st.markdown(f"**MISP** : {misp.get('status') or misp.get('sync_status')} · mode "
                    f"{'réel' if mode == 'real' else 'simulé' if mode == 'simulated' else '-'} · événement "
                    f"{misp.get('event_id') or '-'} {('· erreur : ' + misp['error']) if misp.get('error') else ''}")
    corr = res.get("correlations") or []
    if corr:
        st.markdown("**Corrélations potentielles détectées**")
        for c in corr[:5]:
            st.markdown(f"- {c['report_id']} · score {c['score']:.2f} ({c['strength']}) — "
                        f"{'; '.join(c['evidence']['reasons'])}")
    if res.get("report_id"):
        st.session_state["selected_report"] = res["report_id"]
        st.success("Rapport enregistré. Poursuivez sur « Analyse des menaces » ou « Validation blockchain ».")


tab_file, tab_manual, tab_misp, tab_demo = st.tabs(["📄 Fichier (TXT / PDF / JSON)", "✍️ Saisie manuelle",
                                                     "🔗 Événement MISP", "🎬 Données de démonstration"])

with tab_file:
    up = st.file_uploader("Rapport CTI", type=["txt", "pdf", "json"], help="Taille maximale : 5 Mo")
    c1, c2 = st.columns(2)
    tlp = c1.selectbox("TLP", TLPS, index=1, key="tlp_file")
    source = c2.text_input("Source / provenance", key="src_file", placeholder="ex. SOC de l'organisation")
    if up is not None:
        raw = up.getvalue()
        with st.expander("Prévisualisation du contenu", expanded=True):
            if up.name.lower().endswith(".pdf"):
                st.caption(f"PDF de {len(raw) / 1024:.1f} Ko — le texte sera extrait côté serveur (pypdf).")
            elif up.name.lower().endswith(".json"):
                try:
                    st.json(json.loads(raw.decode("utf-8-sig")))
                except ValueError:
                    st.error("JSON invalide")
            else:
                st.text(raw.decode("utf-8", errors="replace")[:5000])
        b1, b2 = st.columns(2)
        if b1.button("🔍 Aperçu de l'analyse (sans enregistrement)", disabled=up.name.lower().endswith(".pdf")):
            text = raw.decode("utf-8", errors="replace")
            title = up.name
            if up.name.lower().endswith(".json"):
                obj = json.loads(text)
                text, title = obj.get("text", ""), obj.get("title", up.name)
            try:
                with st.spinner("Analyse..."):
                    show_analysis(api.post("/api/v1/reports/analyze", json={"title": title[:300], "text": text,
                                                                            "persist": False}))
            except api.ApiError as exc:
                ui.show_error(exc)
        if b2.button("🚀 Importer et analyser", type="primary"):
            try:
                with st.spinner("Import, extraction, classification, enrichissement, MISP..."):
                    res = api.post("/api/v1/reports/upload", files={"file": (up.name, raw)},
                                   data={"tlp": tlp, "source": source or ""})
                api.clear_cache()
                show_analysis(res)
            except api.ApiError as exc:
                ui.show_error(exc)

with tab_manual:
    with st.form("manual"):
        title = st.text_input("Titre", max_chars=300)
        text = st.text_area("Texte du rapport", height=220, placeholder="Collez ici le rapport CTI...")
        c1, c2, c3 = st.columns(3)
        tlp_m = c1.selectbox("TLP", TLPS, index=1)
        cat = c2.selectbox("Catégorie déclarée (optionnel)", ["", "phishing", "ransomware", "malware", "exploitation"])
        pub = c3.date_input("Date de publication", value=None)
        c1, c2 = st.columns(2)
        src = c1.text_input("Source")
        src_url = c2.text_input("URL source (optionnel)")
        mitre_decl = st.text_input("Techniques ATT&CK déclarées (optionnel, séparées par des virgules)",
                                   placeholder="T1566.001, T1204.002")
        preview_only = st.checkbox("Aperçu seulement (ne rien enregistrer)")
        submitted = st.form_submit_button("Analyser", type="primary")
    if submitted:
        try:
            with st.spinner("Analyse en cours..."):
                if preview_only:
                    res = api.post("/api/v1/reports/analyze", json={"title": title, "text": text, "persist": False})
                else:
                    body = {"title": title, "text": text, "tlp": tlp_m, "source": src or None,
                            "source_url": src_url or None, "category": cat or None,
                            "published_at": pub.isoformat() if pub else None,
                            "mitre_techniques": [m.strip() for m in mitre_decl.split(",") if m.strip()]}
                    res = api.post("/api/v1/reports", json=body)
                    api.clear_cache()
            show_analysis(res)
        except api.ApiError as exc:
            ui.show_error(exc)

with tab_misp:
    st.caption("Importer un événement MISP existant (IOC déclarés repris comme indicateurs, puis analyse complète).")
    ref = st.text_input("Identifiant ou UUID de l'événement MISP")
    if st.button("Importer l'événement", disabled=not ref):
        try:
            with st.spinner("Lecture de l'événement MISP..."):
                res = api.post(f"/api/v1/reports/import-misp/{ref.strip()}")
            api.clear_cache()
            show_analysis(res)
        except api.ApiError as exc:
            ui.show_error(exc)

with tab_demo:
    ui.note("Rapports de démonstration <b>synthétiques</b> (indicateurs fictifs RFC 5737 / RFC 2606). "
            "Scénario conseillé : Org A importe le n°1, le soumet ; B et C votent ; puis Org B importe le n°2 "
            "(IOC partagé → corrélation).")
    if DEMO_DIR is None:
        st.warning("Dossier de démonstration introuvable.")
    else:
        for f in sorted(DEMO_DIR.iterdir()):
            if f.suffix.lower() not in (".txt", ".json", ".pdf"):
                continue
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"**{f.name}**  \n<small>{f.stat().st_size / 1024:.1f} Ko</small>", unsafe_allow_html=True)
            if c2.button("Importer", key=f"demo_{f.name}"):
                try:
                    with st.spinner(f"Import de {f.name}..."):
                        st.session_state["demo_result"] = api.post(
                            "/api/v1/reports/upload", files={"file": (f.name, f.read_bytes())},
                            data={"tlp": "TLP:GREEN", "source": f"Démo - Org {api.current_org()}"})
                    st.session_state.pop("demo_error", None)
                    api.clear_cache()
                except api.ApiError as exc:
                    st.session_state["demo_error"] = exc
                    st.session_state.pop("demo_result", None)
        st.divider()
        if st.session_state.get("demo_error"):
            ui.show_error(st.session_state["demo_error"])
        elif st.session_state.get("demo_result"):
            show_analysis(st.session_state["demo_result"])
