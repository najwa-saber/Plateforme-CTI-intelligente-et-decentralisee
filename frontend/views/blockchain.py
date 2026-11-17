"""Validation blockchain: submitted reports, SHA-256, votes, statuses, transaction history, actions by rights."""
import pandas as pd
import streamlit as st

from components import api, ui

ui.setup("Validation blockchain", "Empreintes SHA-256 sur Ethereum, votes des validateurs et finalisation par smart contract")

try:
    chain = api.cached_get("/api/v1/blockchain/status", api.current_org())
except api.ApiError as exc:
    ui.show_error(exc)
    st.stop()

c1, c2, c3, c4 = st.columns(4)
c1.markdown(ui.card("Réseau", "Hardhat local" if chain.get("chain_id") == 31337 else chain.get("chain_id", "-"),
                    f"bloc #{chain.get('block_number', '-')}"), unsafe_allow_html=True)
_addr = chain.get("contract_address") or "-"
c2.markdown(ui.card("Contrat CTIValidation", f"{_addr[:6]}…{_addr[-4:]}" if len(_addr) > 12 else _addr,
                    "déployé" if chain.get("contract_deployed") else "non déployé"), unsafe_allow_html=True)
c3.markdown(ui.card("Rapports on-chain", chain.get("report_count", "-"), "empreintes enregistrées"), unsafe_allow_html=True)
period = chain.get("voting_period_s")
c4.markdown(ui.card("Période de vote", f"{period / 86400:.1f} j" if period else "-", "au-delà : INCOMPLETE"),
            unsafe_allow_html=True)
if chain.get("warning") or chain.get("error"):
    ui.note(chain.get("warning") or chain.get("error"), warn=True)
ui.note("<b>On-chain</b> : identifiant, empreinte SHA-256, adresses, votes, statut, réputation protocolaire. "
        "<b>Off-chain</b> : rapport, IOC, analyses (PostgreSQL + MISP). Règle : seuil = ⌊éligibles/2⌋ + 1 "
        "(A soumet → B et C votent : 2 oui = VALIDATED, 2 non = REJECTED, 1/1 = DISPUTED, 1 seul vote = PENDING).")

try:
    reports = api.list_reports()
except api.ApiError as exc:
    ui.show_error(exc)
    st.stop()

submitted = [r for r in reports if r["chain_report_id"] is not None]
st.subheader("Rapports soumis pour validation")
if submitted:
    anchor_label = {"current": "✔ chaîne actuelle", "previous_instance": "⚠ instance précédente (non vérifiable)",
                    "unknown": "? nœud injoignable"}
    st.dataframe(pd.DataFrame([{"Rapport": r["report_id"], "ID on-chain": r["chain_report_id"],
                                "Ancrage": anchor_label.get(r.get("chain_anchor"), "-"), "Titre": r["title"],
                                "Émetteur": f"Org {r['submitter']['code']}", "Votes ✔": r["votes"]["approve"],
                                "Votes ✘": r["votes"]["reject"], "Statut off-chain": r["status"], "Score": r["score"]}
                               for r in submitted]), hide_index=True, use_container_width=True)
    if any(r.get("chain_anchor") == "previous_instance" for r in submitted):
        ui.note("Les rapports marqués « instance précédente » ont été ancrés sur un réseau Hardhat qui a depuis été "
                "redémarré : leur statut est l'historique enregistré off-chain, leur empreinte n'est plus vérifiable "
                "on-chain (les identifiants on-chain ont été réattribués à d'autres rapports).", warn=True)
else:
    st.info("Aucun rapport soumis on-chain pour l'instant.")

st.subheader("Actions et détail")
rid = ui.report_picker("Rapport", key="bc_pick", statuses=["ANALYZED", "PENDING", "VALIDATED", "REJECTED",
                                                           "DISPUTED", "INCOMPLETE"])
if not rid:
    st.stop()
try:
    r = api.get(f"/api/v1/reports/{rid}")
    st_info = api.get(f"/api/v1/reports/{rid}/status")
except api.ApiError as exc:
    ui.show_error(exc)
    st.stop()

me = api.current_org()
is_owner = r["submitter"]["code"] == me
st.markdown(f"{ui.status_badge(r['status'])} &nbsp; **{r['title']}** — émetteur Org {r['submitter']['code']}",
            unsafe_allow_html=True)
bc = r["blockchain"]

col_a, col_b = st.columns([1.3, 1])
with col_a:
    if bc["content_hash"]:
        st.markdown(f"**Empreinte SHA-256 ({bc['canonical_version']})**<br><span class='cti-hash'>{bc['content_hash']}</span>",
                    unsafe_allow_html=True)
        st.caption(f"ID on-chain {bc['chain_report_id']} · contrat {bc['contract']}")
    if st_info.get("chain_error"):
        ui.note("⚠️ " + st_info["chain_error"] + " — le statut affiché est le dernier statut off-chain enregistré "
                "(voir docs/07_troubleshooting.md, « réinitialisation de la chaîne »).", warn=True)
    chain_view = st_info.get("chain")
    if chain_view:
        st.markdown(f"**État on-chain** : {ui.status_badge(chain_view['status'])} · {chain_view['approvals']} oui / "
                    f"{chain_view['rejections']} non · seuil {chain_view['threshold']} sur "
                    f"{chain_view['eligible_validators']} validateurs éligibles", unsafe_allow_html=True)
        prev = st_info.get("finalization_preview") or {}
        if r["status"] == "PENDING":
            st.caption(f"Finalisation possible : {'oui → ' + prev.get('outcome', '') if prev.get('can_finalize') else 'non (votes incomplets)'}")
    if st_info.get("votes"):
        st.dataframe(pd.DataFrame([{"Organisation": f"Org {v['org']}", "Vote": "APPROUVE" if v["approve"] else "REJETTE",
                                    "Transaction": v["tx_hash"], "Date": v["at"]} for v in st_info["votes"]]),
                     hide_index=True, use_container_width=True)
with col_b:
    st.markdown("**Actions disponibles pour Org " + me + "**")
    if r["status"] == "ANALYZED":
        if is_owner:
            if st.button("⛓️ Soumettre l'empreinte sur Ethereum", type="primary", use_container_width=True):
                try:
                    with st.spinner("Transaction submitReport..."):
                        res = api.post(f"/api/v1/reports/{rid}/submit")
                    api.clear_cache()
                    st.success(f"Soumis : id on-chain {res['chain_report_id']} · tx {res['transaction']['tx_hash'][:18]}…")
                    st.rerun()
                except api.ApiError as exc:
                    ui.show_error(exc)
        else:
            st.caption("Seule l'organisation émettrice peut soumettre ce rapport.")
    elif r["status"] == "PENDING":
        if st_info.get("can_vote"):
            comment = st.text_input("Commentaire (optionnel)", key="vote_comment")
            b1, b2 = st.columns(2)
            for col, approve, label in ((b1, True, "✔ Approuver"), (b2, False, "✘ Rejeter")):
                if col.button(label, use_container_width=True, type="primary" if approve else "secondary"):
                    try:
                        with st.spinner("Transaction voteReport..."):
                            res = api.post(f"/api/v1/reports/{rid}/vote", json={"approve": approve,
                                                                                "comment": comment or None})
                        api.clear_cache()
                        st.success(f"Vote enregistré (tx {res['transaction']['tx_hash'][:18]}…)"
                                   + (f" — rapport finalisé : {res['status']}" if res.get("finalized") else ""))
                        st.rerun()
                    except api.ApiError as exc:
                        ui.show_error(exc)
        elif is_owner:
            st.info("Auto-validation interdite : l'émetteur ne peut pas voter sur son propre rapport.")
        else:
            st.info("Votre organisation a déjà voté sur ce rapport.")
        if st.button("Finaliser (règle de majorité)", use_container_width=True):
            try:
                res = api.post(f"/api/v1/reports/{rid}/finalize")
                api.clear_cache()
                st.success(f"Statut final : {res['status']}")
                st.rerun()
            except api.ApiError as exc:
                ui.show_error(exc)
    else:
        st.caption("Rapport finalisé : aucune action de vote possible.")
    if bc["chain_report_id"] is not None and st.button("🔐 Vérifier l'intégrité", use_container_width=True):
        try:
            integ = api.get(f"/api/v1/reports/{rid}/integrity")
            if integ["verified"] is None:
                st.warning(integ["message"])
            else:
                (st.success if integ["verified"] else st.error)(integ["message"])
            st.markdown(f"Hash recalculé : <span class='cti-hash'>{integ['recomputed_hash']}</span><br>"
                        f"Hash enregistré à la soumission : <span class='cti-hash'>{integ['stored_hash']}</span><br>"
                        f"Hash on-chain : <span class='cti-hash'>{integ['onchain_hash'] or 'indisponible'}</span>",
                        unsafe_allow_html=True)
        except api.ApiError as exc:
            ui.show_error(exc)

st.subheader("Historique des transactions")
try:
    txs = api.get("/api/v1/blockchain/transactions", params={"report_id": rid})
    if txs:
        st.dataframe(pd.DataFrame([{"Action": t["action"], "Org": t["org"], "Bloc": t["block_number"], "Gas": t["gas_used"],
                                    "Statut": t["status"], "Événements": ", ".join(e["event"] for e in t["events"] or []),
                                    "Tx": t["tx_hash"], "Date": t["created_at"]} for t in txs]),
                     hide_index=True, use_container_width=True)
    if bc["chain_report_id"] is not None:
        with st.expander("Événements Solidity lus sur la blockchain (journal on-chain)"):
            ev = api.get(f"/api/v1/reports/{rid}/chain-events")
            st.dataframe(pd.DataFrame([{"Événement": e["event"], "Bloc": e["block_number"], "Arguments": str(e["args"]),
                                        "Tx": e["tx_hash"]} for e in ev["events"]]), hide_index=True,
                         use_container_width=True)
except api.ApiError as exc:
    ui.show_error(exc)
