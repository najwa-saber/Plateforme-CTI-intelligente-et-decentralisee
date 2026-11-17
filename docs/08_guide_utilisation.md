# 08 — Guide d'utilisation et scénario de soutenance

Interface : **http://localhost:8501**. Barre latérale : sélecteur de **thème** (🌙 Sombre / ☀️ Clair), choix de
l'**organisation** active (A, B, C — chaque choix utilise la clé API et le compte Ethereum de l'organisation), état
des services (PostgreSQL, ML, ATT&CK, MISP réel/simulé, Ethereum) et avertissements éventuels.
Les paramètres `?theme=`, `?org=` et `?report=` de l'URL permettent des liens directs reproductibles.

## Les huit pages

| Page | Contenu | Actions |
|---|---|---|
| **Dashboard général** | rapports, IOC, validés / rejetés / en attente, statuts, menaces, réputations off/on-chain, IOC partagés, techniques fréquentes, incohérences, derniers rapports | — |
| **Importation CTI** | fichier TXT / PDF / JSON, saisie manuelle, événement MISP, données de démonstration | aperçu sans enregistrement, import + analyse, résultats détaillés |
| **Analyse des menaces** | classification (probabilités, termes explicatifs), IOC (statut, drapeaux, confiance d'extraction, contexte, candidats écartés), ATT&CK (tactiques, justification, phrase source, lien officiel), anomalies et détail de Q, texte | relancer l'analyse (émetteur) |
| **Gestion MISP** | mode réel/simulé, version, synchronisation, événements, attributs, tags | recherche d'IOC, re-test de connexion, (re)synchronisation |
| **Validation blockchain** | réseau, contrat, rapports soumis, empreinte SHA-256, état on-chain, votes, transactions, événements Solidity | soumettre (émetteur), voter (validateurs éligibles), finaliser, vérifier l'intégrité |
| **Fiabilité & réputation** | jauge S, contributions R/Q/V, détail de Q, pénalités, historique ; réputations comparées, évolution, explications | — |
| **Corrélation** | graphe des relations (couleur = catégorie, contour = statut), tableau des liens et justifications | seuil, pondérations, recalcul |
| **Documentation** | architecture, fonctionnement, évaluation ML/NLP, informations techniques, limites | — |

## Scénario de démonstration (≈ 10 minutes)

Préparation : pile démarrée avec MISP, `/api/v1/health` tout vert. Variante automatique :
`python scripts/run_demo_scenario.py` (20 étapes + contrôles de robustesse, résultat dans
`docs/test-reports/demo_scenario_run.json`).

1. **Org A** — *Importation CTI* → *Données de démonstration* → `01_orgA_phishing_report.txt` → Importer : IOC
   extraits (URL défangée normalisée, IP, domaine, MD5), doublons, phishing (~98 %), T1566.002 / T1566.001 justifiés,
   événement créé dans **MISP réel**.
2. *Analyse des menaces* : montrer probabilités, termes explicatifs, phrases sources des techniques, drapeaux
   (plages de documentation = données fictives).
3. *Gestion MISP* : l'événement, ses attributs (`to_ids=false`) et tags ATT&CK.
4. *Validation blockchain* (Org A) → **Soumettre** : empreinte SHA-256, transaction, statut PENDING.
5. **Org B** → voter **Approuver** → toujours PENDING (1/2) ; cliquer **Finaliser** → refus du contrat
   (`FinalizationTooEarly`). Org A n'a pas de bouton de vote (auto-validation interdite).
6. **Org C** → **Approuver** → finalisation automatique → **VALIDATED** ; **Vérifier l'intégrité** → hash recalculé
   = hash on-chain.
7. *Fiabilité & réputation* : S final (R, Q, V), réputation de A en hausse avec explication, comparaison on-chain.
8. **Org B** → importer `02_orgB_followup_shared_ioc.json` → *Corrélation* : lien avec le rapport de A
   (domaine commun, T1566.002, proximité temporelle) — « relation potentielle, pas une preuve ».
9. Robustesse (optionnel) : `04_orgA_malformed_and_duplicates.txt` (IOC mal formés, hash de fichier vide, adresse
   privée, infrastructure légitime) ; réimporter un fichier → `409` doublon ; basculer le thème clair/sombre.

Messages à garder pour le jury : un IOC valide n'est pas forcément malveillant ; une correspondance ATT&CK par
mots-clés est une proposition ; le score n'est pas une probabilité de véracité ; la blockchain prouve l'intégrité et la
traçabilité, pas la vérité ; les performances ML sont mesurées sur un corpus synthétique.
