# Matrice de conformité — CDC_2I2AY et Cadrage_Projet_2i2ay (audit du 17/11/2026)

Statuts : **TV** = terminé et vérifié · **INV** = implémenté mais non vérifié · **P** = partiellement implémenté ·
**NI** = non implémenté · **B** = bloqué. Les preuves renvoient à des fichiers du dépôt ou à des exécutions datées
(« audit » = relancé le 17/11 en lecture seule ; « antérieur » = exécution précédente documentée).

## A. Exigences fonctionnelles et non fonctionnelles du CDC (§12–13)

| ID | Exigence | Implémentation actuelle | Preuve | Statut | Travail restant |
|---|---|---|---|---|---|
| F01 | Importer un rapport CTI | TXT, PDF, JSON (+IOC déclarés), saisie, événement MISP — `nlp/document_parser.py`, `routes/reports.py` | `test_units.py` (parseurs), `test_api.py`, import réel MISP n°14 (antérieur) | TV | — |
| F02 | Extraire et normaliser les IOC | regex + validation, refang, IDN, IP canonique — `nlp/*` | 12 tests ; challenge P=0,968 R=1,00 | TV | IPv6/e-mail/SHA-1 hors périmètre |
| F03 | Détecter les doublons | empreinte texte (409), quasi-doublons TF-IDF, IOC connus BDD et MISP | `test_import_detects_duplicates_and_conflicts` ; UI (409) | TV | — |
| F04 | Signaler les incohérences | `nlp/consistency.py` (11 types d'anomalies) | tests, rapport démo n°4 | TV | — |
| F05 | Classifier les menaces (MVP expérimental) | TF-IDF + LogReg entraîné, repli mots-clés | recalcul audit : 14/16 ; `metrics.json` | TV | pas meilleur que la baseline (p=1,00) |
| F06 | Enrichir avec MITRE ATT&CK | STIX officiel v20.1, 55 règles, similarité, justification + phrase source | tests ATT&CK, P=0,623 R=0,762 | TV | — |
| F07 | Intégrer MISP | PyMISP (événements, attributs, tags, recherche, lecture), adaptateur simulé | tests *live* (antérieur), cohérence MISP (audit) | TV | épingler la version des images |
| F08 | Soumettre sur Ethereum | `submitReport` via Web3.py, instance mémorisée | Hardhat 21 (audit), *live* (antérieur), cohérence (audit) | TV | — |
| F09 | Enregistrer les votes | `voteReport`, finalisation automatique | Hardhat + `test_api` + scénario | TV | — |
| F10 | Calculer la fiabilité | `services/scoring.py` (S=0,30R+0,30Q+0,40V) | `test_scoring_reputation.py`, cohérence score (audit) | TV | voir C10.1 |
| F11 | Gérer la réputation (amélioration) | protocolaire on-chain + analytique bornée | tests, cohérence réputation (audit) | TV | — |
| F12 | Corréler les rapports (amélioration) | `correlation/engine.py`, 5 critères pondérés | tests ; P=1,00 R=0,814 | TV | — |
| F13 | Tableau de bord | Streamlit 8 pages, thèmes | vérifications navigateur (manuel) | TV | tests automatisés d'interface absents |
| NF01 | Intégrité | SHA-256 canonique + `verifyIntegrity` | `test_integrity_failure_is_detected`, cohérence (audit) | TV | — |
| NF02 | Contrôle d'accès | clés API, propriétaire, TLP:RED, règles Solidity | tests 401/403, Hardhat | TV | — |
| NF03 | Confidentialité (rien de complet on-chain) | seuls hash + identifiants on-chain | revue du contrat, `docs/03_blockchain.md` | TV | — |
| NF04 | Traçabilité | événements Solidity, transactions, audit, historique réputation | `/chain-events`, `/audit`, audit des ancrages | TV | — |
| NF05 | Modularité | services + adaptateurs séparés | structure du dépôt | TV | — |
| NF06 | Reproductibilité | Docker Compose, images épinglées par digest, `requirements.lock`, corpus déterministe | installation depuis les seuls fichiers versionnables : build OK, 85 tests dans l'image neuve (`test-reports/clean_install.json`, 17/11) | TV | démarrage complet de la pile neuve (MISP) non rejoué |
| NF07 | Robustesse | gestion 400–503, MISP/chaîne indisponibles | tests de robustesse | TV | — |

## B. Exigences détaillées du CDC

| ID | Exigence | Implémentation actuelle | Preuve | Statut | Travail restant |
|---|---|---|---|---|---|
| C4.1 | Corpus hybride (extraits publics, IOC publics, ATT&CK, synthétique) | synthétique + descriptions ATT&CK uniquement | `data/README.md` | P | ajouter des extraits publics annotés |
| C4.2 | Licences, dates, provenance par source | documentées pour ATT&CK et IANA | `data/README.md` | P | URLhaus/MalwareBazaar non intégrés |
| C4.3 | 4 catégories | phishing, ransomware, malware, exploitation | `reports.jsonl` | TV | — |
| C4.4 | 80 extraits, 20/catégorie | 80 / 20 | `reports.jsonl` (80 lignes) | TV | — |
| C4.5 | Arborescence des données | conforme | `data/` | TV | — |
| C4.6 | Schéma `reports.jsonl` | conforme + `ambiguous`, `notes` | fichier | TV | — |
| C4.7 | Schéma `iocs.csv` | conforme (`unknown`) | fichier (182 IOC) | TV | — |
| C4.8 | Schéma `relations.csv` | conforme (163 paires) | fichier | TV | négatifs « faciles » |
| C4.9 | Règles d'annotation (catégorie **justifiée**, cas ambigus, pas de fuite de campagne) | ambigus marqués, découpage groupé | `build_corpus.py` (assertion anti-fuite) | P | justification de catégorie par rapport absente |
| C5.1 | Extraction IOC + validation | conforme | tests | TV | — |
| C5.4 | Métriques, 60/20/20, TF-IDF sur apprentissage seul | conforme | `train.py`, recalcul audit | TV | — |
| C6.2 | Règles + justification textuelle, non probante | conforme | tests, UI | TV | — |
| C7.2 | PyMISP : créer, ajouter, rechercher, récupérer, tags | conforme | tests *live* | TV | — |
| C7.3 | MISP Docker + adaptateur simulé temporaire | conforme | `docker-compose.yml`, `misp/simulated.py` | TV | — |
| C8.1 | 10 endpoints du contrat initial | conformes (+ complémentaires) | `/docs`, `test_api.py` | TV | — |
| C8.4 | Codes 400/401/403/404/409/422/500, organisation authentifiée | conforme (+413, 503) | tests, audit des erreurs | TV | — |
| C9.1 | Hardhat local, une adresse par organisation | conforme | `deploy.js`, cohérence | TV | réseau en mémoire |
| C9.2 | 6 fonctions prévues | présentes (+ vues complémentaires) | `CTIValidation.sol` | TV | — |
| C9.3 | Règles 1–5 (autorisés, un vote, pas d'auto-validation, majorité, journalisation) | dans le contrat | 21 tests Hardhat (audit) | TV | — |
| C9.4 | Cycle PENDING→VALIDATED/REJECTED + désaccord / incomplet | + DISPUTED, INCOMPLETE | tests Hardhat | TV | — |
| C9.5 | Empreinte canonique identique soumission / vérification | `core/canonical.py` | tests, cohérence | TV | — |
| C10.1 | Score, composantes normalisées, pondérations **justifiées et testées**, pas une probabilité | formule implémentée, avertissement affiché | tests de la formule | P | aucune analyse de sensibilité des pondérations |
| C10.2 | Réputation neutre, bornes contre variations/manipulations | conforme | tests | TV | — |
| C11.2 | Critères de corrélation | IOC, ATT&CK, TF-IDF, temps (+catégorie) | tests | TV | — |
| C11.3 | Interprétation prudente + évaluation via `relations.csv` | conforme | `enrichment_correlation_eval.json` | TV | — |
| C14 | Dépôt GitHub officiel, branches, PR, aucun secret versionné | `git init`, `.gitignore`, scan des secrets ; aucun commit, aucun dépôt distant | `git status` | B | autorisation de commit / push requise |
| C16 | Tests NLP/ML, blockchain (7 cas), intégration | conformes | sections ci-dessus | TV | — |
| C17 | Risques et mesures | traités et documentés | `docs/07`, `docs/10` | TV | — |
| C18.2 | Corpus annoté **et guide d'annotation** | corpus + règles dans `data/README.md` | — | P | guide d'annotation dédié |
| C18.9 | Démonstration finale **et rapport** | démonstration prête ; rapport/mémoire non rédigé | `docs/08` | P | rédiger le rapport final |

## C. Cadrage

| ID | Exigence | Implémentation actuelle | Preuve | Statut | Travail restant |
|---|---|---|---|---|---|
| K4.1 | Importer rapports ou événements MISP | conforme | import MISP n°14 (antérieur) | TV | — |
| K4.2 | Format, normalisation, IOC déjà enregistrés, **renseignements contradictoires**, signalement | contradictions = IOC d'un rapport rejeté, catégorie déclarée ≠ prédite | tests | P | contradictions entre rapports (ex. IOC jugé bénin ailleurs) |
| K4.5 | Soumission, validateurs, votes, double vote, finalisation | conforme | Hardhat | TV | — |
| K4.7 | Réputation : pas d'auto-validation, variations limitées, pas de domination | conforme | tests | TV | — |
| K4.8 | Corrélation IOC, ATT&CK, temps, catégorie | conforme | tests | TV | — |
| K5 | Scénario de démonstration (11 étapes) | scénario 20 étapes | `demo_scenario_run.json` 24/24 (antérieur) | TV | — |
| K7.1 | MVP (8 points) | tous présents | sections A/B | TV | — |
| K7.2 | Améliorations prioritaires (4) | réputation, corrélation, ML, graphe | UI, tests | TV | — |
| K9.1–K9.11 | 11 critères de réussite | tous démontrés par le scénario et les tests | `docs/09_rapport_tests.md` | TV ×11 | — |
| K9-E1 | Précision/rappel de l'extraction sur corpus annoté | mesurés (corpus + challenge) | `ioc_extraction_eval.json` | TV | — |
| K9-E2 | Performances du classifieur | mesurées | `metrics.json`, recalcul audit | TV | — |
| K9-E3 | **Temps de traitement** | latence par étape hors réseau (80 rapports) + durée du scénario bout-en-bout | `test-reports/pipeline_benchmark.json` (médiane 103,6 ms/rapport), `demo_scenario_run.json` (9,6 s) | TV | MISP/Ethereum mesurés globalement seulement |
| K9-E4 | Bon fonctionnement des contrats | Hardhat + *live* | — | TV | — |
| K9-E5 | Cohérence validation / corrélation | cohérence 12/12 + évaluation corrélation | rapports JSON | TV | — |

## D. Calcul du taux de conformité

Unité de compte : une ligne = une exigence (les 11 critères de réussite du cadrage comptent pour 11 lignes).
Total : 20 (A) + 30 (B) + 24 (C, avec K9.1–K9.11 développés) = **74 exigences**.

| Statut | Nombre |
|---|---|
| TV (terminé et vérifié) | 66 |
| INV | 0 |
| P | 7 (C4.1, C4.2, C4.9, C10.1, C18.2, C18.9, K4.2) |
| NI | 0 |
| B | 1 (C14) |

* **Taux strict** (TV / total) = 66 / 74 = **89,2 %** (86,5 % à l'audit initial).
* **Taux pondéré** (TV = 1 ; INV = 0,75 ; P = 0,5 ; NI = B = 0) = (66 + 3,5) / 74 = **93,9 %** (92,9 % à l'audit initial).
* Mise à jour du 17/11/2026 : NF06 (installation propre vérifiée) et K9-E3 (benchmark par étape) passent de INV/P à TV.
* **Exigences MVP du CDC (F01–F10, F13, 11 lignes)** : 11/11 TV = **100 %**.

Aucune exigence n'est entièrement non implémentée ; les écarts portent sur la nature des données (corpus
synthétique), la justification scientifique (pondérations, temps de traitement), des livrables documentaires
(guide d'annotation, rapport final) et le versionnement (en attente d'autorisation).
