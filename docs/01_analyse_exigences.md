# 01 — Analyse des exigences et traçabilité

Sources : *Cadrage_Projet_2i2ay.pdf* (note de cadrage, 12 p.) et *CDC_2I2AY.pdf* (cahier des charges v1.0, 11 p.).

## 1. Synthèse

**Problématique** : analyser, enrichir, valider et partager des renseignements CTI en garantissant intégrité,
traçabilité et évaluation explicable de leur fiabilité.

**Objectifs spécifiques (CDC 1.3)** : importer rapports et IOC ; extraire et normaliser les IOC ; détecter doublons et
incohérences ; classifier par type de menace ; enrichir avec MITRE ATT&CK ; stocker dans MISP ; valider
collaborativement par blockchain ; calculer un score de fiabilité explicable ; gérer la réputation des organisations ;
corréler les rapports.

**Contraintes** : prototype de 4–5 semaines, trois organisations simulées, Ethereum local (Hardhat), séparation
on-chain/off-chain, aucune garantie de véracité, données de test, reproductibilité (Docker Compose).

**Exclusions (cadrage 7.3)** : pas de SecureBERT entraîné de zéro, pas d'IDS complet, pas de Proof-of-Quality complet,
pas de blockchain publique, pas de réseau multi-organisations réel, pas de réponse automatisée en production, pas de
garantie de détection de tous les faux IOC.

## 2. Matrice de traçabilité

| ID | Exigence (source) | Priorité | Module / fichiers | Vérification |
|---|---|---|---|---|
| F01 | Importer un rapport (TXT, PDF, JSON, saisie, événement MISP) — CDC 12, cadrage 4.1 | MVP | `nlp/document_parser.py`, `api/routes/reports.py` (`POST /reports`, `/upload`, `/import-misp`) | `test_units.py` (parseurs), `test_api.py`, import UI |
| F02 | Extraire et normaliser les IOC (IPv4, domaines, URL, MD5, SHA-256) — CDC 5.1 | MVP | `nlp/ioc_extractor.py`, `nlp/normalizer.py`, `nlp/validators.py` | `test_ioc_extraction.py`, `evaluate_ioc_extraction.py` |
| F03 | Détecter les doublons — CDC 12, cadrage 4.2 | MVP | empreinte de texte (409), quasi-doublons TF-IDF, IOC déjà vus (BDD, MISP) — `services/report_service.py` | `test_api.py::test_import_detects_duplicates_and_conflicts` |
| F04 | Signaler les incohérences — CDC 12 | MVP | `nlp/consistency.py` (mal formés, infra légitime, catégorie contradictoire, rapport rejeté…) | tests + rapport n°4 de démo |
| F05 | Classifier les menaces (4 catégories) — CDC 4.3, 5.2 | MVP expérimental | `ml/train.py`, `ml/classifier.py`, `ml/baseline.py` | `metrics.json`, `test_units.py` |
| F06 | Enrichir avec MITRE ATT&CK, justification — CDC 6 | MVP | `mitre/catalog.py` (STIX officiel), `mitre/rules.py`, `mitre/enricher.py` | `test_units.py`, `evaluate_enrichment_correlation.py` |
| F07 | Intégrer MISP via PyMISP — CDC 7 | MVP | `misp/pymisp_adapter.py`, `misp/simulated.py`, `misp/factory.py` | `test_live_integration.py::test_live_misp_event_lifecycle` |
| F08 | Soumettre l'empreinte sur Ethereum — CDC 9 | MVP | `blockchain/contracts/CTIValidation.sol`, `app/blockchain/client.py`, `services/validation_service.py` | Hardhat + tests live |
| F09 | Enregistrer les votes (règles 9.3) | MVP | `voteReport`, `finalizeReport` | 21 tests Hardhat, `test_api.py` |
| F10 | Calculer la fiabilité S = 0,30R + 0,30Q + 0,40V — CDC 10.1 | MVP | `services/scoring.py` | `test_scoring_reputation.py` |
| F11 | Gérer la réputation — CDC 10.2 | Amélioration | `services/reputation.py` + réputation protocolaire on-chain | tests unitaires, scénario |
| F12 | Corréler les rapports — CDC 11 | Amélioration | `correlation/engine.py` | `test_units.py`, `evaluate_enrichment_correlation.py` |
| F13 | Tableau de bord — CDC 12 | MVP | `frontend/` (8 pages) | parcours navigateur, audit de contraste |
| NF01 | Intégrité (comparaison des empreintes) | — | `core/canonical.py`, `verifyIntegrity`, `GET /reports/{id}/integrity` | `test_integrity_failure_is_detected`, scénario |
| NF02 | Contrôle d'accès | — | clés API par organisation, `ensure_owner`, TLP:RED, règles Solidity | tests 401/403 |
| NF03 | Confidentialité (aucun rapport complet on-chain) | — | seuls hash + identifiants on-chain | revue du contrat |
| NF04 | Traçabilité | — | événements Solidity, `chain_transactions`, `audit_logs`, `reputation_events` | `GET /chain-events`, `/audit` |
| NF05 | Modularité | — | services séparés, adaptateurs MISP/chain | — |
| NF06 | Reproductibilité | — | Docker Compose, `.env.example`, `generate_env.py`, corpus déterministe | installation documentée |
| NF07 | Robustesse | — | gestion d'erreurs 400–503, MISP/chain indisponibles | tests de robustesse |
| — | Critères de réussite du cadrage (§9, 11 points) | — | voir [09_rapport_tests.md](09_rapport_tests.md) | scénario 20 étapes |

## 3. Contradictions et ambiguïtés — décisions

| # | Point | Cadrage | CDC | Décision et justification |
|---|---|---|---|---|
| 1 | Blockchain locale | Hardhat **ou** Ganache | Hardhat | **Hardhat** (CDC, plus récent ; Ganache n'est plus maintenu). |
| 2 | Classifieur | LogReg **ou** Random Forest | LogReg | **LogReg** retenu ; RF évalué comme *baseline* sur le même test. |
| 3 | Extraction | regex, spaCy « si nécessaire » | regex + validation | regex + validation syntaxique ; spaCy non nécessaire. |
| 4 | Réputation on-chain | listée on-chain | absente du tableau 3.3 | **deux niveaux** : réputation protocolaire bornée on-chain (tracée par événements) + réputation analytique off-chain (intègre la qualité, sert de R). |
| 5 | Stockage off-chain | MISP + base applicative | MISP | PostgreSQL = base opérationnelle (états, scores, audit) ; MISP = référentiel de partage CTI. |
| 6 | Critères de corrélation | IOC, MITRE, temps, **catégorie** | IOC, MITRE, **TF-IDF**, temps | union des deux listes (5 composantes pondérées configurables). |
| 7 | Taille du corpus | 15–30 rapports (S1) | 80, 20/catégorie | **80** (exigence la plus forte). |
| 8 | Statuts de validation | « règle simple » | PENDING → VALIDATED / REJECTED + « désaccord ou incomplet » | PENDING, VALIDATED, REJECTED, **DISPUTED**, **INCOMPLETE** (délai de vote dépassé). |
| 9 | Incohérences dans le score | facteur listé | formule R, Q, V uniquement | incohérences intégrées comme **pénalités de Q** (plafonnées à 40). |
| 10 | Arborescence | `backend/nlp …` | idem | modules sous `backend/app/` (paquet Python importable), conformément au prompt. |
| 11 | Signatures du contrat | conceptuelles | « à préciser » | `submitReport(bytes32, string externalId)` (identifiant off-chain), `previewFinalization`, `verifyIntegrity`, `getEligibleValidators` ajoutées. |
| 12 | Sources URLhaus / MalwareBazaar | — | listées | non intégrées (IOC réels) — environnement contrôlé ; documenté comme perspective. |

## 4. Exigences ajoutées en cours de projet (prompt)

* Interface : 8 pages, **thèmes sombre / clair** commutables, persistants entre pages et après rechargement.
* Robustesse face au redémarrage du réseau Hardhat en mémoire : détection des ancrages perdus (`chain_instance`).
* Jeu *challenge* indépendant pour l'évaluation de l'extraction.
