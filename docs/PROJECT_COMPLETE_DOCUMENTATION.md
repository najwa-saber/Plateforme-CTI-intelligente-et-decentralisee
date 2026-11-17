# Documentation complète du projet — dossier de soutenance

**Plateforme CTI intelligente et décentralisée** — PFE ENSA Marrakech. Référentiels : `CDC_2I2AY.pdf`,
`Cadrage_Projet_2i2ay.pdf`. Ce document relie toutes les pièces ; chaque chiffre renvoie à un fichier de preuve.

## 1. Problème et objectifs

Les organisations partagent du renseignement sur les menaces (CTI) sans moyen simple de juger sa fiabilité ni de
prouver qu'un rapport n'a pas été modifié. Objectifs :
1. analyser automatiquement un rapport (IOC, type de menace, techniques ATT&CK) ;
2. le partager dans le standard de la communauté (MISP) ;
3. le faire valider collectivement, de façon traçable et non falsifiable (smart contract Ethereum) ;
4. attribuer un score de fiabilité explicable et une réputation aux émetteurs ;
5. relier les rapports entre eux (corrélation).

## 2. Architecture

Voir [`ARCHITECTURE.md`](ARCHITECTURE.md) (vue logique, flux de données, déploiement, choix technologiques) et
[`02_architecture.md`](02_architecture.md) (séquences, séparation on-chain / off-chain, sécurité applicative).
Résumé : Streamlit → FastAPI (seul orchestrateur) → PostgreSQL (données), MISP (partage), Hardhat/Solidity
(intégrité, votes, réputation protocolaire). Tout tourne en Docker Compose, ports liés à `127.0.0.1`.

## 3. Fonctionnalités réalisées

| Fonction | Implémentation | Preuve |
|---|---|---|
| Import TXT / PDF / JSON / saisie / événement MISP | `nlp/` (parsing, contrôles de contenu, 5 Mo, 60 pages) | `test_api.py`, scénario étape 1 |
| Extraction et normalisation des IOC (IPv4, domaine, URL, MD5, SHA-256) | regex + refang + TLD IANA + drapeaux | F1 1,00 corpus, 0,984 jeu piégé |
| Déduplication | empreinte canonique SHA-256 (`cti-report/v1`) ; IOC dédoublonnés | `409` doublon testé |
| Classification | TF-IDF + régression logistique, explication par termes | `ML_EVALUATION.md` |
| Enrichissement ATT&CK | catalogue STIX v20.1 (706 techniques), 55 règles + similarité | P 0,62 / R 0,76 |
| Partage MISP | PyMISP, attributs `to_ids=false`, tags TLP / ATT&CK / statut | cohérence 12/12 |
| Validation décentralisée | `CTIValidation.sol` : soumission, votes, majorité, finalisation, pause | 21 tests Hardhat |
| Score de fiabilité | S = 0,30 R + 0,30 Q + 0,40 V | `test_scoring_reputation.py` |
| Réputation | analytique (PostgreSQL, explicable) + protocolaire bornée 10–90 (on-chain) | cohérence 12/12 |
| Corrélation | 5 critères pondérés (IOC, ATT&CK, texte, temps, catégorie), seuil 0,30 | P 1,00 / R 0,814 |
| Interface | 8 pages, thèmes sombre/clair, liens directs, responsive | 19 tests UI, audit mobile/tablette |
| Industrialisation | Docker Compose épinglé, locks, CI GitLab (13 jobs) | `clean_install.json`, `GITLAB_CI_CD.md` |

## 4. Résultats expérimentaux

| Mesure | Valeur | Fichier |
|---|---|---|
| Extraction IOC (80 rapports, 182 IOC) | précision 1,00, rappel 1,00 | `test-reports/ioc_extraction_eval.json` |
| Extraction IOC, jeu piégé (25 textes) | précision 0,968, rappel 1,00, F1 0,984 | idem |
| Classification, CV imbriquée groupée (25 plis) | macro-F1 0,876 ± 0,094 ; ROC-AUC 0,989 | `test-reports/ml_model_comparison.json` |
| Classification, test held-out (16) | accuracy 0,875, macro-F1 0,874 (IC 95 % [0,64 ; 0,965]) | idem |
| Classification, jeu externe réel ATT&CK (49) | macro-F1 1,00 (jeu lexicalement facile) | idem |
| Règles ATT&CK | P 0,623, R 0,762, F1 0,686 | `test-reports/enrichment_correlation_eval.json` |
| Corrélation (163 paires) | P 1,00, R 0,814, F1 0,897 | idem |
| Latence hors réseau | médiane 103,6 ms / rapport, p95 169,9 ms | `test-reports/pipeline_benchmark.json` |
| Scénario bout-en-bout | 24/24 étapes, 8,1 s (rejoué après la mise à jour) | `test-reports/demo_scenario_run.json` |
| Conformité CDC / cadrage | 66/74 exigences vérifiées (89,2 %), pondéré 93,9 % | `REQUIREMENTS_TRACEABILITY.md` |

Tests : backend 85, interface 19, contrat 21, live 4 — tous réussis (`TESTING_AND_VALIDATION.md`).

## 5. Décisions notables

* Modèle ML conservé après comparaison de 7 approches : aucune n'est significativement meilleure (t-test corrigé).
* Résultats d'analyse exclus de l'empreinte : un ré-entraînement ne casse pas la vérification d'intégrité.
* Règles métier (auto-validation, double vote, éligibilité, majorité) appliquées **par le contrat** ; le backend les
  simule par `eth_call` pour renvoyer une erreur claire.
* Identité d'ancrage = (instance de chaîne, id) pour résister aux redémarrages du nœud en mémoire (migration 0003).
* Dépendances : mise à jour de sécurité (FastAPI/Starlette, pypdf, Streamlit/Pillow, pytest) après `pip-audit`.

## 6. Limites (voir aussi [`10_limites.md`](10_limites.md))

* Corpus d'entraînement **synthétique** (80 rapports, auteur unique) : les métriques ML ne valent pas preuve sur des
  rapports réels ; le jeu externe est court et explicite.
* Règles ATT&CK : précision 0,62 — ce sont des propositions à valider par l'analyste.
* Blockchain locale (Hardhat en mémoire) : pas de consensus distribué réel, pas de persistance de la chaîne au redémarrage.
* Trois organisations simulées sur une seule machine ; pas de test de charge.
* Pondérations du score fixées par conception, sans analyse de sensibilité.
* CI GitLab non encore exécutée sur un runner réel (aucun commit ni dépôt GitLab à ce jour).

## 7. Perspectives

Corpus réel annoté (rapports publics, URLhaus, MalwareBazaar) ; modèles pré-entraînés spécialisés si le corpus le
justifie ; réseau Ethereum de test persistant (Sepolia) ou permissionné ; signature des rapports par organisation ;
analyse de sensibilité du score ; export STIX 2.1 / TAXII ; multi-étiquettes.

## 8. Scénarios de démonstration

* Scénario guidé de 10 minutes : [`08_guide_utilisation.md`](08_guide_utilisation.md) (phishing de A, votes de B et C,
  intégrité, réputation, corrélation avec le rapport de B, robustesse).
* Variante automatique : `python scripts/run_demo_scenario.py` (écrit en base, dans MISP et sur la chaîne).
* Démonstrations sans écriture : tableau de bord, analyse, corrélation et vérification d'intégrité sur les rapports existants.

## 9. Questions probables du jury

| Question | Réponse courte |
|---|---|
| Pourquoi ne pas tout mettre sur la blockchain ? | confidentialité (TLP), coût, volume ; on ancre l'empreinte, ce qui suffit à prouver l'intégrité |
| La blockchain prouve-t-elle que le rapport est vrai ? | non : intégrité et traçabilité des votes ; la véracité reste un jugement collectif |
| Pourquoi un modèle simple ? | 80 textes : un modèle linéaire interprétable fait aussi bien que les autres testés, sans gain significatif |
| Que se passe-t-il si Hardhat redémarre ? | nouvelle instance détectée ; anciens ancrages marqués « instance précédente », aucune donnée perdue hors chaîne |
| Comment éviter qu'une organisation valide son propre rapport ? | erreur `SelfValidation` du contrat, testée |
| Comment est garantie la reproductibilité ? | images épinglées, locks, corpus déterministe, installation propre testée, CI |

## 10. Index des documents

| Besoin | Document |
|---|---|
| Installer | [`INSTALLATION_GUIDE.md`](INSTALLATION_GUIDE.md), [`06_installation.md`](06_installation.md), [`07_troubleshooting.md`](07_troubleshooting.md) |
| Utiliser | [`USER_GUIDE.md`](USER_GUIDE.md), [`08_guide_utilisation.md`](08_guide_utilisation.md) |
| Comprendre | [`ARCHITECTURE.md`](ARCHITECTURE.md), [`02`](02_architecture.md), [`03_blockchain.md`](03_blockchain.md), [`04_api.md`](04_api.md) |
| Évaluer | [`ML_EVALUATION.md`](ML_EVALUATION.md), [`05_evaluation.md`](05_evaluation.md), [`TESTING_AND_VALIDATION.md`](TESTING_AND_VALIDATION.md) |
| Sécurité | [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md), [`GIT_SECURITY_AUDIT.md`](GIT_SECURITY_AUDIT.md) |
| Industrialiser | [`GITLAB_CI_CD.md`](GITLAB_CI_CD.md), [`DATABASE_MIGRATION_AUDIT.md`](DATABASE_MIGRATION_AUDIT.md) |
| Conformité et bilan | [`REQUIREMENTS_TRACEABILITY.md`](REQUIREMENTS_TRACEABILITY.md), [`FINAL_PROJECT_REPORT.md`](FINAL_PROJECT_REPORT.md) |
