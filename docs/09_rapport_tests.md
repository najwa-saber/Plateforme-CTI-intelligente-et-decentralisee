# 09 — Rapport des tests réellement exécutés (2026-11-16)

> Rapport historique. Les résultats à jour (17/11/2026) sont dans [`TESTING_AND_VALIDATION.md`](TESTING_AND_VALIDATION.md).

| Campagne | Commande | Résultat |
|---|---|---|
| Tests Python (unitaires, robustesse, API, *live* Hardhat + MISP réel) | `cd backend && pytest -q` | **69 passed**, 0 skipped |
| Tests du contrat Solidity | `npx hardhat test` (image node:22) | **21 passing** |
| Scénario de démonstration (20 étapes + 4 contrôles de robustesse) sur la pile Docker, MISP réel | `python scripts/run_demo_scenario.py` | **24/24 PASS**, 4,3 s — `test-reports/demo_scenario_run.json` |
| Extraction IOC — corpus / *challenge* indépendant | `python scripts/evaluate_ioc_extraction.py` | P=R=1,000 / **P=0,968 R=1,000** — `test-reports/ioc_extraction_eval.json` |
| ATT&CK (règles) et corrélation | `python scripts/evaluate_enrichment_correlation.py` | ATT&CK P=0,623 R=0,762 ; corrélation P=1,000 R=0,814 |
| Classifieur | `python -m app.ml.train` | test acc. 0,875, macro-F1 0,874 ; CV groupée 0,881 ± 0,082 |
| Interface — parcours navigateur | import (TXT, JSON, doublon 409, rapport bruité), analyse, soumission, votes A/B → DISPUTED, intégrité, rapport ancré sur une chaîne précédente | conforme |
| Interface — thèmes | audit automatique de contraste WCAG (texte HTML et SVG) sur les 8 pages × 2 thèmes ; zones claires en sombre / sombres en clair ; persistance navigation + rechargement ; conservation des sélections | 0 défaut réel restant (faux positifs justifiés : emoji, valeur de curseur, groupes SVG) |
| Conteneur frontend Docker | chargement des 8 pages en thème sombre | 0 exception, titres corrects |
| Santé des services | `GET /api/v1/health`, `docker compose ps` | 10 services sains (hors one-shot `misp-certs`) |

## Couverture des critères de réussite du cadrage (§9)

| Critère | Preuve |
|---|---|
| 1. importer et analyser un rapport | scénario étapes 1–7, `test_api.py` |
| 2. extraire et normaliser des IOC | `test_ioc_extraction.py`, évaluations |
| 3. détecter au moins un doublon | 409 doublon exact, IOC connus inter-rapports, quasi-doublons |
| 4. créer un événement MISP | scénario étape 7 (MISP réel), test *live* |
| 5. soumettre l'empreinte sur Ethereum | scénario étapes 8–9 |
| 6. enregistrer des votes autorisés | étapes 11–13, tests Hardhat |
| 7. bloquer les doubles votes | test Hardhat, scénario (409) |
| 8. vérifier l'intégrité | étape 15, `test_integrity_failure_is_detected` |
| 9. afficher statut et score | étapes 15–16, pages Blockchain / Fiabilité |
| 10. corrélation entre deux événements | étapes 18–19 |
| 11. expliquer l'évolution de la réputation | étape 17, historique expliqué |

## Anomalies trouvées et corrigées pendant la validation

Désynchronisation chaîne/BDD après redémarrage de Hardhat (détection `chain_instance`, migration 0002) ; verrou
SQLite de l'adaptateur MISP simulé ; titres Plotly « undefined » ; libellés tronqués ; lenteur `localhost` IPv6 ;
navigation brute Streamlit (`pages/` → `views/`) ; lien direct cassé par les paramètres d'URL ; tag TLP tronqué
(Markdown) ; tags de statut MISP cumulés au lieu d'être remplacés ; contrastes insuffisants en thème clair.
