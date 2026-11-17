# Tests et validation

Règle : un résultat n'est listé ici que s'il a été **réellement exécuté** ; la date, la commande et le fichier
de preuve sont indiqués. Ce qui n'a pas été exécuté est marqué comme tel.

## 1. Synthèse (17/11/2026)

| Domaine | Commande | Résultat | Preuve |
|---|---|---|---|
| Backend (API, NLP, ML, MITRE, MISP simulé, scoring, réputation, ancrage, migrations) | `cd backend && pytest -m "not live_chain and not live_misp" --cov=app` | **85 réussis**, 0 échec ; couverture **76 %** (3 316 instructions) ; rejoué après la mise à jour de sécurité des dépendances : 85 réussis | `test-reports/pytest-backend.xml` |
| Interface (8 pages × 2 thèmes + 3 tests) | `pytest frontend/tests` | **19 réussis** en 12,8 s puis 10,0 s (après corrections responsive), puis 25,0 s avec Streamlit 1.67 / Pillow 13 | `test-reports/pytest-frontend.xml` |
| Contrat Solidity | `npx hardhat test` (conteneur jetable, réseau in-process) | **21 passing** | `test-reports/hardhat-test.log` |
| Installation propre | build 3 images depuis une copie des seuls fichiers versionnables + pytest dans l'image neuve | build OK (152 s), **85 réussis** dans l'image | `test-reports/clean_install.json` |
| Responsive (mobile 375 px, tablette 768 px, 820 px, 1 366 px) | navigateur, émulation d'appareil | 8/8 pages sans débordement de page ni exception après 3 corrections, revérifié avec Streamlit 1.67 | `test-reports/responsive_audit.json` |
| Cohérence inter-services (API ↔ PostgreSQL ↔ contrat ↔ MISP) | `python scripts/verify_consistency.py` | **12/12** contrôles | `test-reports/consistency_check.json` |
| Ancrages blockchain | `python scripts/audit_chain_anchors.py` | aucun doublon de tx, aucun rapport historique lié à la chaîne actuelle | `test-reports/chain_anchor_audit.json` |
| Scénario de démonstration bout-en-bout | `python scripts/run_demo_scenario.py`, rejoué le 17/11 10:53 UTC **après** la mise à jour des dépendances (autorisé) | **24/24 étapes**, 8,1 s (MISP réel : événement 17 ; chaîne : id 4, VALIDATED 2/2) | `test-reports/demo_scenario_run.json` (exécution précédente conservée : `demo_scenario_run_2026-11-17T0824.json`) |
| Extraction IOC | `backend/scripts/evaluate_ioc_extraction.py` | corpus 182 IOC : P = R = 1,00 ; jeu « challenge » (25 textes piégés) : P 0,968, R 1,00, F1 0,984 | `test-reports/ioc_extraction_eval.json` |
| Enrichissement MITRE / corrélation | `backend/scripts/evaluate_enrichment_correlation.py` | règles ATT&CK : P 0,623, R 0,762, F1 0,686 ; corrélation (seuil 0,30, 163 paires) : P 1,00, R 0,814, F1 0,897 | `test-reports/enrichment_correlation_eval.json` |
| ML (7 modèles, CV imbriquée, test, externe) | `python -m app.ml.experiments` | voir `ML_EVALUATION.md` | `test-reports/ml_model_comparison.json` |
| Latence hors réseau | `backend/scripts/benchmark_pipeline.py` | médiane 103,6 ms / rapport, p95 169,9 ms | `test-reports/pipeline_benchmark.json` |
| Secrets | gitleaks v8.21.2 sur les 259 fichiers versionnables + recherche des valeurs réelles du `.env` | aucune fuite | `SECURITY_AUDIT.md` |
| Dépendances | pip-audit 2.7.3 sur les deux locks | 5 paquets vulnérables → **0** après mise à jour | `test-reports/pip-audit-{b,f}.json` |
| Lint | ruff 0.8.4 (backend, frontend, scripts) | 15 avertissements corrigés → « All checks passed! » ; sorties des scripts de données identiques octet par octet | — |
| Installation combinée des deux locks (cas CI) | `pip install -r … -c backend/requirements.lock -r … -c frontend/requirements.lock` en conteneur neuf | OK, `pip check` sans conflit ; 85 tests ; porte ML PROMOTABLE (macro-F1 0,874) | — |

## 2. Tests *live* (services réels) — 4/4 réussis le 17/11 (autorisés)

`backend/tests/test_live_integration.py` (4 tests, marqueurs `live_chain` / `live_misp`) :

| Test | Effet de bord | État |
|---|---|---|
| `test_live_misp_unknown_event_is_404` | **lecture seule** (GET d'un événement inexistant sur MISP réel) | réussi |
| `test_live_contract_full_validation_flow` | déploie un **nouveau** contrat CTIValidation sur le nœud Hardhat en service (ajoute des blocs ; le contrat de la plateforme n'est pas modifié) | réussi |
| `test_live_contract_duplicate_and_disputed` | idem | réussi |
| `test_live_misp_event_lifecycle` | **crée, étiquette, recherche puis supprime** un événement sur l'instance MISP réelle | réussi |

Commande : `cd backend && pytest -m "live_chain or live_misp"` → **4 passed en 11,96 s** (`test-reports/pytest-live.xml`).
Après ces écritures : cohérence 12/12 sur le nouveau rapport, audit des ancrages OK, contrat de la plateforme inchangé (même adresse, même instance, 4 rapports on-chain), schéma `0003`.

## 3. Collision des identifiants on-chain — cause, correction, tests

* **Cause** : Hardhat (réseau en mémoire) repart de zéro quand le nœud redémarre ; le contrat est redéployé à la
  **même adresse** et les identifiants de rapport recommencent à 1. Un rapport historique « id 1 » et un nouveau
  rapport « id 1 » désignaient donc deux objets différents.
* **Correction** : l'identité d'un ancrage est le couple *(instance de chaîne, id)* ; l'instance est le hash du bloc
  de déploiement du contrat. Colonne `chain_instance` sur les transactions, index unique partiel
  `uq_reports_chain_anchor` (migration **0003**, conservée), vérification de l'instance, de l'`externalId` et du
  soumissionnaire avant toute lecture d'état on-chain. Les rapports ancrés sur une instance précédente sont affichés
  « ⚠ instance précédente (non vérifiable) » ; **aucune donnée historique n'a été réécrite**.
* **Tests** : `backend/tests/test_chain_anchor_identity.py` (13 tests), `tests/test_migrations.py` (schéma 0001→0003 =
  modèles), `frontend/tests/test_pages.py::test_blockchain_page_shows_anchor_state`, audit
  `scripts/audit_chain_anchors.py` (2 rapports historiques correctement classés « previous_instance », 3 rapports
  actuels concordants).

## 4. Corrections apportées pendant la validation de l'interface

| Problème constaté | Correction | Vérification |
|---|---|---|
| Barre latérale forcée ouverte, recouvrant le contenu sur téléphone | `frontend/app.py` : `initial_sidebar_state="auto"` | mobile : `aria-expanded=false` à l'ouverture |
| Étiquettes MISP longues (sha256, galaxies) débordant de l'écran | `components/theme.py` : retour à la ligne des `.cti-badge` sous 800 px | 13 badges, 0 débordement, `scrollWidth = 375` |
| Cartes KPI et graphiques écrasés entre ~800 et 1 200 px (barre latérale ouverte), libellés coupés en milieu de mot | `components/theme.py` : retour à la ligne des colonnes sous 1 200 px (min. 140 px pour les cartes, 260 px sinon) | 820 px : 3 cartes de 149 px par ligne ; 1 366 px : inchangé (6 × 136 px) |
| Timeout ponctuel d'un test UI (163 s) | aucune : dû à la charge d'un build Docker parallèle | 2 exécutions suivantes 19/19 en 10–13 s |

## 5. Non couvert / limites des tests

* CI GitLab jamais exécutée sur un runner GitLab (fichier validé localement uniquement).
* Démarrage complet des images neuves (MISP + PostgreSQL + nœud) non fait pour ne pas créer une seconde instance MISP.
* Pas de test de charge multi-utilisateurs ; pas de test navigateur réel automatisé (AppTest = rendu serveur).
* Couverture 76 % : les chemins non couverts sont surtout les adaptateurs réseau réels (PyMISP, Web3), couverts par les tests *live*.

## 6. Rejouer

```bash
cd backend && ../.venv/Scripts/python -m pytest -q -m "not live_chain and not live_misp" --cov=app
```
```bash
./.venv/Scripts/python -m pytest -q frontend/tests
```
```bash
docker run --rm --network none --entrypoint npx cticlean-hardhat hardhat test
```
```bash
./.venv/Scripts/python scripts/verify_consistency.py
```
