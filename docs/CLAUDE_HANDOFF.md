# Transfert de contexte — Plateforme CTI intelligente et décentralisée

**Rédigé le 17/11/2026 (≈ 09:10 UTC)**, à la fin d'une session dont le contexte était saturé.
Ce document permet à une nouvelle discussion de reprendre **exactement** là où le travail s'est arrêté.
Chaque affirmation est accompagnée de sa preuve (fichier, commande, rapport). Ce qui n'a pas pu être vérifié est
signalé **[NON VÉRIFIÉ]**. **Le projet n'est pas terminé.**

Racine du projet : `C:\Users\najwa\Downloads\ia avancee\prj\intelligent-decentralized-cti`
Suivi d'avancement associé : [`docs/FINALIZATION_PROGRESS.md`](FINALIZATION_PROGRESS.md).

---

## 000. ÉTAT FINAL CI (17/11/2026)

Pipeline #3079286060 (`5e7b224`) : statut « success », 10/10 jobs automatiques, et le job manuel `integration:stack` **réussi** (140 s) : pile neuve construite sur le runner (PostgreSQL, Hardhat, backend), santé « ok » sur les 5 composants (MISP en mode simulé), scénario de démonstration **24/24 étapes** réussi. `main` = `5e7b224` sur GitLab et GitHub.

## 00. DERNIER ÉTAT (17/11/2026, après push)

Historique Git : `05b64df` (initial, sans ligne Co-Authored-By) → `ff9a580` (correctif CI) → `4d10748` (suivi), identique sur GitLab (`origin`, privé, ID 89054342) et GitHub (`github`). Ne jamais ajouter de ligne Co-Authored-By.
CI : pipeline GitLab **#3078904924** (commit `4d10748`, 17/11/2026, 6 min 51 s) : les 10 jobs automatiques réussis — validate, lint, secrets (gitleaks), dépendances (pip-audit : « No known vulnerabilities found »), tests Python (85 réussis, couverture 76 %), Hardhat (21 passing), `ml:data-validation` (corpus régénéré identique, PROMOTABLE), `ml:train-candidate` (empreinte enregistrée = empreinte courante, PROMOTABLE), build des 3 images. Correctif suivant (statut « manuel ») dans `.gitlab-ci.yml`, non encore commité/poussé au moment de cette note. Push forcé sur `main` GitLab : désactivé (protection normale).

## 0. MISE À JOUR — fin de la session « mission finale » (17/11/2026) — À LIRE EN PREMIER

Cette section **remplace** les §4 (phases), §9 (problèmes) et §11 (prochaines étapes) ci-dessous, conservés comme historique.
Bilan complet et preuves : [`FINAL_PROJECT_REPORT.md`](FINAL_PROJECT_REPORT.md), [`TESTING_AND_VALIDATION.md`](TESTING_AND_VALIDATION.md).

**Fait et prouvé dans cette session** : tests UI hors charge 19/19 ; gitleaks 0 fuite (259 fichiers) ; installation
propre OK (`test-reports/clean_install.json`) ; 3 corrections responsive (`frontend/app.py`, `components/theme.py`) ;
Hardhat 21 passing ; test *live* MISP lecture seule réussi ; ruff « All checks passed! » (15 corrections) ; mise à jour de
sécurité des dépendances (pip-audit : 5 paquets vulnérables → 0) avec locks alignés backend/frontend ; conteneurs
backend et frontend reconstruits `--no-deps` (PostgreSQL, Hardhat, MISP intacts, aucune migration appliquée) ;
re-tests après mise à jour : backend 85/85 (cov 76 %), UI 19/19, cohérence 12/12, ancrages OK, porte ML PROMOTABLE
(macro-F1 0,874) ; CI : étapes `lint`/`ml-validation`, 13 jobs validés localement ; documentation phase 8 complète ;
conformité 66/74 (89,2 %).

**Versions en service** : fastapi 0.163.1, starlette 1.10.0, pypdf 6.21.4, uvicorn 0.54.0, numpy 2.4.6,
scikit-learn 1.6.1, streamlit 1.67.0, pillow 13.0.0, pytest 9.2.0 (venv local aligné sur les mêmes locks).
Sauvegardes des anciens `requirements*` et README : dossier scratchpad de la session (temporaire, hors dépôt).

**Écritures réelles vérifiées après la mise à jour (autorisées, 17/11 10:53 UTC)** : scénario 24/24 (rapport
CTI-A25476F0FE, MISP événement 17, on-chain id 4 VALIDATED) ; tests *live* 4/4 ; cohérence 12/12 ; ancrages OK.
État base : schéma 0003, 13 rapports, 24 transactions.

**Prochaines étapes (toutes soumises à autorisation)** :
1. ~~scénario de démonstration~~ : fait (24/24) ;
2. ~~tests live~~ : faits (4/4) ;
3. ~~commit initial~~ : fait, `1aa1d38` sur `main` (263 fichiers ; les mises à jour de suivi postérieures ne sont pas encore commitées) ;
3 bis. (ancien libellé) commit initial (message dans `FINAL_PROJECT_REPORT.md` §4) ;
4. projet GitLab + `git remote add` + `git push` → premier pipeline ; consigner son identifiant et son résultat ;
5. facultatif : promotion du modèle candidat, suppression des images `cticlean-*`.

Précautions inchangées : §1 ci-dessous. Ne jamais recréer le conteneur `hardhat` ; reconstruire seulement avec
`docker compose up -d --build --no-deps backend frontend`. Réseau lent (~200 kB/s) : une reconstruction complète des
dépendances prend ~10–14 min.

---

## 1. Règles impératives (fixées par l'utilisatrice, toujours en vigueur)

* **Aucun commit, aucun push, aucun déploiement** sans autorisation explicite.
* **Migration 0003** : la conserver telle quelle (appliquée en base). Aucun rollback, aucune nouvelle migration sans accord.
* **Ne pas supprimer / vider / réinitialiser** : PostgreSQL, Hardhat (le nœud tourne depuis ~14 h, ses données font foi),
  MISP, rapports, données historiques, fichiers.
* **Ne pas écraser le modèle ML déployé** (`backend/app/ml/artifacts/classifier.joblib`) sans comparaison et accord.
* **Tests *live*** (écriture MISP / blockchain) et **rejeu du scénario de démo** : demander l'autorisation avant.
* **Ne jamais fabriquer** un résultat, une métrique ou un statut de test ; ne déclarer « fait » qu'avec preuve.
* Ne jamais exposer `.env`, clés API, mots de passe.
* Toute action destructive, irréversible ou externe : la présenter et attendre l'accord.
* Économie de tokens : analyses ciblées, pas de répétition des tâches déjà validées.

## 2. Contexte et objectifs

Projet académique ENSA Marrakech (projet du module IA avancée et Blockchain, « Plateforme CTI intelligente et décentralisée »), cahier des charges
`CDC_2I2AY.pdf` + `Cadrage_Projet_2i2ay.pdf` (dans `prj/`). Trois organisations simulées A/B/C partagent des
rapports CTI : extraction d'IOC, classification ML, enrichissement MITRE ATT&CK, publication MISP, validation
collective sur Ethereum (Hardhat local), score de fiabilité `S = 0.30R + 0.30Q + 0.40V`, réputation, corrélation,
interface Streamlit 8 pages (thèmes sombre/clair or champagne), scénario de démonstration en 20 étapes.

Mission en cours : **« MISSION GLOBALE — FINALISATION COMPLÈTE »**, 8 phases (voir §4).

## 3. Architecture et technologies (état réel)

| Couche | Technologie | Emplacement |
|---|---|---|
| API | FastAPI, Pydantic v2, SQLAlchemy 2, Alembic (0001→0003), X-API-Key SHA-256 par organisation | `backend/app/` |
| Base | PostgreSQL 16 (Docker) ; SQLite pour les tests | `backend/alembic/versions/` |
| NLP | regex + refang + liste TLD IANA, empreinte canonique SHA-256 `cti-report/v1` | `backend/app/nlp/`, `core/canonical.py` |
| ML | TF-IDF (1-2 grammes) + Régression logistique (C=100, balanced) ; baseline mots-clés | `backend/app/ml/` |
| MITRE | catalogue STIX ATT&CK v20.1 (706 techniques), 55 règles regex + similarité TF-IDF | `backend/app/mitre/` |
| MISP | MISP 2.5.51 (misp-docker : core + nginx:8443 + db + redis + modules), PyMISP, adaptateur simulé de secours | `backend/app/misp/` |
| Blockchain | Solidity `CTIValidation` (Ownable, Pausable, OZ 5.4.0), Hardhat 2.29.2, Web3.py ; identité d'instance = hash du bloc de déploiement | `blockchain/`, `backend/app/blockchain/` |
| UI | Streamlit `st.navigation` (`frontend/views/`), Plotly, thème via `?theme=` | `frontend/` |
| Conteneurs | Docker Compose, images épinglées par digest, pip `-c requirements.lock` | `docker-compose.yml`, `docker/` |
| CI | `.gitlab-ci.yml` (12 jobs) — **jamais exécuté sur GitLab** | racine |

Documentation d'architecture existante : `docs/02_architecture.md`, `docs/03_blockchain.md`, `docs/04_api.md`.

## 4. État réel des 8 phases de la mission globale

Légende : ✅ terminé (preuve) · 🟡 partiel · ⏸ en attente d'autorisation · ⬜ non commencé

| # | Phase | État | Preuve / reste à faire |
|---|---|---|---|
| 1 | Audit Git, dépôt propre | 🟡 / ⏸ | `docs/GIT_SECURITY_AUDIT.md` ; `.gitignore` corrigé (`/reports/` au lieu de `reports/`), `.gitattributes` (LF) ajouté. Branche `main`, **0 commit, aucun remote, rien d'indexé**, **248** fichiers candidats (dont les 2 documents de transfert) (`git ls-files --others --exclude-standard`). Reste : re-scanner les secrets sur les fichiers ajoutés depuis l'audit, puis commit initial **⏸ autorisation**. |
| 2 | Stabilisation technique | 🟡 | Fait : digests d'images dans `docker-compose.yml` et `docker/*.Dockerfile` ; `backend/requirements.lock` (82 l.) et `frontend/requirements.lock` (39 l.) ; Dockerfiles installent avec `-c *.lock`. **Test d'installation propre INTERROMPU** : build `cticlean` arrêté pendant le téléchargement de scipy (~816 s, réseau ~180 kB/s) ; seule l'image `cticlean-hardhat` existe ; pytest dans l'image neuve **non exécuté**. Conteneurs en service **[NON VÉRIFIÉ]** : reconstruits ou non avec les Dockerfiles épinglés. |
| 3 | Renforcement scientifique ML | 🟡 | Fait : `app/ml/experiments.py` (7 modèles, CV imbriquée groupée 5×5, t-test corrigé Nadeau-Bengio) → `docs/test-reports/ml_model_comparison.json` ; jeu externe réel ATT&CK `data/external/attack_eval.jsonl` (49 textes, script `data/scripts/build_attack_eval_set.py`) ; porte de validation `app/ml/validate_model.py` ; `train.py` enregistre l'empreinte du jeu (`--output-dir`). **Décision : garder la LR déployée** (aucun gain significatif). Candidat ré-entraîné identique + empreinte dans `.venv/ml_candidate_test/` (porte : PROMOTABLE). Reste : promotion du candidat tracé **⏸ autorisation** ; documenter (`docs/05_evaluation.md`). |
| 4 | Fonctions CTI & cohérence inter-services | ✅ (lecture seule) / ⏸ | `scripts/verify_consistency.py` → 12/12 (`consistency_check.json`) ; `scripts/audit_chain_anchors.py` → aucun ancrage erroné (`chain_anchor_audit.json`). Benchmark de latence ajouté : `backend/scripts/benchmark_pipeline.py` → `pipeline_benchmark.json` (médiane 103,6 ms/rapport, p95 169,9 ms, hors réseau). Rejeu du scénario 20 étapes **⏸ autorisation** (écrit en base, MISP, chaîne). |
| 5 | Améliorations UI + tests UI | 🟡 | `frontend/tests/test_pages.py` (AppTest, 19 tests : 8 pages × 2 thèmes + 3). Exécution 1 : 19/19 ; exécution 2 (pendant le build Docker) : **18 réussis, 1 échec** = timeout 120 s `dashboard.py-dark` (JUnit `pytest-frontend.xml`). Cause supposée = charge machine, **non confirmée**. Audit responsive mobile **non terminé**. |
| 6 | Tests complets | 🟡 / ⏸ | Backend non-live : **85/85** (JUnit `pytest-backend.xml`, 17/11 08:56 UTC), inclut `tests/test_migrations.py` (upgrade head = modèles). Hardhat : 21/21 (session précédente). **4 tests live non exécutés** ⏸ (créent/suppriment un événement MISP, déploient un contrat neuf sur le nœud Hardhat). Installation propre : voir phase 2. |
| 7 | Pipeline GitLab CI | 🟡 | `.gitlab-ci.yml` écrit (validate, secrets gitleaks, pip-audit, pytest+couverture, Hardhat, validation données ML, entraînement candidat + porte, comparaison manuelle, promotion manuelle, build images, intégration manuelle, rapport). Validé **localement** (YAML + contrôles de structure, 0 erreur). **Jamais exécuté sur GitLab ; aucun dépôt GitLab configuré ; CI Lint GitLab non passé.** |
| 8 | Documentation finale | ⬜ | À créer : `docs/TESTING_AND_VALIDATION.md`, `docs/PROJECT_COMPLETE_DOCUMENTATION.md`, doc module ML (MAJ `05_evaluation.md`), doc pipeline GitLab, guide de configuration, MAJ `README.md`, `06_installation.md`, `08_guide_utilisation.md`, `09_rapport_tests.md`, `03_blockchain.md`, `data/README.md`, matrice de conformité, rapport final. |

## 5. Git, GitLab, VS Code

* Dépôt local : initialisé, branche `main`, **aucun commit** (`git log` → « does not have any commits yet »).
* Remote : **aucun** (`git remote -v` vide). La feuille de route mentionne un push éventuel vers
  `github.com/eamalea/intelligent-decentralized-cti` (GitHub, pas GitLab) — **non configuré, à confirmer**.
* GitLab : aucun projet relié ; le pipeline n'a jamais tourné.
* Connexion VS Code ↔ GitLab : **[NON VÉRIFIÉ]** — aucun dossier `.vscode/` dans le projet ; l'extension et
  l'authentification VS Code ne sont pas observables depuis cette session.
* `.env` ignoré (vérifié lors de l'audit) ; scan de secrets : 0 secret réel sur les 232 fichiers de l'audit.
  16 fichiers ajoutés depuis → **re-scan nécessaire** avant le commit.

## 6. État des services (observé le 17/11 ≈ 09:05 UTC via `docker ps`)

Projet Compose `cti-platform` : backend (healthy, up 34 min), frontend (healthy, up 38 min), hardhat (healthy,
up 14 h), postgres, misp-core, misp-nginx, misp-db, misp-redis, misp-modules (tous healthy, up 14 h).
Base : `alembic current` = `heads` = **0003**, `alembic check` sans écart (`docs/DATABASE_MIGRATION_AUDIT.md`).
Données : 2 rapports historiques ancrés sur une instance Hardhat précédente (CTI-60C0B69D4E, CTI-9C938CFA11,
affichés « instance précédente ») ; rapports courants CTI-7FCE46A77C (DISPUTED), CTI-0860C34F98 et
CTI-BE426BF5C7 (VALIDATED). **Ne pas toucher.**

## 7. Fichiers créés / modifiés pendant la mission globale

Créés : `.gitattributes`, `.gitlab-ci.yml`, `backend/requirements.lock`, `frontend/requirements.lock`,
`backend/app/ml/experiments.py`, `backend/app/ml/validate_model.py`, `backend/scripts/benchmark_pipeline.py`,
`backend/tests/test_migrations.py`, `frontend/tests/test_pages.py`, `data/scripts/build_attack_eval_set.py`,
`data/external/attack_eval.jsonl`, `docs/GIT_SECURITY_AUDIT.md`, `docs/DATABASE_MIGRATION_AUDIT.md`,
`docs/test-reports/{ml_model_comparison,pipeline_benchmark}.json`, `docs/test-reports/pytest-{backend,frontend}.xml`,
ce fichier et `docs/FINALIZATION_PROGRESS.md`.
Modifiés : `.gitignore`, `docker-compose.yml` (digests, `MISP_INTERNAL_URL`), `docker/{backend,frontend,hardhat}.Dockerfile`
(digests, lock), `backend/app/ml/train.py` (`--output-dir`, empreinte du jeu, version sklearn ; sortie par défaut inchangée).
Non modifiés volontairement : migration 0003, modèle déployé, données de `data/annotated|splits|raw`.

## 8. Décisions techniques de la session

1. Migration 0003 conservée (additive, testée) — décision de l'utilisatrice.
2. Identité d'ancrage = (instance de chaîne, id on-chain) ; anciens ancrages marqués « instance précédente », pas réécrits.
3. Modèle LR conservé : SGD meilleur en moyenne (CV 0,903 vs 0,876) mais p = 0,46 ; baseline mots-clés 0,935 (p = 0,19) → pas de gain significatif sur 80 rapports synthétiques.
4. Jeu externe ATT&CK : étiquettes dérivées par règles explicites (champ `label_source`), jugé lexicalement facile — à mentionner comme limite.
5. Promotion de modèle : uniquement manuelle et derrière la porte `validate_model --require-fingerprint`.
6. CI : pas de déploiement, push d'images seulement sur tag, jobs lourds manuels.

## 9. Problèmes non résolus / risques

* Test d'installation propre non abouti (réseau lent) — reproductibilité non démontrée de bout en bout.
* Timeout UI `dashboard-dark` à re-tester hors charge.
* Modèle déployé sans empreinte de jeu enregistrée (porte : « not recorded ») tant que le candidat n'est pas promu.
* 4 tests live jamais rejoués depuis les dernières modifications.
* CI GitLab jamais exécutée ; `pip-audit` et `gitleaks` jamais lancés localement.
* Corpus d'entraînement synthétique (80 rapports) : métriques à interpréter avec prudence (IC Wilson [0,64 ; 0,965]).
* Dossier de clone propre dans le scratchpad de l'ancienne session (peut disparaître) ; image `cticlean-hardhat:latest` restante (inoffensive ; suppression seulement sur accord).

## 10. Commandes utiles pour reprendre (depuis la racine du projet, Git Bash)

```bash
docker ps --format '{{.Names}}\t{{.Status}}'
```
```bash
cd backend && ../.venv/Scripts/python -m pytest -q -p no:cacheprovider -m "not live_chain and not live_misp" --junitxml=../docs/test-reports/pytest-backend.xml
```
```bash
./.venv/Scripts/python -m pytest -q -p no:cacheprovider frontend/tests --junitxml=docs/test-reports/pytest-frontend.xml
```
```bash
cd blockchain && npx hardhat test
```
```bash
cd backend && ../.venv/Scripts/python -m app.ml.validate_model --report ../docs/test-reports/deployed-model-validation.json
```
```bash
cd backend && ../.venv/Scripts/python scripts/benchmark_pipeline.py
```
```bash
git ls-files --others --exclude-standard | wc -l
```

Lecture seule / sans écriture MISP-chaîne : les commandes ci-dessus. **Soumises à autorisation** :
`pytest -m "live_chain or live_misp"`, `python scripts/run_demo_scenario.py`, copie du candidat
`.venv/ml_candidate_test/` vers `backend/app/ml/artifacts/`, `git commit`, `git push`, reconstruction du clone propre
(`docker compose -p cticlean build`, long et gourmand en réseau).

## 11. Prochaines étapes, par priorité

1. **Re-lancer les tests UI** hors charge (commande ci-dessus) et consigner le résultat.
2. **Phase 8 — documentation** : `TESTING_AND_VALIDATION.md` (incl. collision d'identifiants on-chain : cause, correction, tests), `PROJECT_COMPLETE_DOCUMENTATION.md`, doc ML (expériences, porte, jeu externe, benchmark), doc pipeline GitLab, guide de configuration, mises à jour README/06/08/09/03/data README.
3. Re-scan des secrets sur les 248 fichiers candidats ; préparer le message de commit actualisé.
4. Demander les autorisations groupées : tests live, rejeu du scénario, promotion du modèle tracé, commit initial, (push et remote), relance du test d'installation propre.
5. Après accord : exécuter, consigner, puis rapport final + matrice de conformité CDC/cadrage.
