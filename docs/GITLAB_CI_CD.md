# Pipeline GitLab CI/CD

Fichier : [`.gitlab-ci.yml`](../.gitlab-ci.yml). **État : exécuté sur GitLab.com** (projet privé `projet-ia8944347/plateforme-cti-intelligente-et-decentralisee`).
Le pipeline GitLab **#3078904924** (commit `4d10748`, 17/11/2026, 6 min 51 s) : les 10 jobs automatiques réussis — validate, lint, secrets (gitleaks), dépendances (pip-audit : « No known vulnerabilities found »), tests Python (85 réussis, couverture 76 %), Hardhat (21 passing), `ml:data-validation` (corpus régénéré identique, PROMOTABLE), `ml:train-candidate` (empreinte enregistrée = empreinte courante, PROMOTABLE), build des 3 images. Détails et historique des corrections : §6.

## 1. Étapes et jobs

| Étape | Job | Rôle | Bloquant | Quand |
|---|---|---|---|---|
| validate | `code:validate` | `compileall`, `pip check`, YAML de `docker-compose.yml` | oui | toujours |
| lint | `lint:python` | `ruff 0.8.4` sur backend, frontend, scripts ; rapport *Code Quality* GitLab | oui | toujours |
| security | `security:secrets` | `gitleaks v8.21.2` sur l'arbre de fichiers (sorties masquées) | oui | toujours |
| security | `security:dependencies` | `pip-audit` sur chaque fichier lock | non (*advisory*) | toujours |
| test | `test:python` | pytest backend hors *live* + JUnit + couverture Cobertura | oui | toujours |
| test | `test:hardhat` | `npm ci` + `npx hardhat test` (21 tests du contrat) | oui | toujours |
| ml-validation | `ml:data-validation` | régénère le corpus (déterministe) et vérifie `git diff` vide ; porte sur le modèle déployé | oui | toujours |
| ml-validation | `ml:train-candidate` | entraîne un candidat dans `candidates/<sha>` puis porte `--require-fingerprint` | oui | si `data/**` ou `backend/app/ml/**` change, ou lancement manuel |
| ml-validation | `ml:model-comparison` | comparaison des 7 modèles (≈ 2 min) | non | manuel |
| ml-validation | `ml:promote-model` | vérifie `promotable=true` du candidat ; la promotion se fait par merge request relue | oui | manuel, branche par défaut |
| build | `build:images` | construit les 3 images ; *push* au registre **uniquement sur tag** | oui | après lint + tests |
| integration | `integration:stack` | Postgres + Hardhat + backend en Docker-in-Docker, scénario de démo (MISP simulé) | non | manuel |
| report | `report:summary` | regroupe `docs/test-reports/` en artefact | — | toujours |

Images de base épinglées par digest (`PYTHON_IMAGE`, `NODE_IMAGE`) ; dépendances installées avec `-c requirements.lock`.

## 2. Principes de sécurité

* **Aucun secret applicatif requis** : les tests génèrent des clés jetables (`tests/conftest.py`, `scripts/generate_env.py`).
* Seules variables utilisées : `CI_REGISTRY*` (fournies par GitLab, push sur tag seulement).
* À déclarer *masked* + *protected* si un registre externe est utilisé : `CI_REGISTRY_PASSWORD`.
* Aucun job de déploiement ; aucun modèle promu automatiquement ; `.env` exclu par `.gitignore`.
* Les tests *live* (MISP réel, déploiement de contrat) ne sont **pas** exécutés en CI.

## 3. Traçabilité ML

Chaque candidat porte dans `metrics.json` l'empreinte SHA-256 des splits et la version de scikit-learn ; son
`validation_report.json` est conservé 90 jours en artefact. Voir [`ML_EVALUATION.md`](ML_EVALUATION.md) §5.

## 4. Validation locale effectuée (17/11/2026)

| Contrôle | Résultat |
|---|---|
| YAML + cohérence structurelle (étapes déclarées, `needs` existants et pas d'étape ultérieure) | 13 jobs, 8 étapes, 0 erreur |
| `ruff check` (même version, mêmes dossiers) | « All checks passed! » après correction de 15 avertissements |
| pytest backend (même commande) | 85 réussis |
| `npx hardhat test` | 21 passing |
| Build des 3 images depuis les seuls fichiers versionnables | OK (`docs/test-reports/clean_install.json`) |
| `pip-audit` (même commande, un fichier lock à la fois) | 0 vulnérabilité après mise à jour (`SECURITY_AUDIT.md`) |
| gitleaks (même version) sur les fichiers versionnables | aucune fuite |
| Installation des deux locks dans un même environnement (template `.python`) | OK, `pip check` sans conflit |
| CI Lint de GitLab | **non exécuté** (nécessite un projet GitLab) |

## 5. Mise en place (réalisée le 17/11/2026) (après autorisation du commit et du push)

1. Créer un projet GitLab vide (sans README) ; activer le registre de conteneurs si l'on veut pousser les images.
2. Vérifier qu'un runner **Docker** est disponible ; `build:images` et `integration:stack` exigent le mode *privileged* (dind).
   Sur gitlab.com, les runners partagés conviennent.
3. Valider le fichier dans *Build > Pipeline editor > Validate* (CI Lint).
4. Depuis le dépôt local :
   ```bash
   git remote add origin <URL-du-projet-GitLab>
   ```
   ```bash
   git push -u origin main
   ```
5. Contrôler le pipeline : *Build > Pipelines* ; artefacts JUnit, couverture, Code Quality, gitleaks, pip-audit.
6. Consigner l'identifiant et le résultat du pipeline dans `TESTING_AND_VALIDATION.md` — c'est la seule preuve
   acceptable que la CI fonctionne.

VS Code : l'extension officielle « GitLab Workflow » permet de suivre les pipelines après le push (authentification
par jeton personnel, à créer par l'utilisatrice ; ne jamais le placer dans le dépôt). Non vérifié depuis cette session.

## 6. Exécutions réelles

| Pipeline | Commit | Résultat | Correction |
|---|---|---|---|
| #3078686978 | `1aa1d38` | 1 job en échec : `ml:data-validation` — `git: command not found` (exit 127) | `ff9a580` : copie du corpus + `diff -r` ; CSV en LF |
| #3078904924 | `4d10748` | 10/10 jobs automatiques réussis ; statut « manuel » car `ml:promote-model` (manuel) bloquait `report:summary` | promotion manuelle non bloquante (`allow_failure: true`), `report:summary` avec `needs` sur les jobs automatiques, dépendance optionnelle vers `ml:train-candidate` |
| suivant | — | à consigner | — |

Remarque : la branche `main` est protégée ; le push forcé (nécessaire une fois pour réécrire le message du commit initial) a été autorisé puis immédiatement désactivé.
