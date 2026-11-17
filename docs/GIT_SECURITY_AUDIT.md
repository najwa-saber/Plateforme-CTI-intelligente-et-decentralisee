# Audit Git et sécurité du dépôt — 17/11/2026

## État constaté (lecture seule)

| Élément | Constat |
|---|---|
| Branche | `main` (aucun commit — `git log` : « does not have any commits yet ») |
| Index (`git diff --cached`) | vide — rien n'est indexé |
| `git diff` | sans objet (aucun fichier suivi) |
| Dépôt distant | **aucun** (`git remote -v` vide) |
| Identité Git | configurée ; `core.autocrlf=true` (Windows) |
| Fichiers candidats au premier commit | 229 puis 231 après ajout de `.gitattributes` et des documents d'audit |

Comme aucun commit n'existe, tout le projet est « non suivi » : il n'y a pas de différence entre « changements
préexistants » et « changements récents » du point de vue de Git. La chronologie est donnée par
`docs/PROJECT_CURRENT_STATE.md` §6 (modifications des 16–17/11 : ancrages, MISP 404, T1110.004, migration 0003).

## Secrets

* Recherche des **valeurs réelles** de `.env` (mot de passe PostgreSQL, 3 clés API, clé MISP, 4 mots de passe MISP)
  dans les 229 fichiers candidats : **0 occurrence**.
* Clés privées PEM, clé privée par défaut de Hardhat : **0 occurrence**.
* `.env` ignoré (`git check-ignore` OK) ; `.env.example` ne contient que des valeurs `change-me`.
* Les rapports `docs/test-reports/*.json` contiennent des URL et identifiants de démonstration, pas de secret.

## Fichiers exclus (`.gitignore`) — vérifiés

`.env`, `.venv/`, `__pycache__/`, `.pytest_cache/`, `*.db`, `*.log`, `blockchain/node_modules/`, `cache/`,
`artifacts/`, `deployments/`, bundle STIX MITRE de 55 Mo (`data/raw/mitre/enterprise-attack.json`, re-téléchargeable),
`.claude/`, et désormais `backend/app/ml/artifacts/candidates/` (modèles candidats) et `reports/` (rapports locaux).

## Fichiers volumineux / binaires versionnés (justifiés)

| Fichier | Taille | Justification |
|---|---|---|
| `backend/app/mitre/data/enterprise_techniques.json` | 680 Ko | catalogue ATT&CK compact dérivé du STIX officiel (évite 55 Mo) |
| `blockchain/package-lock.json` | 324 Ko | reproductibilité npm |
| `backend/app/ml/artifacts/classifier.joblib` | 196 Ko | modèle **promu** (binaire, `.gitattributes`) — régénérable par `python -m app.ml.train` |
| `data/*` | < 100 Ko par fichier | corpus synthétique annoté, découpages |

## Correctif appliqué (sûr)

`.gitattributes` : fins de ligne LF forcées pour `*.sh`, `*.py`, `*.sol`, `*.js`, YAML, TOML, Dockerfiles (les
scripts exécutés dans des conteneurs Linux casseraient en CRLF avec `core.autocrlf=true`) ; `*.joblib` et `*.pdf`
déclarés binaires.

## Stratégie de sauvegarde (proposée, non exécutée)

1. **Base PostgreSQL** (lecture seule pour la base) :
   `docker compose exec -T postgres pg_dump -U cti -d cti -Fc > backups/cti_YYYYMMDD.dump` ;
   restauration : `pg_restore --clean -d cti` (opération destructive, à n'exécuter qu'avec accord).
2. **MISP** : `docker compose exec -T misp-db mariadb-dump -u misp -p misp > backups/misp_YYYYMMDD.sql`.
3. **Chaîne Hardhat** : non sauvegardable (réseau en mémoire) ; la traçabilité off-chain (transactions, votes,
   empreintes) est en base ; voir la détection d'instance (`docs/03_blockchain.md`).
4. **Code** : premier commit local, puis dépôt distant privé (GitLab) après autorisation ; `backups/` à ajouter au
   `.gitignore` avant toute sauvegarde locale.

## Stratégie de premier commit

1. Relire la liste : `git status --short` puis `git add -A --dry-run`.
2. Vérifier à nouveau l'absence de secrets (procédure ci-dessus).
3. `git add -A && git commit` avec le message proposé dans `docs/FINALIZATION_ROADMAP.md` (mis à jour en fin de
   finalisation).
4. Étiqueter la version présentée : `git tag v1.0-soutenance` (après validation).

Aucun commit ni push n'a été réalisé.
