# 06 — Installation, configuration et Docker

## Prérequis

| Outil | Version testée | Usage |
|---|---|---|
| Docker Desktop / Engine + Compose v2 | Docker 29.6, Compose 5.3 | toute la pile |
| RAM allouée à Docker | ≥ 4 Go (pile de base), ≥ 8 Go avec MISP | MISP + MariaDB sont gourmands |
| Python | 3.11 | scripts (`generate_env.py`, scénario, évaluations), exécution locale optionnelle |
| Node.js | non requis sur l'hôte | Hardhat tourne dans l'image `node:22-bookworm-slim` |

## 1. Configuration

```bash
python scripts/generate_env.py
```

Crée `.env` à partir de `.env.example` avec des secrets aléatoires (mot de passe PostgreSQL, clés API A/B/C, clé MISP
de 40 caractères, mots de passe MISP). Le fichier n'est jamais versionné. Variables principales :

| Variable | Rôle |
|---|---|
| `ORG_X_API_KEY`, `ORG_X_NAME`, `ORG_X_ACCOUNT_INDEX` | identité des organisations simulées (clé API, nom, compte Hardhat) |
| `MISP_MODE` | `real` · `simulated` · `auto` (réel si joignable, sinon simulé signalé) |
| `MISP_INTERNAL_URL` / `MISP_URL` / `MISP_PUBLIC_URL` | URL vue par le conteneur backend / par une exécution locale / par le navigateur |
| `VOTING_PERIOD_SECONDS` | durée de vote avant INCOMPLETE (défaut 7 jours) |
| `SCORE_WEIGHT_*`, `CORR_*` | pondérations du score et de la corrélation |
| `API_URL` | URL de l'API pour le frontend local (utiliser `127.0.0.1`, voir dépannage) |

## 2. Démarrage avec Docker Compose

```bash
docker compose --profile misp up -d --build
```

Services (`docker compose ps`) :

| Service | Image | Port (127.0.0.1) | Santé |
|---|---|---|---|
| postgres | postgres:16-alpine | 5432 | `pg_isready` |
| hardhat | build `docker/hardhat.Dockerfile` | 8545 | RPC + fichier de déploiement |
| backend | build `docker/backend.Dockerfile` | 8000 | `GET /health` |
| frontend | build `docker/frontend.Dockerfile` | 8501 | `/_stcore/health` |
| misp-db, misp-redis, misp-modules, misp-core, misp-nginx (profil `misp`) | images officielles misp-docker | 8443 (HTTPS) | heartbeat / ports |
| misp-certs (profil `misp`) | one-shot | — | génère un certificat auto-signé dans un volume |

Ordre de démarrage géré par `depends_on` + healthchecks. Au démarrage, le backend attend PostgreSQL, applique
`alembic upgrade head`, attend le déploiement du contrat puis enregistre les organisations.

Sans MISP (plus léger) : `docker compose up -d --build` — le mode `auto` bascule sur l'adaptateur simulé, signalé
« MISP · SIMULÉ » dans l'interface.

Mise à jour d'un seul service **sans recréer Hardhat** (dont l'état est en mémoire) :

```bash
docker compose up -d --build --no-deps backend frontend
```

## 3. Vérification

```bash
curl -s http://127.0.0.1:8000/api/v1/health
```

Tous les composants doivent être `ok: true` (`misp.mode: real` si le profil MISP tourne). Puis le scénario complet :

```bash
python scripts/run_demo_scenario.py
```

## 4. Exécution locale (développement, sans conteneurs applicatifs)

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -r backend/requirements.txt -r frontend/requirements.txt
```

```bash
cd backend && ../.venv/Scripts/python -m uvicorn app.main:app --port 8000
```

```bash
cd frontend && ../.venv/Scripts/python -m streamlit run app.py --server.address 127.0.0.1
```

En local, la base par défaut est SQLite (`DATABASE_URL`), le schéma est créé au démarrage ; Hardhat et MISP peuvent
rester dans Docker (ports 8545 / 8443).

## 5. Tests

```bash
cd backend && ../.venv/Scripts/python -m pytest -q
```

Les tests *live* (`-m "live_chain or live_misp"`) s'exécutent automatiquement si Hardhat (8545) et MISP (8443) sont
joignables, et sont ignorés sinon. Tests du contrat : voir [03_blockchain.md](03_blockchain.md#tests).

## 6. Migrations

`backend/alembic/versions/` : `0001` schéma initial, `0002` colonne `reports.chain_instance` (ajout non destructif).
Nouvelle migration : `alembic revision --autogenerate -m "..."` (depuis `backend/`, `DATABASE_URL` positionnée).

## 7. Données et modèles

* Corpus : `python data/scripts/build_corpus.py` (déterministe).
* Modèle : `cd backend && python -m app.ml.train` (écrit `app/ml/artifacts/`).
* Catalogue ATT&CK : télécharger `enterprise-attack.json` (attack-stix-data) dans `data/raw/mitre/` puis
  `python backend/scripts/build_mitre_dataset.py data/raw/mitre/enterprise-attack.json backend/app/mitre/data/enterprise_techniques.json`.
