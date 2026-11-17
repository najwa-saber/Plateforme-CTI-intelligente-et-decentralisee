# 07 — Dépannage

## Réinitialisation de la chaîne (Hardhat redémarré)

**Symptôme** : avertissement « N report(s) were anchored on a previous instance of the local Hardhat network » dans la
barre latérale ou `/api/v1/health` ; `409 chain_anchor_mismatch` sur un vote ; intégrité « non vérifiable on-chain ».

**Cause** : le réseau Hardhat est en mémoire. Un redémarrage du conteneur `hardhat` (ou un `docker compose up --build`
qui le reconstruit) recrée une chaîne vide et redéploie le contrat à la même adresse. Les rapports ancrés auparavant
n'ont plus d'enregistrement on-chain. La plateforme le **détecte** (hash du bloc de déploiement mémorisé par rapport)
au lieu de lire l'enregistrement d'un autre rapport.

**Options** :
1. *Conserver les données* : rien à faire ; les anciens rapports restent consultables, leur statut final off-chain
   est conservé et signalé ; les nouveaux rapports fonctionnent normalement.
2. *Repartir d'un environnement propre* (**destructif** : supprime rapports, votes, scores et événements MISP) :

```bash
docker compose --profile misp down
```

```bash
docker volume rm cti-platform_pg_data cti-platform_misp_mysql
```

```bash
docker compose --profile misp up -d
```

**Prévention** : mettre à jour backend/frontend avec `docker compose up -d --build --no-deps backend frontend`.

## L'interface locale est lente (≈ 2 s par action) sous Windows

`localhost` est résolu d'abord en IPv6 (`::1`) alors que Docker ne publie que sur `127.0.0.1` : chaque requête attend
l'échec IPv6. Utiliser `API_URL=http://127.0.0.1:8000` (valeur par défaut de `.env.example`). Le conteneur frontend
n'est pas concerné (il appelle `http://backend:8000`).

## MISP

| Symptôme | Cause / solution |
|---|---|
| Mode « SIMULÉ » alors que le profil MISP est lancé | MISP s'initialise 3–5 min au premier démarrage ; bouton « Re-tester la connexion MISP » (page Gestion MISP) ou `GET /api/v1/misp/status?reprobe=true`. |
| `Connection refused` sur `misp-core:443` | depuis misp-docker 2.5, le serveur web est le conteneur **misp-nginx** (port 8443) ; `misp-core` n'expose que PHP-FPM (9002). Utiliser `MISP_INTERNAL_URL=https://misp-nginx:8443`. |
| misp-nginx ne démarre pas | `BASE_URL` en `https://` exige `cert.pem`/`key.pem` : générés par le service `misp-certs` (volume `misp_ssl`). |
| Avertissement de certificat dans le navigateur | certificat auto-signé de laboratoire ; `MISP_VERIFY_SSL=false` côté backend (réseau Docker interne). |
| Identifiants web MISP | `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD` du fichier `.env`. |

## Ethereum

| Symptôme | Solution |
|---|---|
| `503 blockchain_error`, « deployment file not found » | `docker compose logs hardhat` ; le service redéploie au démarrage (`deployments/localhost.json` dans le volume `deployments`). |
| `409 contract_revert` | règle métier du contrat (double vote, auto-validation, finalisation prématurée…) : voir `details.contract_error`. |
| Tests Hardhat : erreur Node | Hardhat 2.29 + toolbox 5 : utiliser l'image `node:22-bookworm-slim`. |

## Interface

| Symptôme | Solution |
|---|---|
| Le thème change pour tous les navigateurs ouverts | comportement documenté : les options de thème Streamlit sont propres au serveur (une instance de démonstration = un thème courant). |
| Lien direct vers une page qui ouvre le tableau de bord | ne pas écrire de paramètres d'URL avant `st.navigation` (corrigé dans `app.py`). |
| Mauvaise organisation après rechargement | l'organisation active est conservée dans l'URL (`?org=B`). |

## Base de données

* Logs de migration : `docker compose logs backend | grep alembic`.
* Accès SQL : `docker compose exec postgres psql -U cti -d cti`.
