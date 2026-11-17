# Guide d'installation

Guide pas à pas pour une machine neuve. Les détails de configuration (variables, exécution locale sans conteneurs,
migrations) restent dans [`06_installation.md`](06_installation.md) ; le dépannage dans [`07_troubleshooting.md`](07_troubleshooting.md).

Procédure **vérifiée le 17/11/2026** sur une copie contenant uniquement les fichiers versionnables
(sans `.env`, sans `node_modules`, sans environnement virtuel) : build des 3 images en 152 s, 85 tests réussis dans
l'image neuve (`test-reports/clean_install.json`).

## 1. Prérequis

| Outil | Version | Remarque |
|---|---|---|
| Docker Desktop / Engine + Compose v2 | testé Docker 29.6, Compose 5.3 | ≥ 4 Go de RAM pour Docker, ≥ 8 Go avec MISP |
| Python | 3.11 | uniquement pour les scripts hôtes (`generate_env.py`, scénario, évaluations) |
| Git | toute version récente | `.gitattributes` force les fins de ligne LF des scripts shell |
| Node.js | non requis | Hardhat tourne dans son conteneur |

Connexion Internet nécessaire au premier build (images et paquets). Le catalogue MITRE nécessaire à l'API est versionné
(`backend/app/mitre/data/enterprise_techniques.json`) ; le bundle STIX complet n'est requis que pour régénérer ce catalogue
ou le jeu externe ATT&CK.

## 2. Installation

```bash
git clone <URL-du-dépôt> intelligent-decentralized-cti
```
```bash
cd intelligent-decentralized-cti
```
```bash
python scripts/generate_env.py
```
Crée `.env` avec des secrets aléatoires (CSPRNG). Ne jamais le versionner ni le partager.

Pile complète, avec MISP réel (premier démarrage de MISP : 5 à 10 min) :
```bash
docker compose --profile misp up -d --build
```
Pile légère, avec MISP simulé (signalé « MISP · SIMULÉ » dans l'interface) :
```bash
docker compose up -d --build
```

Les dépendances Python sont installées avec des versions exactes (`pip install -r requirements.txt -c requirements.lock`) ;
les images de base sont épinglées par digest : deux installations produisent les mêmes versions.

## 3. Vérification

```bash
docker compose ps
```
Tous les services doivent être `healthy` (`misp-certs` est un service ponctuel qui se termine).

```bash
curl -s http://127.0.0.1:8000/api/v1/health
```

| Adresse | Contenu |
|---|---|
| http://127.0.0.1:8501 | interface Streamlit (8 pages) |
| http://127.0.0.1:8000/docs | documentation OpenAPI de l'API |
| https://127.0.0.1:8443 | MISP (certificat auto-signé de laboratoire) |

## 4. Tests

Environnement hôte pour les tests :
```bash
python -m venv .venv
```
```bash
./.venv/Scripts/python -m pip install -r backend/requirements.txt -c backend/requirements.lock -r frontend/requirements.txt -c frontend/requirements.lock
```
(sous Linux/macOS : `.venv/bin/python`). Puis les commandes de [`TESTING_AND_VALIDATION.md`](TESTING_AND_VALIDATION.md) §6.

## 5. Mise à jour et arrêt

Reconstruire l'API et l'interface **sans recréer Hardhat** (son état est en mémoire : le recréer remet la chaîne à zéro) :
```bash
docker compose up -d --build --no-deps backend frontend
```
Arrêter sans supprimer les données :
```bash
docker compose --profile misp stop
```
`docker compose down -v` **supprime les volumes** (PostgreSQL, MISP) : ne l'utiliser que pour repartir de zéro, volontairement.

## 6. Points d'attention

* Windows : utiliser `127.0.0.1` plutôt que `localhost` (résolution IPv6 qui ajoute ~2 s par requête).
* Un redémarrage du conteneur `hardhat` crée une nouvelle instance de chaîne : les rapports déjà ancrés sont affichés
  « instance précédente (non vérifiable) », sans perte de données hors chaîne.
* Le backend applique `alembic upgrade head` à chaque démarrage (tête actuelle : `0003`).
