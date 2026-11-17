# État actuel du projet — audit du 17/11/2026

> Document de diagnostic. Aucune modification de code, de données ou de configuration n'a été effectuée pour le
> produire : toutes les commandes utilisées sont en lecture seule (sauf l'écriture de ce document et des rapports de
> diagnostic JSON dans `docs/test-reports/`). Voir l'encadré « Événement de l'audit » ci-dessous.

## Événement de l'audit à connaître

Au moment où la consigne « aucune migration » a été reçue, une commande lancée juste avant (reconstruction du backend
`--no-deps`) était en cours. Elle a été interrompue, mais le conteneur avait déjà été recréé : son point d'entrée a
exécuté `alembic upgrade head` et **la migration `0003_chain_anchor_identity` est appliquée** sur PostgreSQL
(constat en lecture seule : `alembic_version = 0003`, index unique partiel `uq_reports_chain_anchor` présent,
colonne `chain_transactions.chain_instance` présente). Cette migration est **additive** (un index partiel, une
colonne nullable) : aucune ligne existante n'a été modifiée ni supprimée. Elle n'a pas été annulée (une annulation
serait elle-même une migration). **Décision requise** : la conserver (recommandé, elle est couverte par des tests) ou
la révoquer.

## 1. Arborescence et volume

| Zone | Fichiers | Lignes | Contenu |
|---|---|---|---|
| `backend/app` | 51 | 5 138 | API FastAPI, services, NLP, ML, MITRE, MISP, blockchain, corrélation |
| `backend/tests` | 8 | 1 360 | 88 tests pytest |
| `backend/scripts` | 3 | 307 | catalogue ATT&CK, évaluations IOC / ATT&CK / corrélation |
| `backend/alembic` | 4 | 358 | migrations 0001, 0002, 0003 |
| `blockchain/` | 5 | 649 | `CTIValidation.sol`, 21 tests Hardhat, déploiement, santé |
| `frontend/` | 14 | 1 671 | Streamlit : `app.py`, 8 vues, composants (api, ui, charts, theme) |
| `data/scripts` | 6 | 768 | corpus synthétique (sources annotées), génération |
| `scripts/` | 4 | 431 | `.env`, scénario de démo, cohérence, audit des ancrages |
| `docker/` + `docker-compose.yml` | 5 | ~330 | 3 Dockerfiles, entrypoint, 11 services |
| `docs/` | 10 + 5 rapports JSON | 786 | documentation technique |

Données : `data/annotated` (80 rapports, 182 IOC, 163 relations, 25 cas *challenge*), `data/splits` (48/16/16),
`data/demo` (5 fichiers), `data/raw/reports` (80), `data/raw/iocs` (**vide**), `data/raw/mitre` (bundle STIX, non versionné).

## 2. Infrastructure en fonctionnement (constat)

| Service | Image | État |
|---|---|---|
| postgres | postgres:16-alpine | sain — migration 0003 |
| hardhat | build local (Hardhat 2.29.2, Solidity 0.8.24, OZ 5.4.0) | sain — même instance depuis ~13 h, contrat `0x5FbD…0aa3`, 3 rapports on-chain |
| backend | build local (Python 3.11, FastAPI 0.115.14) | sain — recréé lors de l'événement ci-dessus (contient le code non commité) |
| frontend | build local (Streamlit 1.45.1) | sain |
| misp-core / misp-nginx / misp-modules | `ghcr.io/misp/misp-docker/*:latest` (MISP 2.5.51) | sains — **tags `latest` non épinglés** |
| misp-db / misp-redis | mariadb:10.11 / valkey:7.2 | sains |

`GET /api/v1/health` : `ok` pour base, ML, MITRE, MISP (mode **réel**), Ethereum ; avertissement « 2 rapports ancrés
sur une instance précédente ».

## 3. Base de données (lecture seule)

8 rapports : 2 historiques (`CTI-60C0B69D4E`, `CTI-9C938CFA11`, VALIDATED, ancrés sur une instance Hardhat
disparue, `chain_instance` NULL), 3 ancrés sur l'instance courante (`CTI-7FCE46A77C` DISPUTED, `CTI-0860C34F98` et
`CTI-BE426BF5C7` VALIDATED), 3 analysés non soumis (+ rapports créés par les démonstrations). Le rapport
`CTI-60C0B69D4E` a son événement MISP dans l'adaptateur **simulé** (créé avant le démarrage du MISP réel).

## 4. Dépendances

Python (venv 3.11) : FastAPI 0.115.14, Pydantic 2.14, SQLAlchemy 2.0.57, Alembic 1.16.5, psycopg 3.2.13,
scikit-learn 1.6.1, NumPy 2.2.6, pandas 2.2.3, pypdf 5.9, PyMISP 2.5.34.4, web3 7.8.0, Streamlit 1.45.1,
Plotly 6.0.1. `requirements.txt` exprime des **intervalles** (pas de fichier de verrouillage) ; `package-lock.json`
est présent pour Hardhat.

## 5. Composants : réellement implémentés vs partiels

| Composant | État | Commentaire |
|---|---|---|
| Import TXT / PDF / JSON / saisie / événement MISP | implémenté et vérifié | tests + import réel depuis MISP (événement 14) |
| Extraction / normalisation / validation IOC | implémenté et vérifié | regex + validation ; IPv6, e-mails, SHA-1 hors périmètre |
| Doublons / incohérences | implémenté et vérifié | « renseignements contradictoires » couverts partiellement |
| Classification (TF-IDF + LogReg) | implémenté, entraîné, évalué | pas meilleur que la baseline à mots-clés (voir audit IA) |
| ATT&CK (règles + similarité STIX) | implémenté et vérifié | 55 règles, catalogue officiel v20.1 |
| MISP réel + adaptateur simulé | implémenté et vérifié | création, attributs, tags remplaçants, recherche, import, 404 |
| Contrat Solidity + Web3.py | implémenté et vérifié | règles du CDC, réputation bornée, événements |
| Score de fiabilité, réputation, corrélation | implémenté et vérifié | pondérations du score non validées empiriquement |
| Détection des changements d'instance Hardhat | implémenté et vérifié | renforcé (index unique, émetteur) — **non commité** |
| Streamlit 8 pages, thèmes | implémenté, vérifié manuellement | **aucun test automatisé d'interface dans le dépôt** |
| Docker Compose | implémenté, vérifié sur ce poste | installation depuis un clone propre **jamais testée** |
| Versionnement Git / dépôt GitHub officiel | **non réalisé** | dépôt initialisé, aucun commit (autorisation requise) |

## 6. Code non commité (dépôt Git)

Le dépôt n'a **aucun commit** : l'intégralité du projet est non versionnée. Modifications des dernières sessions,
présentes dans l'arbre de travail et dans les conteneurs backend/frontend en service :
indicateur d'ancrage (`chain_anchor`) dans l'API, le tableau de bord et la page Blockchain ; renforcement de
l'identité des ancrages (index unique, vérification de l'émetteur, instance des transactions, contrôle de
redémarrage pendant la soumission) + migration 0003 ; `404` pour les événements MISP inexistants ; règle
T1110.004 ; adresse du contrat abrégée ; scripts `verify_consistency.py`, `audit_chain_anchors.py` ;
test `tests/test_chain_anchor_identity.py` (18 cas).

## 7. Documentation

`README.md`, `data/README.md`, `docs/01…10`. **Écarts constatés** : les nombres de tests (69) et de règles, la
migration 0003, l'indicateur d'ancrage et l'import MISP vérifié ne sont pas à jour dans `docs/09_rapport_tests.md`
et `README.md` ; les documents `docs/TESTING_AND_VALIDATION.md` et `docs/PROJECT_COMPLETE_DOCUMENTATION.md`
demandés précédemment **n'existent pas encore** ; pas de guide d'annotation séparé ni de dossier de soutenance.
