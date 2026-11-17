# Audit de sécurité

Audit du 17/11/2026. Complète [`GIT_SECURITY_AUDIT.md`](GIT_SECURITY_AUDIT.md) (dépôt Git) et la section sécurité de
[`02_architecture.md`](02_architecture.md) §6 (mesures applicatives). Chaque résultat est issu d'une exécution réelle.

## 1. Synthèse

| Contrôle | Outil / méthode | Résultat |
|---|---|---|
| Secrets dans les fichiers versionnables (259 fichiers) | gitleaks v8.21.2 (`detect --no-git --redact`) | **aucune fuite** |
| Secrets : valeurs réelles du `.env` recherchées dans les fichiers candidats | script ad hoc (14 valeurs ≥ 12 caractères) + motifs (clés PEM, AWS, GitHub, GitLab, Slack, affectations `password/secret/token`) | **0 secret** ; seules coïncidences : noms d'organisation, e-mail admin MISP par défaut, URL SQLite par défaut (non sensibles) |
| `.env` exclu du dépôt | `git check-ignore .env` | ignoré |
| Vulnérabilités des dépendances Python (avant) | pip-audit 2.7.3 sur les locks | **5 paquets vulnérables** : pypdf 5.9.0, starlette 0.46.2, pytest 8.4.2, streamlit 1.45.1, pillow 11.3.0 |
| Vulnérabilités des dépendances Python (après correction) | pip-audit 2.7.3 | **0** sur 84 paquets backend et 46 paquets frontend (`test-reports/pip-audit-{b,f}.json`) |
| Qualité / code mort | ruff 0.8.4 | 15 avertissements corrigés ; « All checks passed! » |
| Images de base | épinglage par digest SHA-256 (`docker-compose.yml`, `docker/*.Dockerfile`) | toutes épinglées |
| Exposition réseau | `docker-compose.yml` | ports publiés sur `127.0.0.1` uniquement (8000, 8501, 8545, 8443, 5432) |
| Utilisateur des conteneurs applicatifs | Dockerfiles | backend et frontend en utilisateur non root (uid 10001) |

## 2. Mise à jour de sécurité des dépendances

| Paquet | Avant | Après | Avis corrigés (extraits) |
|---|---|---|---|
| pypdf (lecture des PDF importés — surface d'attaque directe) | 5.9.0 | 6.21.4 | > 60 (PYSEC-2026-1827…3027, GHSA-…) |
| starlette (via FastAPI) | 0.46.2 | 1.10.0 | PYSEC-2026-161, -248, -249, -1941, -1942, -2280, -2281 |
| fastapi | 0.115.14 | 0.163.1 | requis pour starlette ≥ 1.3.1 |
| pytest (outil de test) | 8.4.2 | 9.2.0 | PYSEC-2026-1845 |
| streamlit | 1.45.1 | 1.67.0 | PYSEC-2026-212, PYSEC-2026-2285 |
| pillow (via streamlit) | 11.3.0 | 13.0.0 | > 50 (PYSEC-2026-165…4363, GHSA-…) |
| uvicorn, numpy, websockets, packaging | alignés entre backend et frontend | 0.54.0, 2.4.6, 17.4, 24.2 | pas de vulnérabilité ; un seul environnement peut installer les deux locks (nécessaire à la CI) |

Méthode : versions corrigées d'abord testées dans des conteneurs jetables (backend 85/85, interface 19/19, porte ML
identique : macro-F1 test 0,874, externe 1,00), puis adoptées dans `requirements.txt` / `requirements.lock`
(anciens fichiers sauvegardés hors dépôt), conteneurs backend et frontend reconstruits avec `--no-deps`
(PostgreSQL, MISP et Hardhat non touchés), tests relancés sur l'environnement local mis à jour.
Avertissement restant (non bloquant) : `websockets.client.connect` obsolète, émis par une bibliothèque tierce (web3), pas par le code du projet.

## 3. Mesures de sécurité applicatives (rappel, vérifiées par les tests)

* Authentification par clé API par organisation, stockée hachée (SHA-256), comparaison à temps constant.
* Autorisation : émetteur seul pour analyser / soumettre / synchroniser ; non-émetteur pour voter ; TLP:RED réservé à l'émetteur et jamais ancré.
* Entrées : Pydantic strict ; fichiers : liste blanche, contrôle du contenu, 5 Mo, 60 pages, PDF chiffrés refusés.
* Contrat : règles appliquées on-chain (auto-validation, double vote, éligibilité), `Ownable`, `Pausable`.
* Erreurs JSON homogènes sans trace interne ; en-têtes `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`.
* Journal d'audit des succès et des refus (`audit_logs`).

## 4. Risques résiduels

| Risque | Niveau | Commentaire |
|---|---|---|
| MISP avec certificat auto-signé, `verify_ssl=false` côté backend | moyen en production, acceptable en laboratoire | fournir un certificat signé avant tout déploiement réel |
| Comptes Hardhat déverrouillés (clés de développement publiques) | élevé hors laboratoire | n'utiliser qu'un réseau local ; signature locale `ORG_X_PRIVATE_KEY` prévue pour un autre réseau |
| Clés API transmises en clair entre navigateur et Streamlit/API | faible (127.0.0.1) | TLS obligatoire si exposé sur un réseau |
| Nouvelles CVE après le 17/11/2026 | variable | job CI `security:dependencies` (pip-audit) à chaque pipeline |
| Pas d'audit npm des dépendances Hardhat | faible (outil de développement, conteneur local) | `npm audit` non exécuté ; à ajouter si le nœud est exposé |
| Image Docker `misp-*:latest` épinglées par digest mais non auditées | moyen | images officielles MISP ; mise à jour manuelle du digest |

## 5. Rejouer

```bash
docker run --rm -v "<copie-des-fichiers-versionnables>:/repo:ro" zricethezav/gitleaks:v8.21.2 detect --source /repo --no-git --redact -v
```
```bash
pip-audit --no-deps --disable-pip -r backend/requirements.lock
```
```bash
pip-audit --no-deps --disable-pip -r frontend/requirements.lock
```
