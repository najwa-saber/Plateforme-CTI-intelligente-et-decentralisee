# 04 — API REST (FastAPI)

Documentation interactive générée : **http://localhost:8000/docs** (Swagger) et **/redoc** ; schéma : `/openapi.json`.

## Authentification et autorisation

Chaque organisation possède une clé API (variables `ORG_A_API_KEY`… de `.env`, stockées hachées en base), envoyée dans
l'en-tête `X-API-Key`. Règles : seul l'émetteur peut analyser, soumettre ou resynchroniser un rapport ; seuls les
autres peuvent voter ; un rapport `TLP:RED` n'est visible que de son émetteur et ne peut pas être soumis on-chain.
`/health` et `/api/v1/health` sont publics (aucune donnée métier).

## Endpoints du contrat initial (CDC 8.1)

| Méthode | Endpoint | Fonction |
|---|---|---|
| POST | `/api/v1/reports` | Importer un rapport (saisie / JSON avec IOC déclarés) ; `?analyze=false` pour ne pas analyser |
| POST | `/api/v1/reports/analyze` | Importer + analyser (`persist=false` : aperçu sans enregistrement) |
| GET | `/api/v1/reports` | Lister (filtres `status`, `category`, `submitter`, `q`, pagination) |
| GET | `/api/v1/reports/{id}` | Détail complet (IOC, ATT&CK, anomalies, qualité, MISP, blockchain, votes, scores) |
| POST | `/api/v1/reports/{id}/submit` | Soumettre l'empreinte SHA-256 sur Ethereum |
| POST | `/api/v1/reports/{id}/vote` | Voter `{approve, comment}` (finalisation automatique si l'issue est déterminée) |
| GET | `/api/v1/reports/{id}/status` | Statut off-chain + on-chain, votes, aperçu de finalisation |
| GET | `/api/v1/reports/{id}/correlations` | Corrélations (`min_score`, poids `w_ioc`, `w_mitre`, `w_text`, `w_time`, `w_category`) |
| GET | `/api/v1/organizations` | Organisations, réputations off/on-chain, statistiques |
| GET | `/api/v1/organizations/{id}/reputation` | Réputation, politique, historique expliqué |

## Endpoints complémentaires

| Méthode | Endpoint | Fonction |
|---|---|---|
| POST | `/api/v1/reports/upload` | Import de fichier TXT / PDF / JSON (multipart) |
| POST | `/api/v1/reports/import-misp/{event}` | Importer un événement MISP existant |
| POST | `/api/v1/reports/{id}/analyze` | Relancer l'analyse (interdit après soumission) |
| POST | `/api/v1/reports/{id}/misp` | (Re)synchroniser vers MISP |
| POST | `/api/v1/reports/{id}/finalize` | Finaliser explicitement |
| GET | `/api/v1/reports/{id}/integrity` | Vérification d'intégrité (hash recalculé vs on-chain) |
| GET | `/api/v1/reports/{id}/score` | Score courant détaillé + historique |
| GET | `/api/v1/reports/{id}/chain-events` | Événements Solidity du rapport |
| GET | `/api/v1/organizations/me` | Organisation authentifiée |
| GET | `/api/v1/correlations/graph`, POST `/api/v1/correlations/recompute` | Graphe / recalcul global |
| GET | `/api/v1/iocs` | Recherche d'IOC |
| GET | `/api/v1/misp/status`, `/misp/events`, `/misp/events/{ref}`, `/misp/search` | MISP (mode réel/simulé indiqué) |
| GET | `/api/v1/blockchain/status`, `/blockchain/transactions` | Nœud, contrat, transactions |
| GET | `/api/v1/stats/dashboard` | Indicateurs du tableau de bord |
| GET | `/api/v1/ml/model`, `/api/v1/mitre/info`, `/api/v1/mitre/techniques/{id}` | Modèle et catalogue |
| GET | `/api/v1/audit` | Journal d'audit de l'organisation |
| GET | `/health`, `/api/v1/health` | Liveness / état des composants |

## Erreurs

Format unique : `{"error": {"code", "message", "details", "request_id"}}`.

| Code | Cas |
|---|---|
| 400 | requête invalide (type de fichier, TLP…) |
| 401 | clé API absente ou invalide |
| 403 | action non autorisée (non-émetteur, auto-validation, TLP:RED) |
| 404 | rapport / organisation / événement introuvable |
| 409 | conflit : doublon de rapport, déjà soumis, double vote, règle du contrat (`contract_revert`), ancrage perdu (`chain_anchor_mismatch`) |
| 413 | fichier ou texte trop volumineux |
| 422 | validation Pydantic (`validation_error`) ou contenu illisible |
| 500 | erreur interne (message générique + `request_id`) |
| 503 | MISP ou Ethereum indisponible (`misp_error`, `blockchain_error`) |

## Exemples

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/reports/analyze -H "X-API-Key: $ORG_A_API_KEY" -H "Content-Type: application/json" -d '{"title":"Phishing campaign","text":"A phishing campaign used attack.example to harvest credentials from employees."}'
```

Réponse (extrait, conforme au CDC 8.3) :

```json
{"report_id": "CTI-1A2B3C4D5E", "category": "phishing",
 "iocs": [{"type": "domain", "value": "attack.example", "status": "valid"}],
 "mitre_techniques": ["T1566.002"], "status": "ANALYZED", "details": {"…": "…"}}
```

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/reports/CTI-1A2B3C4D5E/vote -H "X-API-Key: $ORG_B_API_KEY" -H "Content-Type: application/json" -d '{"approve": true, "comment": "IOC observés"}'
```
