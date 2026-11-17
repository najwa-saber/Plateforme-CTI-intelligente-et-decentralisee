# Plan de finalisation — 17/11/2026

Priorisé à partir de `PROJECT_CURRENT_STATE.md`, `AI_ML_NLP_AUDIT.md`, `TESTS_CURRENT_STATUS.md` et
`REQUIREMENTS_TRACEABILITY.md`. **Aucune tâche n'est engagée sans autorisation.**

## Criticité BLOQUANTE (livraison)

### B1 — Statuer sur les modifications non commitées et la migration 0003
* **Problème** : le dépôt n'a aucun commit ; la migration additive 0003 est appliquée en base et le code de
  renforcement des ancrages tourne dans les conteneurs, sans être versionné ni documenté.
* **Pourquoi** : l'état livré doit être identifiable et reproductible.
* **Solution** : conserver 0003 (recommandé : additive, testée) ; relancer la suite complète (84 + 4 *live*) et le
  scénario ; mettre à jour la documentation ; puis commit initial (B2).
* **Fichiers** : `backend/alembic/versions/0003_*`, `app/models/entities.py`, `app/services/validation_service.py`,
  `app/misp/pymisp_adapter.py`, `app/mitre/rules.py`, `tests/test_chain_anchor_identity.py`, `frontend/views/*`.
* **Tests** : `pytest` complet (88), Hardhat (21), `run_demo_scenario.py`, `verify_consistency.py`, `audit_chain_anchors.py`.
* **Résultat attendu** : 88/88, 21/21, scénario 24/24, cohérence 12/12, audit OK.

### B2 — Versionnement (CDC §14)
* **Problème** : aucun commit, aucun dépôt distant.
* **Solution** : commit initial (message proposé ci-dessous) après revue ; ensuite, si souhaité, push vers
  `github.com/eamalea/intelligent-decentralized-cti` (action externe, autorisation explicite).
* **Tests** : scan des secrets (déjà négatif), `git check-ignore` (`.env`, `node_modules`, bundle MITRE).
* **Résultat attendu** : historique propre, aucun secret versionné.

Message de commit proposé :

```
feat: plateforme CTI intelligente et décentralisée (prototype PFE)

- FastAPI + PostgreSQL (Alembic 0001-0003) : import TXT/PDF/JSON/MISP, extraction et
  normalisation des IOC, doublons, incohérences, classification TF-IDF + régression
  logistique, enrichissement MITRE ATT&CK (STIX v20.1), score et réputation, corrélation
- MISP réel via PyMISP (+ adaptateur simulé de secours)
- Contrat CTIValidation.sol (Hardhat, OpenZeppelin) : soumission d'empreintes, votes,
  majorité, réputation bornée ; détection des changements d'instance du réseau local
- Streamlit (8 pages, thèmes sombre/clair), Docker Compose, corpus synthétique annoté
- Tests : 88 pytest (dont 4 live), 21 Hardhat ; documentation docs/
```

## Criticité ÉLEVÉE

| ID | Problème | Pourquoi | Solution recommandée | Fichiers | Tests | Résultat attendu |
|---|---|---|---|---|---|---|
| E1 | Documentation désynchronisée (69 tests, 53 règles, 0003, ancrage, import MISP) ; `TESTING_AND_VALIDATION.md` et `PROJECT_COMPLETE_DOCUMENTATION.md` absents | cohérence code/doc exigée en soutenance | mettre à jour `README.md`, `docs/03`, `docs/09` ; rédiger les 2 documents (cause/correction de la collision, tests, dossier de présentation 10 points) | `docs/*`, `README.md` | relecture croisée avec les rapports JSON | docs alignées sur l'état réel |
| E2 | Tests *live* et scénario non relancés après les derniers changements | preuves à jour | relancer (écrit dans MISP et sur la chaîne de démo) | — | `pytest -m "live_chain or live_misp"`, scénario | 4/4, 24/24 |
| E3 | Reproductibilité : images MISP `latest`, pas de lock Python, installation propre non testée | NF06 | épingler les images par tag/digest, générer `requirements.lock`, tester un clone propre dans un dossier séparé | `docker-compose.yml`, `backend/`, `frontend/` | `docker compose up` depuis un clone vierge | NF06 → TV |
| E4 | Présentation scientifique du ML | éviter une sur-interprétation devant le jury | ajouter IC 95 % et McNemar dans `docs/05`, formuler « égalité avec la baseline » | `docs/05_evaluation.md` | — | discours honnête et défendable |
| E5 | Pas de tests automatisés d'interface | régressions UI non détectées (plusieurs bugs trouvés manuellement) | suite `streamlit.testing.v1.AppTest` : 8 pages, thèmes, persistance `?theme/?org/?report`, ancrage | `frontend/tests/` | `pytest frontend/tests` | 8 pages × 2 thèmes sans exception |

## Criticité MOYENNE

| ID | Problème | Solution | Fichiers | Résultat attendu |
|---|---|---|---|---|
| M1 | Guide d'annotation absent (C18.2), catégorie non justifiée par rapport (C4.9) | `data/ANNOTATION_GUIDE.md` + champ `category_rationale` | `data/` | C4.9, C18.2 → TV |
| M2 | Corpus 100 % synthétique (C4.1, C4.2) | ajouter ~20 extraits publics annotés (licence notée) ; flux URLhaus/MalwareBazaar en environnement isolé | `data/` | évaluation sur données réelles |
| M3 | Pondérations du score non testées (C10.1) | analyse de sensibilité (variation ±0,1 des poids, effet sur le classement) | `backend/scripts/` | justification chiffrée |
| M4 | Temps de traitement non mesuré (cadrage §9) | chronométrage par étape (extraction, ML, ATT&CK, MISP, transactions) | `report_service.py` (journalisation), script d'évaluation | tableau de latences |
| M5 | Contradictions inter-rapports partielles (K4.2) | signaler un IOC présent dans un rapport VALIDATED et un rapport REJECTED / étiquettes divergentes | `nlp/consistency.py` | K4.2 → TV |
| M6 | Audit responsive interrompu | terminer le contrôle mobile (375 px) des 8 pages | — | absence de débordement |
| M7 | Démo : réputation de A plafonnée (+0) après démonstrations répétées le même jour | rejouer la démo après 24 h ou avec une autre organisation émettrice ; l'expliquer au jury | `docs/08` | variation visible |
| M8 | Rapport final / mémoire (C18.9) non rédigé | à partir de `docs/` | — | livrable académique |

## Améliorations OPTIONNELLES

* Réseau Ethereum persistant (Besu/geth privé ou Anvil avec état) — supprime la cause des collisions d'identifiants.
* Modèle préentraîné (SecureBERT *fine-tuné*) et classification multi-étiquettes, comparaison statistique.
* Heuristique contre les numéros de version pris pour des IPv4 ; IPv6, e-mails, SHA-1.
* Export STIX 2.1 / TAXII ; synchronisation MISP ↔ MISP entre organisations.
* Authentification par utilisateur (JWT), limitation de débit, rotation des clés.
* Thème par session (actuellement global au serveur Streamlit) ; messages d'erreur API en français.

## Ordre recommandé

B1 → E2 → E1 → B2 (commit) → E4 → E5 → E3 → M3, M4, M1 → M8 → options.
