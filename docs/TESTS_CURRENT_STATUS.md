# État des tests — audit du 17/11/2026

Légende : **Exécuté (audit)** = relancé pendant cet audit ; **Exécuté (antérieur)** = résultat d'une exécution
précédente, non relancée ici (le plus souvent parce qu'elle écrit dans MISP ou sur la chaîne, ce que la consigne de
l'audit interdit) ; **Manuel** = vérification humaine/navigateur sans test automatisé versionné.

## 1. Vérification des résultats annoncés

| Annonce | Constat de l'audit | Nature |
|---|---|---|
| « 70 tests Python » | **88 tests** existent désormais (18 ajoutés pour les ancrages/MISP/ATT&CK). **84 passés** (hors tests *live*), exécution du 17/11 | Exécuté (audit) |
| 4 tests *live* (Hardhat réel ×2, MISP réel ×2) | non relancés (créent un événement MISP et déploient un contrat) ; dernière exécution réussie le 17/11 avant l'audit (70/70 dont le test MISP 404) | Exécuté (antérieur) |
| « 21 tests Hardhat » | **21 passing** (réseau Hardhat éphémère, sans effet sur le nœud en service) | Exécuté (audit) |
| « 24 vérifications d'intégration » (scénario) | dernier passage : `docs/test-reports/demo_scenario_run.json`, 17/11 08:24, **24/24** ; non relancé (écrit des données) | Exécuté (antérieur) |
| Cohérence API / PostgreSQL / contrat / MISP | **12/12 OK** (`verify_consistency.py`, lecture seule) | Exécuté (audit) |
| Audit des ancrages on-chain | **OK** : 2 rapports sur instance précédente, 3 courants, aucune transaction mal attribuée | Exécuté (audit) |
| « 8 pages frontend » | chargement sans exception en thème sombre (conteneur) et audit de contraste 8 pages × 2 thèmes (instance locale) le 16/11 ; scripts d'audit **non versionnés** | Manuel |
| Audit mobile / responsive | lancé puis **interrompu** — non conclu | Non réalisé |
| Tests MISP réels | `test_live_misp_event_lifecycle`, `test_live_misp_unknown_event_is_404` + import réel de l'événement 14 | Exécuté (antérieur) |
| Tests blockchain réels | `test_live_contract_full_validation_flow`, `test_live_contract_duplicate_and_disputed` | Exécuté (antérieur) |
| Évaluations NLP/ATT&CK/corrélation | rapports JSON du 16–17/11 ; métriques ML **recalculées** pendant l'audit (identiques) | Exécuté (antérieur) + recalcul |

## 2. Répartition des 88 tests Python

| Fichier | Tests | Couverture |
|---|---|---|
| `test_ioc_extraction.py` | 12 | 5 types d'IOC, refang, normalisation, doublons, mal formés, faux positifs, drapeaux, IOC déclarés, P/R sur corpus |
| `test_units.py` | 16 (+ paramétrés) | empreinte canonique, parseurs TXT/JSON/PDF et fichiers malveillants, classifieur et repli, ATT&CK, corrélation |
| `test_scoring_reputation.py` | 7 | politique V, formule S, pénalités Q, amortissement, plafonds, finalisation |
| `test_api.py` | 18 (+ paramétrés) | auth 401, 422, contrat CDC 8.3, aperçu, doublons 409, upload, TLP:RED, propriétaire 403, scénario complet, intégrité, REJECTED/DISPUTED/INCOMPLETE, MISP/chaîne indisponibles, redémarrage de chaîne |
| `test_chain_anchor_identity.py` | 13 (+ paramétrés) | collision d'identifiants entre instances, ligne historique sans instance, rapport historique PENDING, unicité en base, émetteur, altération d'empreinte, redémarrage pendant la soumission, transactions, MISP 404, tags remplaçants, ATT&CK (T1110.004 + non-régression corpus) |
| `test_live_integration.py` | 4 | contrat réel (flux complet, doublon, DISPUTED), MISP réel (cycle de vie, 404) |

Les tests « API » utilisent un **double en mémoire du contrat** (mêmes règles) ; le vrai contrat est couvert par les
21 tests Hardhat et les 2 tests *live*.

## 3. Fonctionnalités importantes sans test automatisé

1. **Interface Streamlit** : aucune suite `streamlit.testing` (AppTest) dans le dépôt (navigation, formulaires,
   sélecteur de thème, persistance `?theme=/?org=/?report=`, affichage de l'ancrage).
2. **Docker / installation** : pas de test d'installation depuis un clone propre ; pas de test des healthchecks.
3. **Migrations Alembic** : pas de test `upgrade`/`downgrade` automatisé (0003 appliquée manuellement en service).
4. **Import PDF réel** via l'API avec un PDF multi-pages (seul un PDF minimal est testé).
5. **Performance / temps de traitement** (critère du cadrage §9) : aucune mesure par étape.
6. **Concurrence** : votes simultanés, nonce des transactions signées localement.
7. **Scripts d'évaluation** : exécutés manuellement, non intégrés à la suite de tests (sauf la non-régression ATT&CK).

## 4. Commandes de reproduction

```bash
cd backend && ../.venv/Scripts/python -m pytest -q -m "not live_chain and not live_misp"
```

```bash
cd backend && ../.venv/Scripts/python -m pytest -q -m "live_chain or live_misp"
```

```bash
docker run --rm -v "$PWD/blockchain:/app" -v cti_bc_node_modules:/app/node_modules -w /app node:22-bookworm-slim sh -c "npx hardhat test"
```

```bash
python scripts/verify_consistency.py
```

```bash
python scripts/audit_chain_anchors.py
```
