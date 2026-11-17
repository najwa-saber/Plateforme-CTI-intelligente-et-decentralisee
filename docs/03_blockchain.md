# 03 — Blockchain et smart contract

Contrat : `blockchain/contracts/CTIValidation.sol` — Solidity 0.8.24, OpenZeppelin 5.4 (`Ownable`, `Pausable`),
Hardhat 2.29.2, réseau local `chainId 31337`. Déploiement : `blockchain/scripts/deploy.js` (compte 0 = administrateur
du consortium, comptes 1–3 = organisations A, B, C) ; il écrit `deployments/localhost.json` (adresse + ABI) lu par le
backend.

## Fonctions

| Fonction | Rôle | Contrôles |
|---|---|---|
| `registerOrganization(address, name)` | enregistre une organisation (réputation initiale 50,00) | `onlyOwner`, adresse non nulle, pas de doublon, ≤ 32 organisations |
| `setOrganizationActive(address, bool)` | désactive / réactive | `onlyOwner` |
| `submitReport(bytes32 hash, string externalId)` | ancre l'empreinte d'un rapport | organisation active, hash non nul, identifiant 1–64 car., **empreinte jamais soumise**, ≥ 1 validateur éligible |
| `voteReport(uint256 id, bool approve)` | vote | organisation active, rapport `PENDING`, **pas l'émetteur**, **éligible** (instantané), **un seul vote**, avant échéance |
| `previewFinalization(uint256 id)` | issue calculable maintenant ? | vue |
| `finalizeReport(uint256 id)` | applique la règle de majorité | organisation active ou owner ; refuse si l'issue n'est pas déterminable (`FinalizationTooEarly`) |
| `getReport`, `getReportStatus`, `getEligibleValidators`, `getReputation`, `getOrganizations`, `verifyIntegrity` | consultation | vues |
| `setVotingPeriod`, `pause`, `unpause` | administration | `onlyOwner`, période 60 s – 30 j |

## Règle de majorité (documentée dans le contrat)

`éligibles` = organisations actives au moment de la soumission, sauf l'émetteur ; `seuil = ⌊éligibles / 2⌋ + 1`.

| Situation | Statut |
|---|---|
| approbations ≥ seuil | **VALIDATED** |
| rejets ≥ seuil | **REJECTED** |
| tous les éligibles ont voté, aucune majorité | **DISPUTED** |
| échéance dépassée, aucune majorité | **INCOMPLETE** |
| sinon | reste **PENDING** (finalisation refusée) |

Avec A, B, C : A soumet → B et C éligibles, seuil 2 : deux oui = VALIDATED, deux non = REJECTED, un oui + un non =
DISPUTED, un seul vote = PENDING (jusqu'au second vote ou à l'échéance de 7 jours → INCOMPLETE).

## Réputation protocolaire (on-chain, en centièmes)

| Événement | Variation |
|---|---|
| Émetteur, rapport VALIDATED | +3,00 |
| Émetteur, rapport REJECTED | −5,00 |
| Validateur dont le vote suit la décision finale | +1,00 |
| Validateur dont le vote contredit la décision | −1,00 |
| Validateur éligible n'ayant pas voté (VALIDATED, REJECTED, INCOMPLETE) | −0,50 |
| DISPUTED | aucune variation |

Bornes : **10,00 ≤ réputation ≤ 90,00** (pas d'exclusion définitive, pas de domination permanente). Chaque variation
émet `ReputationUpdated(org, reportId, ancienne, nouvelle, delta, raison)`. La réputation **analytique** (off-chain,
`services/reputation.py`) ajoute la qualité Q des rapports, un amortissement près des bornes, un plafond de 5 points
par événement et de 10 points par 24 h ; c'est elle qui alimente R dans le score.

## Événements (traçabilité)

`OrganizationRegistered`, `OrganizationStatusChanged`, `VotingPeriodUpdated`, `ReportSubmitted`, `VoteCast`,
`ReportFinalized`, `ReputationUpdated` — lus par `GET /api/v1/reports/{id}/chain-events`.

## Erreurs personnalisées → API

Le backend simule chaque transaction (`eth_call`) puis décode le sélecteur de l'erreur Solidity :
`SelfValidation`, `AlreadyVoted`, `NotEligible`, `NotRegistered`, `FinalizationTooEarly`, `DuplicateReport`,
`VotingClosed`, `NotPending`… → réponse `409 contract_revert` avec `details.contract_error`.

## Vérification d'intégrité

`GET /api/v1/reports/{id}/integrity` recalcule le SHA-256 de la représentation canonique et le compare
(1) à l'empreinte enregistrée à la soumission et (2) à l'empreinte stockée sur Ethereum (`verifyIntegrity`).
Une altération du texte en base est détectée (`INTEGRITY FAILURE`, test `test_integrity_failure_is_detected`).

## Réseau en mémoire : redémarrage de Hardhat

Le nœud Hardhat ne persiste pas son état ; après un redémarrage, le contrat est redéployé **à la même adresse**
(déploiement déterministe) et les identifiants on-chain recommencent à 1. Pour ne jamais lire l'enregistrement d'un
autre rapport :

* chaque rapport mémorise `chain_instance` = hash du bloc de déploiement (différent à chaque démarrage) ;
* avant toute lecture ou transaction, le backend vérifie instance, existence et `externalId` (`anchored_view`) ;
* en cas de discordance : `409 chain_anchor_mismatch`, intégrité « non vérifiable on-chain » (la comparaison
  off-chain reste affichée), avertissement dans `/api/v1/health` et dans la barre latérale.

Voir [07_troubleshooting.md](07_troubleshooting.md) pour la remise à zéro cohérente de l'environnement.

## Tests

`blockchain/test/CTIValidation.test.js` (21 tests) : enregistrement, droits, soumission, doublon d'empreinte, vote
autorisé, double vote, auto-validation, compte non autorisé, éligibilité tardive, échéance, finalisation prématurée,
VALIDATED, REJECTED, DISPUTED, INCOMPLETE, double finalisation, bornes de réputation, intégrité, pause.
Plus 2 tests *live* Python contre un contrat fraîchement déployé sur le nœud réel (`test_live_integration.py`).

```bash
docker run --rm -v "$PWD/blockchain:/app" -v cti_bc_node_modules:/app/node_modules -w /app node:22-bookworm-slim sh -c "npm ci && npx hardhat test"
```
