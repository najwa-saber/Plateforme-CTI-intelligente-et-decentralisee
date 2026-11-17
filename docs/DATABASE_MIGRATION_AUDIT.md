# Audit des migrations et du schéma PostgreSQL — 17/11/2026

## Chaîne de migrations

| Révision | Parent | Contenu | Nature |
|---|---|---|---|
| `0001_initial_schema` | — | 11 tables : organizations, reports, iocs, mitre_matches, votes, chain_transactions, score_snapshots, reputation_events, correlations, misp_simulated_events, audit_logs (+ index et contraintes d'unicité) | création |
| `0002_chain_instance` | 0001 | `reports.chain_instance VARCHAR(66) NULL` | additive |
| `0003_chain_anchor_identity` | 0002 | index unique **partiel** `uq_reports_chain_anchor (chain_instance, chain_report_id) WHERE chain_instance IS NOT NULL AND chain_report_id IS NOT NULL` ; `chain_transactions.chain_instance VARCHAR(66) NULL` + index | additive |

Ordre linéaire, une seule tête (`alembic heads` = `0003 (head)`).

## État réel (lecture seule, conteneur backend)

* `alembic current` → **0003 (head)** ; `alembic_version` = `0003`.
* `alembic check` (comparaison modèles SQLAlchemy ↔ base réelle) → **« No new upgrade operations detected »** :
  le code backend et le schéma PostgreSQL sont cohérents (message informatif sur la séquence SERIAL de
  `score_snapshots`, sans écart).
* Index `uq_reports_chain_anchor` et colonne `chain_transactions.chain_instance` présents.

## Origine de 0003

Appliquée le 17/11 au redémarrage du backend (point d'entrée `alembic upgrade head`) pendant une reconstruction
interrompue ; conservée sur décision de l'utilisateur. Aucune ligne existante modifiée : les 2 rapports historiques
(`chain_instance` NULL) sont exclus de l'index partiel ; les transactions antérieures ont `chain_instance` NULL.

## Données historiques préservées

2 rapports ancrés sur une instance Hardhat disparue (`CTI-60C0B69D4E`, `CTI-9C938CFA11`) : inchangés, consultables,
signalés « instance précédente » (audit `docs/test-reports/chain_anchor_audit.json`).

## Points de vigilance

* Les tests pytest créent le schéma par `create_all` (SQLite) : la cohérence migrations ↔ modèles doit aussi être
  testée (ajouté : `tests/test_migrations.py`, exécution d'Alembic sur une base SQLite vierge + `alembic check`).
* Toute nouvelle migration doit rester additive ; aucun rollback de 0003.
