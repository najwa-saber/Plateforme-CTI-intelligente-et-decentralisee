# 02 — Architecture technique

## 1. Vue d'ensemble

```mermaid
flowchart TB
  subgraph Client
    UI["Streamlit :8501<br/>8 pages · thèmes sombre/clair<br/>sélecteur d'organisation A/B/C"]
  end
  subgraph Backend["FastAPI :8000 (orchestrateur)"]
    R["routes : reports · organizations · system"]
    S["services : report_service · validation_service · scoring · reputation · audit"]
    NLP["nlp : parser · extractor · normalizer · validators · consistency"]
    ML["ml : preprocess · classifier (joblib) · baseline"]
    MI["mitre : catalog (STIX) · rules · enricher"]
    CO["correlation : engine"]
    AD["adaptateurs : misp (réel / simulé) · blockchain (Web3.py)"]
  end
  PG[("PostgreSQL 16<br/>off-chain")]
  MISP[("MISP 2.5 : misp-core + misp-nginx<br/>mariadb · valkey · modules")]
  HH[("Hardhat node :8545<br/>CTIValidation.sol")]
  UI -- "REST JSON + X-API-Key" --> R --> S
  S --> NLP & ML & MI & CO
  S --> AD
  S -- SQLAlchemy --> PG
  AD -- "PyMISP (HTTPS)" --> MISP
  AD -- "JSON-RPC" --> HH
```

Le backend est le seul composant qui parle à PostgreSQL, MISP et Ethereum ; le frontend ne contient aucune logique
métier. Les adaptateurs isolent les dépendances externes (MISP réel / simulé, client Web3 / double de test).

## 2. Séparation on-chain / off-chain

| Donnée | Emplacement | Raison |
|---|---|---|
| Texte du rapport, titre, provenance, TLP | PostgreSQL + attribut `text` MISP | volumineux, potentiellement sensible |
| IOC normalisés, contexte, drapeaux, confiance d'extraction | PostgreSQL + attributs MISP (`to_ids=false`) | données d'analyse |
| Classification, techniques ATT&CK, anomalies, qualité | PostgreSQL (+ tags MISP pour ATT&CK) | dérivées, recalculables |
| Scores, historique de réputation analytique, corrélations, audit | PostgreSQL | explicabilité, historique |
| Empreinte SHA-256 du rapport canonisé, identifiant externe | **Ethereum** | intégrité, horodatage |
| Adresses des organisations, votes, statut | **Ethereum** | validation collaborative traçable |
| Réputation protocolaire bornée | **Ethereum** | règle du protocole, non falsifiable par le backend |

**Canonicalisation (`core/canonical.py`, version `cti-report/v1`)** : JSON trié, sans espaces superflus, UTF-8 ;
texte normalisé NFC, fins de ligne `\n`, espaces de fin supprimés ; IOC dédoublonnés et triés ; champs : identifiant,
titre, texte, source, date de publication, TLP, organisation émettrice, IOC non mal formés. Les résultats d'analyse
(ML, ATT&CK) sont **exclus** pour qu'un ré-entraînement ne casse pas la vérification. La même fonction sert à la
soumission et à la vérification.

## 3. Diagrammes de séquence

### 3.1 Import et analyse

```mermaid
sequenceDiagram
  actor A as Org A (Streamlit)
  participant API as FastAPI
  participant DB as PostgreSQL
  participant M as MISP
  A->>API: POST /api/v1/reports/upload (fichier, TLP)
  API->>API: parse sécurisé (taille, type, PDF texte seul)
  API->>DB: doublon exact ? (empreinte du texte) → 409 si oui
  API->>API: extraction + refang + normalisation + validation
  API->>DB: IOC déjà connus dans d'autres rapports
  API->>M: recherche des IOC (search attributes)
  API->>API: classification ML · règles ATT&CK + similarité STIX
  API->>API: incohérences · quasi-doublons · qualité Q · score provisoire
  API->>DB: rapport ANALYZED, IOC, techniques, score, corrélations
  API->>M: add_event (attributs, tags TLP / ATT&CK / statut)
  API-->>A: 201 {report_id, category, iocs, mitre_techniques, status, details…}
```

### 3.2 Validation collaborative

```mermaid
sequenceDiagram
  actor A as Org A
  actor B as Org B
  actor C as Org C
  participant API as FastAPI
  participant SC as CTIValidation.sol
  participant M as MISP
  A->>API: POST /reports/{id}/submit
  API->>API: SHA-256(canonique)
  API->>SC: submitReport(hash, id) (eth_call puis transaction)
  SC-->>API: ReportSubmitted(reportId, eligible=2)
  API->>M: tags sha256 / statut PENDING
  B->>API: POST /reports/{id}/vote {approve:true}
  API->>SC: voteReport(reportId, true)
  API->>SC: previewFinalization → (false, PENDING)
  C->>API: POST /reports/{id}/vote {approve:true}
  API->>SC: voteReport(reportId, true)
  API->>SC: previewFinalization → (true, VALIDATED)
  API->>SC: finalizeReport(reportId)
  SC-->>API: ReportFinalized + ReputationUpdated ×3
  API->>API: réputation analytique · score final
  API->>M: tag statut VALIDATED (remplace PENDING)
  API-->>C: {finalized:true, status:VALIDATED}
```

## 4. Dépendances entre composants

| Composant | Dépend de | Comportement si indisponible |
|---|---|---|
| Analyse | extracteur, classifieur (repli : baseline à mots-clés), catalogue ATT&CK | toujours disponible |
| MISP | instance réelle (mode `real`/`auto`) | `auto` : adaptateur simulé signalé ; `real` : `misp_sync_status=FAILED`, l'analyse aboutit, resynchronisation via `POST /reports/{id}/misp` |
| Ethereum | nœud Hardhat + fichier de déploiement | `503 blockchain_error` ; le rapport reste `ANALYZED`, soumission possible plus tard |
| Réseau Hardhat redémarré | — | ancrages précédents détectés (`chain_anchor_mismatch`), signalés dans l'interface |

## 5. Choix de conception

* **Règles métier dans le contrat** (double vote, auto-validation, éligibilité, majorité) : le backend les simule
  par `eth_call` avant d'envoyer la transaction et décode les erreurs Solidity personnalisées en `409`.
* **Instantané des validateurs éligibles** à la soumission : une organisation enregistrée après coup ne peut pas voter
  (protection contre l'ajout d'identités opportunistes).
* **Finalisation automatique** après le vote qui rend l'issue déterminable (`ETH_AUTO_FINALIZE`).
* **Comptes Ethereum** : comptes déverrouillés du nœud Hardhat par index (aucune clé privée dans le code) ou signature
  locale si `ORG_X_PRIVATE_KEY` est fournie.
* **Thèmes** : options natives `theme.*` de Streamlit modifiées à chaud + jetons de couleur pour les éléments
  personnalisés (voir `frontend/components/theme.py`).

## 6. Sécurité

| Mesure | Implémentation |
|---|---|
| Secrets | `.env` non versionné, généré par `scripts/generate_env.py` (CSPRNG) ; jamais affichés ni journalisés |
| Authentification | en-tête `X-API-Key`, clés stockées hachées SHA-256, comparaison à temps constant |
| Autorisation | émetteur seul pour analyser/soumettre/synchroniser ; non-émetteur pour voter ; TLP:RED visible par l'émetteur seul et non partageable on-chain |
| Entrées | Pydantic strict (`extra=forbid`, énumérations, longueurs, motifs ATT&CK, URL http(s)) |
| Fichiers | liste blanche d'extensions, contrôle du contenu (en-tête PDF, JSON, binaire), 5 Mo, 60 pages PDF, PDF chiffrés refusés, nom de fichier assaini |
| Blockchain | rôles vérifiés par le contrat, `Ownable` (enregistrement), `Pausable` (arrêt d'urgence) |
| Réseau | ports publiés sur `127.0.0.1` uniquement ; MISP en HTTPS (certificat auto-signé de laboratoire) |
| Traçabilité | `audit_logs` (succès et refus), événements Solidity, historique de réputation |
| Erreurs | format JSON homogène avec `request_id`, sans trace ni détail interne |
| En-têtes HTTP | `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store` ; CORS limité au frontend |
