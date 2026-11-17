# 10 — Limites et perspectives

## Intégrations réelles, simulations et limites

| Élément | Nature |
|---|---|
| PostgreSQL, FastAPI, Streamlit | réels, conteneurisés |
| MISP 2.5.51 (misp-docker) via PyMISP | **réel** ; adaptateur **simulé** disponible en secours (signalé) |
| Ethereum | **réel mais local** (Hardhat, en mémoire, un seul nœud) — pas de réseau public ni de consensus distribué |
| Trois organisations | **simulées** dans une même interface, comptes Hardhat déverrouillés |
| Corpus | **synthétique** (80 rapports, un seul auteur) ; IOC fictifs |
| Tests Python « API » | double du contrat en mémoire (mêmes règles) ; le vrai contrat est testé par Hardhat et par les tests *live* |

## Limites scientifiques

* **ML** : 16 documents de test ; le modèle n'est pas significativement meilleur que la baseline à mots-clés ;
  aucune conclusion de généralisation à des rapports réels. Catégorie unique par rapport alors que les rapports
  réels mêlent souvent plusieurs menaces.
* **Extraction** : regex + validation ; numéros de version pris pour des IPv4 ; IPv6, e-mails, SHA-1, chemins,
  clés de registre et artefacts non couverts ; aucune vérification de réputation externe des IOC.
* **ATT&CK** : règles écrites en connaissant le corpus (P = 0,62, R = 0,76, optimistes) ; pas de compréhension
  sémantique (négations, hypothèses).
* **Score** : pondérations du CDC non optimisées faute de vérité terrain sur la fiabilité ; Q repose sur des
  heuristiques documentées.
* **Corrélation** : négatifs faciles dans `relations.csv` ; liens de campagne sans IOC commun peu détectés (4/10).

## Limites techniques

* **Gouvernance centralisée** : un administrateur (`owner`) enregistre les organisations ; pas de Proof-of-Quality
  complet (exclu par le cadrage).
* **Réseau en mémoire** : un redémarrage de Hardhat efface la chaîne (détecté et signalé, voir dépannage).
* **Réputation** : la récompense des votes alignés sur la majorité peut inciter au suivisme ; avec trois
  organisations, deux organisations peuvent coopérer pour valider ou rejeter.
* **Clés** : comptes déverrouillés du nœud de développement ; en production, chaque organisation signerait avec sa
  propre clé (option `ORG_X_PRIVATE_KEY` déjà prévue) ou un HSM/portefeuille.
* **Thème** : réglage global du serveur Streamlit (partagé par les sessions ouvertes).
* **Messages d'erreur** de l'API en anglais, interface en français.
* **Authentification** par clé API statique (pas d'utilisateurs individuels, pas de rotation automatique).

## Perspectives

1. Corpus réel annoté (rapports publics sous licence) et comparaison avec un modèle de langue spécialisé
   (SecureBERT en *fine-tuning*), classification multi-étiquettes.
2. Import contrôlé de flux URLhaus / MalwareBazaar dans un environnement isolé, avec étiquettes `malicious`.
3. Réseau Ethereum privé multi-nœuds (une organisation = un nœud) ou Hyperledger Besu ; gouvernance du registre par
   vote des membres ; état persistant.
4. Sélection pondérée des validateurs par réputation (inspiration Proof-of-Quality), délais et quorum adaptatifs.
5. Export STIX 2.1 / TAXII des rapports validés ; synchronisation MISP ↔ MISP entre organisations.
6. Apprentissage des pondérations du score à partir de retours d'analystes.
