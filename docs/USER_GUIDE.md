# Guide utilisateur

Ce guide présente l'usage par rôle. La description page par page et le scénario de soutenance minuté sont dans
[`08_guide_utilisation.md`](08_guide_utilisation.md) (référence, non dupliquée ici).

Interface : http://127.0.0.1:8501 — barre latérale : thème (Sombre / Clair), organisation active (A, B, C),
état des services. Sur téléphone et tablette, la barre latérale est repliée par défaut (bouton `>` en haut à gauche).
Liens directs reproductibles : `?theme=dark|light`, `?org=A|B|C`, `?report=<identifiant>`.

## 1. Rôles

| Rôle | Peut | Ne peut pas |
|---|---|---|
| Organisation émettrice | importer, analyser, synchroniser MISP, soumettre on-chain, finaliser | voter sur son propre rapport |
| Organisation validatrice (éligible à la soumission) | voter approuver / rejeter, finaliser après le délai | modifier le rapport, voter deux fois |
| Toute organisation | consulter tableau de bord, corrélations, scores, réputations | voir un rapport TLP:RED d'une autre organisation |

## 2. Parcours type

1. **Importer** (*Importation CTI*) : fichier TXT, PDF (≤ 60 pages, non chiffré) ou JSON, ≤ 5 Mo ; ou saisie manuelle ;
   aperçu possible sans enregistrement. Un rapport identique déjà importé est refusé (doublon).
2. **Lire l'analyse** (*Analyse des menaces*) : catégorie et probabilités, termes explicatifs, IOC normalisés avec
   leurs drapeaux, techniques ATT&CK avec la phrase source, anomalies et indice de qualité Q.
3. **Partager** (*Gestion MISP*) : synchroniser l'événement (attributs `to_ids=false`, tags TLP et ATT&CK).
4. **Ancrer et valider** (*Validation blockchain*) : soumettre l'empreinte SHA-256 ; les autres organisations votent ;
   la finalisation est automatique dès que la majorité est acquise ; *Vérifier l'intégrité* recalcule l'empreinte.
5. **Évaluer** (*Fiabilité & réputation*) : score S = 0,30 R + 0,30 Q + 0,40 V et sa décomposition ; évolution des réputations.
6. **Relier** (*Corrélation*) : graphe des rapports liés, seuil et pondérations réglables, justification de chaque lien.

## 3. États d'un rapport

| Statut | Signification |
|---|---|
| IMPORTED | importé, analyse non encore effectuée |
| ANALYZED | analysé, pas encore soumis on-chain |
| PENDING | soumis, vote en cours |
| VALIDATED / REJECTED | majorité d'approbations / de rejets atteinte |
| DISPUTED | votes partagés sans majorité possible |
| INCOMPLETE | délai de vote écoulé sans quorum |

Colonne *Ancrage* : « ✔ chaîne actuelle », « ⚠ instance précédente (non vérifiable) » (le nœud Hardhat a redémarré
depuis la soumission), « ? nœud injoignable ».

## 4. Messages fréquents

| Message | Cause | Action |
|---|---|---|
| `409` doublon | rapport déjà importé (même empreinte) | ouvrir le rapport existant |
| Refus du contrat (`FinalizationTooEarly`, `AlreadyVoted`, `SelfValidation`…) | règle du protocole appliquée par le contrat | normal ; voir `03_blockchain.md` |
| « MISP · SIMULÉ » | MISP réel non démarré ou injoignable | démarrer le profil `misp` ou continuer en mode simulé |
| `503` MISP | événement MISP absent ou service indisponible | re-tester la connexion (*Gestion MISP*) |
| Fichier refusé | extension, contenu, taille ou PDF chiffré | fournir un fichier conforme |

## 5. Bonnes interprétations

Un IOC syntaxiquement valide n'est pas forcément malveillant ; une technique ATT&CK proposée par règle est une
hypothèse justifiée ; le score S n'est pas une probabilité de véracité ; la blockchain prouve l'intégrité et la
traçabilité des votes, pas la vérité du contenu.
