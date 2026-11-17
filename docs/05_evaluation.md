# 05 — Pipeline ML et évaluation

> Tous les chiffres ci-dessous proviennent d'exécutions réelles (fichiers `backend/app/ml/artifacts/metrics.json`
> et `docs/test-reports/*.json`). Ils portent sur un **corpus synthétique** : ils ne démontrent pas une
> généralisation à des rapports réels.

## 1. Classification des menaces

**Pipeline** : texte (titre + corps) → refang → masquage des indicateurs (`urltoken`, `iptoken`, `hashtoken`,
`domaintoken`, `cvetoken`, `numtoken`) → minuscules → `TfidfVectorizer` (1–2 grammes, `sublinear_tf`, stop-words
anglais, `max_df=0.9`) → `LogisticRegression` (`class_weight=balanced`) → catégorie + probabilités + termes
explicatifs (tf-idf × coefficient). Le masquage empêche le modèle de mémoriser les IOC d'une campagne.

**Protocole anti-fuite** : découpage 48/16/16 **groupé par campagne** ; TF-IDF ajusté uniquement sur l'apprentissage
(pipeline scikit-learn) ; C choisi sur la validation (macro-F1, départage par log-loss) ; modèle final ré-entraîné sur
apprentissage + validation puis évalué **une seule fois** sur le test ; estimation complémentaire par validation croisée
groupée (5 plis, `StratifiedGroupKFold`).

**Sélection** : C ∈ {0,1 ; 1 ; 10 ; 100} → macro-F1 validation {1,00 ; 1,00 ; 0,94 ; 1,00} ; log-loss
{1,356 ; 1,171 ; 0,825 ; 0,568} → **C = 100**.

**Résultats sur le test (16 documents)**

| Modèle | Accuracy | Macro-F1 |
|---|---|---|
| **TF-IDF + régression logistique (retenu)** | **0,875** | **0,874** |
| Baseline mots-clés (règles) | 0,875 | 0,861 |
| TF-IDF + Random Forest | 0,750 | 0,754 |
| Classe majoritaire | 0,250 | 0,100 |

| Catégorie | Précision | Rappel | F1 |
|---|---|---|---|
| Phishing | 1,00 | 0,75 | 0,86 |
| Ransomware | 0,80 | 1,00 | 0,89 |
| Malware | 0,75 | 0,75 | 0,75 |
| Exploitation | 1,00 | 1,00 | 1,00 |

Matrice de confusion (lignes = réel, colonnes = prédit ; phishing, ransomware, malware, exploitation) :
`[[3,0,1,0],[0,4,0,0],[0,1,3,0],[0,0,0,4]]`. Erreurs : CTI-010 (phishing livrant un voleur de mots de passe, annoté
ambigu → prédit malware, p = 0,47) et CTI-048 (wiper → prédit ransomware, p = 0,55) — confusions sémantiquement
plausibles.

**Validation croisée groupée** : accuracy 0,897 ± 0,076 ; macro-F1 **0,881 ± 0,082**.

**Lecture honnête** : sur 16 documents, une erreur vaut 6,25 points ; le modèle appris **n'est pas significativement
meilleur** que la baseline à mots-clés sur ce test. Son intérêt est méthodologique (probabilités calibrées par
classe, explicabilité par termes, ré-entraînement possible sur des données réelles). Corpus rédigé par un seul
auteur : vocabulaire homogène, résultats optimistes.

Ré-entraînement : `cd backend && python -m app.ml.train` (déterministe, `random_state=42`).

## 2. Extraction des IOC

Commande : `cd backend && python scripts/evaluate_ioc_extraction.py`.

| Jeu | Éléments | Précision | Rappel | F1 |
|---|---|---|---|---|
| Corpus annoté (182 IOC) | 80 rapports | 1,000 | 1,000 | 1,000 |
| **Jeu *challenge* indépendant** (30 IOC) | 25 cas difficiles | **0,968** | **1,000** | **0,984** |

* Le corpus est optimiste : même auteur que l'extracteur, et une règle (`.onion`, RFC 7686) a été ajoutée après
  inspection d'une erreur sur ce corpus.
* Le jeu *challenge* a été écrit après le gel de l'extracteur et évalué une seule fois sans réglage : formes défangées
  variées, IP avec port, noms de fichiers, numéros de version, hash en majuscules et tronqués, liens Markdown, JSON,
  identifiants de code, abréviations, listes. **Erreur restante** : le numéro de version `4.12.0.3` est extrait comme
  IPv4 (syntaxiquement valide) — limite connue, l'analyste voit le contexte de la phrase.
* Rappel : la confiance affichée est une confiance *d'extraction*, jamais une probabilité de malveillance.

## 3. Enrichissement MITRE ATT&CK

Commande : `cd backend && python scripts/evaluate_enrichment_correlation.py`. Correspondance stricte des identifiants
entre les propositions par **règles** et les techniques annotées : **précision 0,623, rappel 0,762, F1 0,685**
(tp = 109, fp = 66, fn = 34). Faux positifs les plus fréquents : T1105, T1078, T1567, T1059.004, T1110 — techniques
plausibles mais non annotées. Les règles ont été écrites en connaissant le corpus : estimation optimiste. Les
suggestions par similarité avec les descriptions STIX officielles sont présentées comme faibles et exclues de cette
mesure.

## 4. Corrélation

Même commande ; 163 paires de `relations.csv`, caractéristiques produites par le vrai pipeline, seuil 0,30 :
**précision 1,000, rappel 0,814, F1 0,897** (tp = 35, fp = 0, fn = 8, tn = 120).

| Type de relation | Détectées |
|---|---|
| hash partagé | 8/8 |
| domaine partagé | 10/10 |
| URL partagée | 1/1 |
| IP partagée | 12/14 |
| même campagne sans IOC commun | 4/10 |
| aucune relation (négatifs) | 0/120 fausses alertes |

Les négatifs sont des paires aléatoires de campagnes différentes (négatifs faciles) : la précision de 1,00 est
favorable. Les liens de campagne sans indicateur commun restent difficiles — c'est attendu, et la plateforme ne
conclut jamais à une campagne commune.

## 5. Score de fiabilité

`S = 0,30 R + 0,30 Q + 0,40 V` (pondérations du CDC, configurables dans `.env`). Q = 6 composantes (validité et
richesse des IOC, contexte ATT&CK, confiance de classification, complétude des métadonnées, substance) moins les
pénalités d'incohérences (high 15, medium 7, low 3, plafond 40). V = 50 tant qu'aucun vote, puis
`50 + 50 (oui − non) / éligibles`. Le score est **provisoire** jusqu'à la finalisation on-chain et n'est pas une
probabilité de véracité. Les pondérations n'ont pas été optimisées empiriquement (pas de vérité terrain sur la
fiabilité) : c'est une limite assumée.
