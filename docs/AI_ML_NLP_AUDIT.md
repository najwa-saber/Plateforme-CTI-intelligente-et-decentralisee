# Audit IA / ML / NLP — 17/11/2026

> Constats établis en rechargeant le modèle sauvegardé et en recalculant les métriques (lecture seule).

## 1. Inventaire précis

| # | Élément | Ce qui existe réellement |
|---|---|---|
| 1 | Algorithmes de ML | **Régression logistique multinomiale** (`sklearn.linear_model.LogisticRegression`, solveur lbfgs) ; Random Forest utilisé **uniquement comme point de comparaison** lors de l'évaluation (non déployé) |
| 2 | Modèles NLP | **Aucun modèle de langue.** NLP = expressions régulières + validation syntaxique (extraction d'IOC), représentation **TF-IDF** (1–2 grammes) et similarité cosinus TF-IDF (corrélation, suggestions ATT&CK) |
| 3 | Deep Learning | **Aucun** (pas de réseau de neurones, pas de PyTorch / TensorFlow) |
| 4 | Modèles préentraînés | **Aucun** (pas de BERT/SecureBERT, pas d'embeddings externes). Ressources externes utilisées = **données** de référence : catalogue officiel MITRE ATT&CK STIX v20.1 et liste IANA des TLD |
| 5 | Modèle entraîné pour le projet | **Oui, un seul** : `backend/app/ml/artifacts/classifier.joblib` (pipeline TF-IDF + LogReg, version `lr-tfidf-20261116184426`) |
| 6 | Jeux de données | Corpus **synthétique** de 80 rapports (20/catégorie, rédigés pour le projet) ; découpage 48/16/16 groupé par campagne ; 182 IOC annotés ; 163 paires de relations ; 25 cas *challenge* |
| 7 | Scripts d'entraînement | `backend/app/ml/train.py` (sélection, entraînement, évaluation, baselines, validation croisée) ; `data/scripts/build_corpus.py` |
| 8 | Fichiers de modèle | `classifier.joblib` (≈ 192 Ko : vocabulaire TF-IDF de 3 314 termes + matrice de coefficients 4 × 3 314) ; `metrics.json` |
| 9 | Hyperparamètres | TF-IDF : `ngram_range=(1,2)`, `sublinear_tf=True`, `max_df=0.9`, `min_df=1`, stop-words anglais ; LogReg : `C=100` (choisi parmi {0,1 ; 1 ; 10 ; 100}), `class_weight="balanced"`, `max_iter=5000`, `random_state=42` ; prétraitement `v1-ioc-masking` |
| 10 | Métriques | accuracy, précision / rappel / F1 par classe, macro-F1, matrice de confusion, log-loss (sélection), validation croisée groupée 5 plis |

## 2. Un entraînement a-t-il réellement eu lieu ?

**Oui — un entraînement supervisé depuis zéro d'un modèle linéaire classique**, pas un *fine-tuning*, pas un modèle
préentraîné. Preuves : l'artefact contient un `TfidfVectorizer` ajusté (vocabulaire de 3 314 n-grammes appris sur le
corpus) et une `LogisticRegression` ajustée (`n_iter_ = 14` itérations lbfgs jusqu'à convergence, coefficients
4 × 3 314), `trained_at = 2026-11-16T18:44:26Z`, `training_size = 64` (apprentissage + validation). Le modèle est
chargé par FastAPI et produit les probabilités affichées.

| Technique | Utilisée ? | Où |
|---|---|---|
| Modèle préentraîné | non | — |
| Entraînement depuis zéro | **oui** (modèle linéaire, 64 documents) | `ml/train.py` → `classifier.joblib` |
| Fine-tuning | non | — |
| Classification par règles | oui, **en repli** si le modèle est absent, et comme baseline | `ml/baseline.py` |
| Classification par mots-clés | oui (même module : comptage de mots-clés + softmax) | `ml/baseline.py` |
| Règles / mots-clés pour ATT&CK | oui (55 règles regex) + similarité TF-IDF avec les descriptions officielles | `mitre/rules.py`, `mitre/enricher.py` |
| Règles pour l'extraction d'IOC | oui (regex + validation) | `nlp/ioc_extractor.py` |

Il ne faut donc pas présenter le projet comme utilisant un « modèle NLP » ou du *deep learning* : c'est un classifieur
linéaire TF-IDF entraîné sur un petit corpus synthétique, entouré de composants à base de règles.

## 3. Vérification de l'accuracy de 0,875 et de la comparaison à la baseline

Recalcul indépendant sur `data/splits/test.jsonl` avec l'artefact sauvegardé :

| | Correct | Accuracy | IC 95 % (Wilson) |
|---|---|---|---|
| TF-IDF + régression logistique | 14 / 16 | **0,875** | [0,64 ; 0,97] |
| Baseline mots-clés | 14 / 16 | **0,875** | [0,64 ; 0,97] |
| Random Forest (TF-IDF) | 12 / 16 | 0,750 | — |
| Classe majoritaire | 4 / 16 | 0,250 | — |

* Erreurs du modèle : CTI-010 (phishing → malware, rapport annoté ambigu), CTI-048 (wiper → ransomware).
* Erreurs de la baseline : CTI-048 (→ ransomware), CTI-060 (malvertising → phishing).
* **Test de McNemar exact : p = 1,00** (chaque méthode réussit un document que l'autre manque) → **aucune différence
  démontrable** entre le modèle appris et la baseline. Macro-F1 : 0,874 contre 0,861, écart non significatif.
* Validation croisée groupée (5 plis) : macro-F1 0,881 ± 0,082 — même ordre de grandeur, forte variance.
* Absence de fuite vérifiée : 0 identifiant, 0 campagne et 0 texte identique commun entre apprentissage et test ;
  TF-IDF ajusté dans le pipeline (apprentissage uniquement).

**Biais à signaler** : le corpus, les règles de la baseline et les règles ATT&CK ont été écrits par le même auteur
(l'assistant), ce qui rend toutes ces mesures optimistes ; 16 documents de test donnent un intervalle de confiance
de plus de 30 points. Ces résultats valident la **chaîne méthodologique** (protocole sans fuite, métriques complètes,
comparaison aux baselines), pas la performance sur des rapports réels.

## 4. Autres composants « intelligents » et leurs résultats mesurés

| Composant | Méthode | Résultat (exécution réelle) |
|---|---|---|
| Extraction d'IOC — corpus | regex + validation | P = 1,000, R = 1,000 (182 IOC) — optimiste (règle `.onion` ajoutée après inspection) |
| Extraction d'IOC — *challenge* indépendant | idem, évaluée une fois sans réglage | **P = 0,968, R = 1,000, F1 = 0,984** ; 1 faux positif (`4.12.0.3`, numéro de version) |
| ATT&CK — règles | regex sur phrases | **P = 0,623, R = 0,762, F1 = 0,685** (correspondance stricte) |
| Corrélation | 5 composantes pondérées, seuil 0,30 | **P = 1,000, R = 0,814** sur 163 paires (négatifs faciles ; campagnes sans IOC commun 4/10) |
| Score de fiabilité | formule du CDC + heuristiques Q | non évaluable faute de vérité terrain |

Les faux positifs sont gérés par : liste IANA des TLD, filtre d'extensions de fichiers, drapeaux (infrastructure
légitime, adresses privées/réservées, plages de documentation, hash de fichier vide), statut `malformed` exclu du
partage, confiance d'extraction distincte de la malveillance.

## 5. Limites et recommandations

1. Ne pas revendiquer une supériorité du ML sur la baseline ; présenter le résultat comme une **égalité** sur un test
   minuscule et synthétique.
2. Pour un résultat scientifique crédible : corpus réel annoté (≥ 200 rapports publics, plusieurs annotateurs,
   accord inter-annotateurs), test plus grand, comparaison avec un modèle préentraîné spécialisé (SecureBERT
   *fine-tuné*) et classification multi-étiquettes.
3. Mesurer la calibration des probabilités (log-loss / courbe de fiabilité sur le test) avant de les présenter.
4. Évaluer ATT&CK et la corrélation sur des données non vues par l'auteur des règles.
