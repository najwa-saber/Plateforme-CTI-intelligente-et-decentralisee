# Évaluation du module ML / NLP

Toutes les valeurs ci-dessous proviennent de fichiers produits par une exécution réelle :
`docs/test-reports/ml_model_comparison.json` (exécution de `python -m app.ml.experiments`, durée 121 s),
`backend/app/ml/artifacts/metrics.json` (modèle déployé), `docs/test-reports/pipeline_benchmark.json`.
Complète `docs/05_evaluation.md` (évaluation historique) sans la remplacer.

## 1. Tâche et modèle déployé

* Tâche : classer un rapport CTI dans l'une de 4 catégories — `phishing`, `ransomware`, `malware`, `exploitation`.
* Prétraitement (`app/ml/preprocess.py`) : titre + texte, IOC masqués par des jetons (`<ip>`, `<domain>`, `<hash>`…)
  pour éviter que le modèle apprenne des indicateurs propres à une campagne.
* Modèle déployé : `lr-tfidf-20261116184426` — TF-IDF (1-2 grammes, `sublinear_tf`, `max_df=0.9`) +
  régression logistique (`C=100`, `class_weight=balanced`, `lbfgs`). Fichier : `backend/app/ml/artifacts/classifier.joblib`.
* Baseline : classifieur par mots-clés (`app/ml/baseline.py`), conservé comme référence et repli.
* Entraînement séparé de l'inférence : `app/ml/train.py` (entraînement), `app/ml/classifier.py` (inférence, chargé par l'API),
  `app/ml/experiments.py` (comparaison, jamais importé par l'API), `app/ml/validate_model.py` (porte de validation).

## 2. Données et audit

| Élément | Valeur |
|---|---|
| Corpus annoté | 80 rapports synthétiques (`data/annotated/reports.jsonl`), 20 par classe, 52 campagnes |
| Découpage | train / validation / test (`data/splits/`), **groupé par campagne** ; test = 16 rapports jamais vus |
| Doublons exacts | 0 |
| Quasi-doublons entre splits | cosinus TF-IDF max 0,223 (train/test) ; 0 paire > 0,8 |
| Campagnes partagées entre splits | 0 |
| Longueur | 36 – 80 mots (médiane 51,5) ; vocabulaire 1 362 termes |
| Jeu externe réel | 49 descriptions MITRE ATT&CK (`data/external/attack_eval.jsonl`, script `data/scripts/build_attack_eval_set.py`) ; 21 étiquetées par correspondance experte technique → catégorie, 28 par règle explicite sur la description (champ `label_source`) ; 34,7 % de mots hors vocabulaire du corpus |
| Licence du jeu externe | MITRE ATT&CK® — conditions d'utilisation MITRE (réutilisation autorisée avec mention) ; aucune donnée personnelle |
| Empreinte du jeu | SHA-256 combiné des splits `8bc9df19…d118` (`train.py::dataset_fingerprint`) |

Limites du corpus (consignées dans le rapport) : auteur unique, vocabulaire de classe explicite (favorise les mots-clés),
textes courts, une seule étiquette par rapport.

## 3. Protocole (fixé avant de lire les résultats)

1. Validation croisée **imbriquée, répétée, groupée** : externe `StratifiedGroupKFold(5)` × 5 répétitions
   (groupes = campagnes), interne `GroupKFold(3)` avec recherche d'hyperparamètres sur le macro-F1.
2. Test held-out (16 rapports) : chaque modèle réglé sur train+validation puis évalué une seule fois.
3. Jeu externe réel (hors distribution).
4. Comparaison appariée avec la régression logistique : t-test rééchantillonné **corrigé de Nadeau-Bengio**.
5. Règle de sélection : remplacer le modèle déployé seulement si macro-F1 CV supérieur avec p corrigé < 0,05
   **et** macro-F1 externe non inférieur.

## 4. Résultats

### 4.1 Validation croisée imbriquée (25 plis externes, moyenne ± écart-type)

| Modèle | Accuracy | Macro-F1 | Weighted-F1 | ROC-AUC (macro OvR) | PR-AUC (macro OvR) | p corrigé vs LR |
|---|---|---|---|---|---|---|
| **Régression logistique** (famille déployée) | 0,902 ± 0,069 | 0,876 ± 0,094 | 0,903 ± 0,068 | 0,989 ± 0,014 | 0,974 ± 0,033 | — |
| SVM linéaire | 0,896 ± 0,079 | 0,873 ± 0,104 | 0,897 ± 0,078 | 0,986 ± 0,015 | 0,969 ± 0,027 | 0,858 |
| Complement NB | 0,884 ± 0,080 | 0,852 ± 0,107 | 0,883 ± 0,082 | 0,988 ± 0,013 | 0,969 ± 0,033 | 0,473 |
| Multinomial NB | 0,839 ± 0,108 | 0,819 ± 0,123 | 0,844 ± 0,103 | 0,985 ± 0,017 | 0,966 ± 0,035 | 0,161 |
| SGD (modified Huber) | 0,916 ± 0,068 | 0,903 ± 0,095 | 0,917 ± 0,066 | 0,983 ± 0,025 | 0,973 ± 0,041 | 0,459 |
| Random Forest | 0,791 ± 0,136 | 0,794 ± 0,145 | 0,799 ± 0,135 | 0,984 ± 0,021 | 0,967 ± 0,043 | 0,245 |
| Baseline mots-clés | 0,951 ± 0,047 | 0,935 ± 0,071 | 0,949 ± 0,051 | 1,000 ± 0,000 | 1,000 ± 0,002 | 0,192 |

### 4.2 Test held-out (16 rapports)

| Modèle | Accuracy | Macro-F1 | Weighted-F1 | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|
| **Modèle déployé** | 0,875 | 0,874 | 0,874 | 0,974 | 0,935 |
| Régression logistique (ré-réglée, C=0,1) | 0,875 | 0,874 | 0,874 | 0,974 | 0,942 |
| SVM linéaire / Complement NB | 0,875 | 0,874 | 0,874 | 0,974 | 0,942 |
| Multinomial NB | 0,875 | 0,874 | 0,874 | 0,984 | 0,964 |
| SGD | 0,938 | 0,937 | 0,937 | 0,969 | 0,924 |
| Random Forest | 0,750 | 0,754 | 0,754 | 0,943 | 0,889 |
| Baseline mots-clés | 0,875 | 0,861 | 0,861 | 1,000 | 1,000 |

Matrice de confusion du modèle déployé (lignes = vérité ; ordre phishing, ransomware, malware, exploitation) :
`[[3,0,1,0],[0,4,0,0],[0,1,3,0],[0,0,0,4]]` → 14/16, intervalle de Wilson 95 % [0,64 ; 0,965].
McNemar déployé vs baseline : p = 1,00 (aucune différence démontrable sur 16 documents).

### 4.3 Jeu externe réel ATT&CK (49 textes)

| Modèle | Accuracy | Macro-F1 |
|---|---|---|
| Régression logistique, SVM linéaire, Complement NB, Multinomial NB | 1,000 | 1,000 |
| Baseline mots-clés | 0,980 | 0,982 |
| SGD | 0,959 | 0,954 |
| Random Forest | 0,755 | 0,760 (11 ransomware sur 15 classés malware) |

Interprétation : ce jeu est **lexicalement facile** (descriptions courtes et explicites) ; il montre que le modèle ne
s'effondre pas hors du style synthétique, il ne prouve pas une performance sur des rapports CTI réels longs.

### 4.4 Décision

SGD obtient la meilleure moyenne CV (+0,027 de macro-F1) mais **p = 0,459** et un macro-F1 externe inférieur (0,954 < 1,000).
Décision enregistrée dans le rapport : **conserver la régression logistique déployée**. Les modèles pré-entraînés
spécialisés (SecBERT, etc.) n'ont pas été évalués : sur 80 textes courts la variance de l'estimation (± 0,09)
empêcherait de démontrer un gain, et leur coût (GPU, image Docker > 2 Go) n'est pas justifié — piste de perspective.

## 5. Traçabilité et porte de validation

* `python -m app.ml.train --output-dir <dir>` enregistre dans `metrics.json` l'empreinte SHA-256 des splits et la version de scikit-learn.
* `python -m app.ml.validate_model [--model-dir <dir>] [--require-fingerprint]` vérifie : absence de fuite (ids, campagnes),
  empreinte, chargement, macro-F1 test ≥ 0,75 et ≥ baseline − 0,05, macro-F1 externe ≥ 0,80. Code de sortie 1 sinon.
* Modèle déployé : qualité OK, empreinte « not recorded » (entraîné avant la porte) → non promouvable par la CI tel quel.
* Candidat ré-entraîné (`.venv/ml_candidate_test/`, hors dépôt) : prédictions et métriques identiques, empreinte enregistrée,
  porte **PROMOTABLE**. Sa promotion (copie vers `backend/app/ml/artifacts/`) **attend l'autorisation**.

## 6. Performances de traitement (hors réseau)

`backend/scripts/benchmark_pipeline.py`, 80 rapports, Python 3.11 / Windows 11 :

| Étape | Médiane | p95 |
|---|---|---|
| Extraction IOC | 1,11 ms | 1,71 ms |
| Classification ML | 13,58 ms | 16,96 ms |
| Enrichissement MITRE | 10,72 ms | 94,05 ms |
| Empreinte SHA-256 | 0,16 ms | 0,23 ms |
| Corrélation (1 contre 80) | 74,29 ms | 85,29 ms |
| **Total par rapport** | **103,64 ms** | **169,90 ms** |

MISP et Ethereum (réseau) sont mesurés de bout en bout par `scripts/run_demo_scenario.py`.

## 7. Reproduire

```bash
cd backend && ../.venv/Scripts/python -m app.ml.experiments
```
```bash
cd backend && ../.venv/Scripts/python -m app.ml.validate_model --report ../docs/test-reports/deployed-model-validation.json
```
