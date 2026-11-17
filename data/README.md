# Corpus CTI — données du projet

> **Toutes les données de ce dossier sont synthétiques.** Les rapports ont été rédigés pour le prototype ; les
> indicateurs sont fictifs : adresses IP des plages de documentation RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`,
> `203.0.113.0/24`), domaines réservés RFC 2606 / RFC 6761 (`.example`, `.test`, `.invalid`), quelques noms fictifs
> sur de vrais gTLD (`.xyz`) uniquement dans le jeu *challenge*, CVE fictives de l'année 2099, acteurs et familles
> de malwares inventés. Aucune donnée réelle n'est mélangée à ces données.

## Arborescence (CDC 4.5)

```
data/
├── raw/
│   ├── reports/          80 rapports bruts (CTI-001.txt … CTI-080.txt), générés par build_corpus.py
│   ├── iocs/             (vide) emplacement prévu pour des flux publics — non utilisé, voir « Sources »
│   └── mitre/            bundle STIX officiel ATT&CK (55 Mo, non versionné, re-téléchargeable)
├── annotated/
│   ├── reports.jsonl     80 rapports annotés (schéma CDC 4.6)
│   ├── iocs.csv          182 IOC de référence (schéma CDC 4.7)
│   ├── relations.csv     163 paires annotées pour évaluer la corrélation (schéma CDC 4.8)
│   └── ioc_challenge.jsonl  25 cas difficiles, jeu indépendant d'évaluation de l'extraction
├── splits/               train.jsonl (48) · validation.jsonl (16) · test.jsonl (16)
├── demo/                 5 rapports de démonstration (TXT, JSON, PDF) hors corpus d'entraînement
└── scripts/              corpus/*.py (sources annotées), build_corpus.py, make_demo_pdf.py
```

## Constitution

* **80 rapports**, **20 par catégorie** : phishing, ransomware, malware (hors ransomware), exploitation de
  vulnérabilités (CDC 4.3–4.4). Styles variés (bulletin, note d'analyste, compte-rendu d'incident, avis).
* **Campagnes** : plusieurs rapports d'une même campagne fictive partagent des IOC (ex. `PH-C1` paie,
  `RW-C1` NightVault) ; certaines campagnes traversent les catégories (ransomware livré après un phishing).
* **Cas ambigus** marqués `"ambiguous": true` (ex. CTI-010 : phishing livrant un stealer) ; la catégorie principale
  suit le sujet dominant (CDC 4.3).
* **Annotation des IOC indépendante de l'extracteur** : les IOC sont balisés à la main dans les sources
  (`<<type|valeur affichée|valeur de référence>>`, ex. version défangée affichée et valeur normalisée attendue).
  `build_corpus.py` ne s'appuie jamais sur le code d'extraction de la plateforme.
* `malicious_label = unknown` pour tous les IOC (CDC 4.7) : la présence dans un rapport ne prouve pas la malveillance.

Reconstruction déterministe :

```bash
python data/scripts/build_corpus.py
```

## Schémas

`reports.jsonl` (une ligne par rapport) : `report_id, title, text, category, mitre_techniques, source ("synthetic"),
source_url, published_at, language, annotation_status, campaign_id, ambiguous, notes`.

`iocs.csv` : `report_id, ioc_type (ipv4|domain|url|md5|sha256), ioc_value (normalisée), malicious_label`.

`relations.csv` : `report_id_1, report_id_2, relation_type (shared_hash|shared_url|shared_domain|shared_ip|same_campaign|none), relation_label (0|1)`.
43 paires positives (IOC communs ou même campagne), 120 négatives tirées au hasard entre campagnes différentes
(négatifs « faciles » : limite assumée).

## Découpage sans fuite (CDC 4.9, 5.4)

60/20/20 **groupé par campagne** et stratifié par catégorie : une campagne n'apparaît jamais dans deux splits
(vérification par assertion dans `build_corpus.py`). Résultat : 12/4/4 rapports par catégorie.

## Sources

| Source | Utilisation dans ce prototype |
|---|---|
| Rapports synthétiques (ce dossier) | entraînement, évaluation, démonstration |
| MITRE ATT&CK STIX 2.1 (officiel) | catalogue des techniques (`backend/app/mitre/data`) — v20.1, téléchargé le 2026-11-16 depuis `github.com/mitre-attack/attack-stix-data` ; marque déposée de The MITRE Corporation, utilisée selon ses conditions |
| Liste IANA des TLD | validation des domaines (`backend/app/nlp/data`) — version 2026111600 |
| URLhaus, MalwareBazaar | **non intégrés** : ces flux contiennent de vrais IOC malveillants ; le CDC impose un environnement contrôlé avec des IOC de test. Intégration possible en perspective (voir docs/10_limites.md) |

## Portée scientifique

Corpus destiné à un prototype : il ne permet **pas** de conclure à une généralisation sur des rapports réels
(auteur unique, vocabulaire homogène, 16 documents de test). Voir [docs/05_evaluation.md](../docs/05_evaluation.md).
