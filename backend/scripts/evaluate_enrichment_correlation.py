"""Evaluate MITRE ATT&CK enrichment and the correlation engine on the annotated corpus.

MITRE  : rule-based proposals (method "rule") vs data/annotated/reports.jsonl "mitre_techniques".
         A proposed sub-technique also counts for its annotated parent and vice versa is NOT accepted
         (strict technique-id match), so the figures are conservative.
CORREL : data/annotated/relations.csv (CDC 4.8) - 163 labelled pairs (43 positive, 120 negative).
         Features are produced by the real pipeline (extractor, enricher, classifier), not by the gold
         annotations; the decision is score >= threshold (default 0.30, as in production).

Output: docs/test-reports/enrichment_correlation_eval.json
Usage (from backend/): python scripts/evaluate_enrichment_correlation.py
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))

from app.correlation.engine import CorrelationEngine, ReportFeatures  # noqa: E402
from app.ml.classifier import ThreatClassifier  # noqa: E402
from app.mitre.enricher import MitreEnricher  # noqa: E402
from app.nlp.ioc_extractor import IOCExtractor  # noqa: E402
from app.nlp.normalizer import url_host  # noqa: E402


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}


def main() -> int:
    reports = [json.loads(line) for line in (ROOT / "data" / "annotated" / "reports.jsonl").read_text(encoding="utf-8").splitlines()]
    ex, enr, clf = IOCExtractor(), MitreEnricher(), ThreatClassifier()
    clf.load()

    # ---------------------------------------------------------------- MITRE
    tp = fp = fn = 0
    fp_counter, fn_counter = Counter(), Counter()
    feats: dict[str, ReportFeatures] = {}
    for r in reports:
        matches = enr.enrich(r["title"], r["text"])
        pred = {m.technique_id for m in matches if m.method == "rule"}
        gold = set(r["mitre_techniques"])
        tp += len(pred & gold)
        fp += len(pred - gold)
        fn += len(gold - pred)
        fp_counter.update(pred - gold)
        fn_counter.update(gold - pred)
        iocs = set()
        for i in ex.extract(r["text"]).iocs:
            if i.status == "malformed":
                continue
            iocs.add((i.ioc_type, i.value))
            if i.ioc_type == "url":
                host = url_host(i.value)
                if host:
                    iocs.add(("ipv4" if host.replace(".", "").isdigit() else "domain", host))
        feats[r["report_id"]] = ReportFeatures(
            report_id=r["report_id"], title=r["title"], text=r["text"],
            category=clf.predict(r["title"], r["text"]).category,
            date=datetime.fromisoformat(r["published_at"]).replace(tzinfo=timezone.utc),
            iocs=iocs, mitre=pred)
    mitre = {"overall": prf(tp, fp, fn), "most_frequent_false_positives": fp_counter.most_common(8),
             "most_frequent_false_negatives": fn_counter.most_common(8)}

    # ---------------------------------------------------------------- correlation
    engine = CorrelationEngine()
    ordered = list(feats.values())
    sims = engine.text_similarity_matrix(ordered)
    index = {f.report_id: k for k, f in enumerate(ordered)}
    rows = list(csv.DictReader((ROOT / "data" / "annotated" / "relations.csv").open(encoding="utf-8")))
    by_type = defaultdict(lambda: [0, 0])  # detected, total (positives) / false alarms, total (negatives)
    tp = fp = fn = tn = 0
    misses = []
    for row in rows:
        a, b = row["report_id_1"], row["report_id_2"]
        res = engine.pair(feats[a], feats[b], float(sims[index[a], index[b]]))
        predicted = res["score"] >= engine.threshold
        label = row["relation_label"] == "1"
        by_type[row["relation_type"]][0] += int(predicted)
        by_type[row["relation_type"]][1] += 1
        if predicted and label:
            tp += 1
        elif predicted and not label:
            fp += 1
        elif label:
            fn += 1
            misses.append({"pair": [a, b], "type": row["relation_type"], "score": res["score"]})
        else:
            tn += 1
    correlation = {
        "threshold": engine.threshold, "weights": engine.weights.as_dict(), "pairs": len(rows),
        "overall": {**prf(tp, fp, fn), "tn": tn},
        "detection_rate_by_relation_type": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_type.items())},
        "missed_positive_pairs": misses,
    }
    out = {"executed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "mitre_rules": mitre,
           "correlation": correlation,
           "notes": ["Rules and corpus share the same author: MITRE figures are optimistic.",
                     "relations.csv positives are derived from shared gold IOCs and campaign ids; negatives are "
                     "random pairs of different campaigns (easy negatives)."]}
    path = ROOT / "docs" / "test-reports" / "enrichment_correlation_eval.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    m, c = mitre["overall"], correlation["overall"]
    print(f"MITRE rules : P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} (tp={m['tp']} fp={m['fp']} fn={m['fn']})")
    print(f"Correlation : P={c['precision']:.3f} R={c['recall']:.3f} F1={c['f1']:.3f} (tp={c['tp']} fp={c['fp']} fn={c['fn']} tn={c['tn']})")
    print("  by relation type:", correlation["detection_rate_by_relation_type"])
    print("  top MITRE FP:", mitre["most_frequent_false_positives"][:5])
    return 0


if __name__ == "__main__":
    sys.exit(main())
