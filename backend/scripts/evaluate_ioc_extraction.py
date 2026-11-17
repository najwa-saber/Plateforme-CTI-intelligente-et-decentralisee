"""Evaluate the IOC extractor (precision / recall / F1) on two annotated sets.

1. corpus    : the 182 gold IOCs of data/annotated/iocs.csv (80 synthetic reports)
2. challenge : data/annotated/ioc_challenge.jsonl - 25 hard cases written AFTER the extractor was
               finalised, evaluated once without tuning (independent check, see docs/05_evaluation.md)

Counting rule: an extracted IOC is a true positive when (type, normalised value) is in the gold set.
Extracted IOCs with status "malformed" are excluded (they are reported, never shared).
Output: docs/test-reports/ioc_extraction_eval.json

Usage (from backend/): python scripts/evaluate_ioc_extraction.py
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))

from app.nlp.ioc_extractor import IOCExtractor  # noqa: E402


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def evaluate(items: list[tuple[str, str, set]], ex: IOCExtractor) -> dict:
    tp = fp = fn = 0
    per_type = defaultdict(lambda: [0, 0, 0])
    errors = []
    for item_id, text, gold in items:
        pred = {(i.ioc_type, i.value) for i in ex.extract(text).iocs if i.status != "malformed"}
        for t, _ in pred & gold:
            per_type[t][0] += 1
        for t, _ in pred - gold:
            per_type[t][1] += 1
        for t, _ in gold - pred:
            per_type[t][2] += 1
        tp += len(pred & gold)
        fp += len(pred - gold)
        fn += len(gold - pred)
        if pred != gold:
            errors.append({"id": item_id, "false_positives": sorted(map(list, pred - gold)),
                           "false_negatives": sorted(map(list, gold - pred))})
    return {"overall": prf(tp, fp, fn), "per_type": {t: prf(*v) for t, v in sorted(per_type.items())},
            "items": len(items), "errors": errors}


def main() -> int:
    ex = IOCExtractor()
    gold: dict[str, set] = defaultdict(set)
    with (ROOT / "data" / "annotated" / "iocs.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            gold[row["report_id"]].add((row["ioc_type"], row["ioc_value"]))
    corpus = [(r["report_id"], r["text"], gold.get(r["report_id"], set()))
              for r in map(json.loads, (ROOT / "data" / "annotated" / "reports.jsonl").read_text(encoding="utf-8").splitlines())]
    challenge = [(c["id"], c["text"], {tuple(g) for g in c["gold"]})
                 for c in map(json.loads, (ROOT / "data" / "annotated" / "ioc_challenge.jsonl").read_text(encoding="utf-8").splitlines())]
    result = {
        "executed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "corpus": evaluate(corpus, ex),
        "challenge": evaluate(challenge, ex),
        "notes": [
            "corpus: same author for corpus and extractor, one rule (.onion) added after inspecting corpus errors "
            "-> optimistic estimate.",
            "challenge: written after the extractor was frozen and evaluated once, no tuning afterwards.",
        ],
    }
    out = ROOT / "docs" / "test-reports" / "ioc_extraction_eval.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for name in ("corpus", "challenge"):
        o = result[name]["overall"]
        print(f"{name:<10} items={result[name]['items']:>3}  P={o['precision']:.3f}  R={o['recall']:.3f}  "
              f"F1={o['f1']:.3f}  (tp={o['tp']} fp={o['fp']} fn={o['fn']})")
    for e in result["challenge"]["errors"]:
        print("  challenge error", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
