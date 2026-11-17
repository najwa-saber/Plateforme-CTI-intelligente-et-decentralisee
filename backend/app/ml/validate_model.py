"""Model validation gate (CI): a model is promotable only if every check passes. Exit code 1 otherwise.

Checks
  1. data      : splits exist, no report id / campaign shared between train, validation and test.
  2. traceable : the model's metrics carry the SHA-256 fingerprint of the splits and it matches the current files
                 (models trained before this gate existed are reported as "not recorded" -> not promotable by CI).
  3. loadable  : the joblib artefact loads and predicts the 4 categories.
  4. quality   : on the untouched test split, macro-F1 >= 0.75 and >= keyword baseline - 0.05;
                 on the external real-text ATT&CK set (if present), macro-F1 >= 0.80.

Usage (from backend/):
  python -m app.ml.validate_model                       # deployed model (report only)
  python -m app.ml.validate_model --model-dir <dir> --require-fingerprint   # CI candidate
Writes a JSON report next to the metrics (validation_report.json) or to --report.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import f1_score

from app.core.config import PROJECT_DIR, get_settings
from app.ml import baseline
from app.ml.preprocess import CATEGORIES, build_document
from app.ml.train import dataset_fingerprint

MIN_TEST_F1, BASELINE_TOLERANCE, MIN_EXTERNAL_F1 = 0.75, 0.05, 0.80


def _load(path: Path) -> pd.DataFrame:
    df = pd.read_json(path, lines=True)
    df["doc"] = [build_document(t, x) for t, x in zip(df["title"], df["text"])]
    return df


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default=None)
    ap.add_argument("--require-fingerprint", action="store_true")
    ap.add_argument("--report", default=None)
    args = ap.parse_args(argv)
    s = get_settings()
    model_path = Path(args.model_dir) / "classifier.joblib" if args.model_dir else Path(s.model_path)
    metrics_path = Path(args.model_dir) / "metrics.json" if args.model_dir else Path(s.model_metrics_path)
    data = PROJECT_DIR / "data"
    checks: dict[str, dict] = {}

    splits = {n: _load(data / "splits" / f"{n}.jsonl") for n in ("train", "validation", "test")}
    shared_ids = sum(len(set(splits[a]["report_id"]) & set(splits[b]["report_id"]))
                     for a, b in (("train", "test"), ("train", "validation"), ("validation", "test")))
    shared_camp = sum(len(set(splits[a]["campaign_id"]) & set(splits[b]["campaign_id"]))
                      for a, b in (("train", "test"), ("train", "validation"), ("validation", "test")))
    checks["data"] = {"ok": shared_ids == 0 and shared_camp == 0, "shared_ids": shared_ids,
                      "shared_campaigns": shared_camp}

    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    current = dataset_fingerprint()["combined_sha256"]
    recorded = (metrics.get("dataset") or {}).get("combined_sha256")
    checks["traceable"] = {"ok": recorded == current if recorded else not args.require_fingerprint,
                           "recorded": recorded or "not recorded", "current": current}

    try:
        pipe = joblib.load(model_path)["pipeline"]
        ok = sorted(pipe.classes_) == sorted(CATEGORIES)
        checks["loadable"] = {"ok": ok, "classes": list(pipe.classes_)}
    except Exception as exc:  # noqa: BLE001 - report any loading problem as a failed check
        checks["loadable"] = {"ok": False, "error": type(exc).__name__}
        pipe = None

    if pipe is not None:
        test = splits["test"]
        f1 = f1_score(test["category"], pipe.predict(test["doc"]), labels=CATEGORIES, average="macro")
        base = f1_score(test["category"], [baseline.predict(f"{t}. {x}")[0] for t, x in zip(test["title"], test["text"])],
                        labels=CATEGORIES, average="macro")
        q = {"test_macro_f1": round(float(f1), 4), "baseline_test_macro_f1": round(float(base), 4)}
        ok = f1 >= MIN_TEST_F1 and f1 >= base - BASELINE_TOLERANCE
        ext_path = data / "external" / "attack_eval.jsonl"
        if ext_path.exists():
            ext = _load(ext_path)
            ef1 = f1_score(ext["category"], pipe.predict(ext["doc"]), labels=CATEGORIES, average="macro")
            q["external_macro_f1"] = round(float(ef1), 4)
            ok = ok and ef1 >= MIN_EXTERNAL_F1
        checks["quality"] = {"ok": bool(ok), **q, "thresholds": {"min_test_f1": MIN_TEST_F1,
                             "baseline_tolerance": BASELINE_TOLERANCE, "min_external_f1": MIN_EXTERNAL_F1}}

    passed = all(c["ok"] for c in checks.values())
    report = {"model": str(model_path.relative_to(PROJECT_DIR)) if model_path.is_relative_to(PROJECT_DIR)
              else str(model_path), "promotable": passed, "checks": checks}
    out = Path(args.report) if args.report else metrics_path.with_name("validation_report.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for name, c in checks.items():
        print(f"[{'OK' if c['ok'] else 'KO'}] {name}: { {k: v for k, v in c.items() if k != 'ok'} }")
    print("PROMOTABLE" if passed else "NOT PROMOTABLE")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
