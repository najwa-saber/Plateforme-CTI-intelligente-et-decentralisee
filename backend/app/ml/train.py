"""Training and evaluation of the CTI report classifier (TF-IDF + Logistic Regression).

Protocol (CDC 5.4):
  * splits produced by data/scripts/build_corpus.py: 60/20/20, grouped by campaign
    (no campaign shared between train / validation / test -> no near-duplicate leakage);
  * TF-IDF is fitted inside a scikit-learn Pipeline, i.e. ONLY on training data;
  * the regularisation strength C is selected on the validation split (macro-F1);
  * the final model is refitted on train+validation with the selected C and evaluated
    ONCE on the untouched test split;
  * complementary estimate: 5-fold StratifiedGroupKFold cross-validation on the whole corpus;
  * baselines on the same test split: majority class, keyword rules, Random Forest.

Usage: python -m app.ml.train  (from backend/)   -> writes app/ml/artifacts/*
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, log_loss
from sklearn.model_selection import StratifiedGroupKFold
import sklearn
from sklearn.pipeline import Pipeline

from app.core.config import PROJECT_DIR, get_settings
from app.ml import baseline
from app.ml.preprocess import CATEGORIES, PREPROCESSING_VERSION, build_document

SPLITS = PROJECT_DIR / "data" / "splits"
ANNOTATED = PROJECT_DIR / "data" / "annotated" / "reports.jsonl"
SEED = 42
C_GRID = [0.1, 1.0, 10.0, 100.0]


def load_split(name: str) -> pd.DataFrame:
    df = pd.read_json(SPLITS / f"{name}.jsonl", lines=True)
    df["doc"] = [build_document(t, x) for t, x in zip(df["title"], df["text"])]
    return df


def make_pipeline(c: float) -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1, max_df=0.9,
                                  stop_words="english")),
        ("clf", LogisticRegression(C=c, class_weight="balanced", max_iter=5000, random_state=SEED)),
    ])


def metrics_for(y_true, y_pred) -> dict:
    report = classification_report(y_true, y_pred, labels=CATEGORIES, output_dict=True, zero_division=0)
    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "macro_f1": round(f1_score(y_true, y_pred, labels=CATEGORIES, average="macro", zero_division=0), 4),
        "macro_precision": round(report["macro avg"]["precision"], 4),
        "macro_recall": round(report["macro avg"]["recall"], 4),
        "per_class": {
            c: {k: round(report[c][k], 4) for k in ("precision", "recall", "f1-score", "support")}
            for c in CATEGORIES
        },
        "confusion_matrix": {"labels": CATEGORIES,
                             "matrix": confusion_matrix(y_true, y_pred, labels=CATEGORIES).tolist()},
    }


def top_features(pipeline: Pipeline, k: int = 12) -> dict[str, list[list]]:
    vec: TfidfVectorizer = pipeline.named_steps["tfidf"]
    clf: LogisticRegression = pipeline.named_steps["clf"]
    names = np.array(vec.get_feature_names_out())
    out = {}
    for i, cls in enumerate(clf.classes_):
        idx = np.argsort(clf.coef_[i])[::-1][:k]
        out[str(cls)] = [[str(names[j]), round(float(clf.coef_[i][j]), 3)] for j in idx]
    return out


def dataset_fingerprint() -> dict:
    """SHA-256 of the split files: ties a model and its metrics to the exact data it was trained/tested on."""
    files = {s: SPLITS / f"{s}.jsonl" for s in ("train", "validation", "test")}
    digests = {s: hashlib.sha256(f.read_bytes()).hexdigest() for s, f in files.items()}
    combined = hashlib.sha256("".join(digests[s] for s in sorted(digests)).encode()).hexdigest()
    return {"splits_sha256": digests, "combined_sha256": combined}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", default=None,
                        help="write classifier.joblib + metrics.json here (CI: a candidate directory). "
                             "Default: the deployed artefact paths from the settings.")
    args = parser.parse_args(argv)
    settings = get_settings()
    out_dir = Path(args.output_dir) if args.output_dir else None
    fingerprint = dataset_fingerprint()
    train, val, test = load_split("train"), load_split("validation"), load_split("test")
    print(f"train={len(train)} validation={len(val)} test={len(test)}")

    # 1) model selection on validation
    selection = []
    for c in C_GRID:
        pipe = make_pipeline(c).fit(train["doc"], train["category"])
        pred = pipe.predict(val["doc"])
        selection.append({"C": c, "val_macro_f1": round(f1_score(val["category"], pred, average="macro"), 4),
                          "val_accuracy": round(accuracy_score(val["category"], pred), 4),
                          "val_log_loss": round(log_loss(val["category"], pipe.predict_proba(val["doc"]),
                                                         labels=list(pipe.classes_)), 4)})
    # primary criterion: macro-F1; tie-break: log-loss (proper scoring rule -> more informative probabilities)
    best_c = max(selection, key=lambda s: (s["val_macro_f1"], -s["val_log_loss"]))["C"]
    print("model selection:", selection, "-> C =", best_c)

    # 2) final model on train+validation, single evaluation on test
    trainval = pd.concat([train, val], ignore_index=True)
    final = make_pipeline(best_c).fit(trainval["doc"], trainval["category"])
    test_pred = final.predict(test["doc"])
    test_metrics = metrics_for(test["category"], test_pred)
    proba = final.predict_proba(test["doc"])
    errors = [
        {"report_id": rid, "true": t, "pred": p, "confidence": round(float(pr.max()), 3)}
        for rid, t, p, pr in zip(test["report_id"], test["category"], test_pred, proba) if t != p
    ]

    # 3) baselines on the same test split
    majority = trainval["category"].value_counts().idxmax()
    baselines = {
        "majority_class": metrics_for(test["category"], [majority] * len(test)),
        "keyword_rules": metrics_for(test["category"],
                                     [baseline.predict(f"{t}. {x}")[0] for t, x in zip(test["title"], test["text"])]),
    }
    rf = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english", max_df=0.9)),
        ("clf", RandomForestClassifier(n_estimators=300, random_state=SEED, class_weight="balanced")),
    ]).fit(trainval["doc"], trainval["category"])
    baselines["random_forest_tfidf"] = metrics_for(test["category"], rf.predict(test["doc"]))

    # 4) grouped cross-validation on the full corpus (complementary, more stable estimate)
    full = pd.read_json(ANNOTATED, lines=True)
    full["doc"] = [build_document(t, x) for t, x in zip(full["title"], full["text"])]
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    cv_scores = []
    for tr, te in cv.split(full["doc"], full["category"], groups=full["campaign_id"]):
        m = make_pipeline(best_c).fit(full["doc"].iloc[tr], full["category"].iloc[tr])
        p = m.predict(full["doc"].iloc[te])
        cv_scores.append({"accuracy": accuracy_score(full["category"].iloc[te], p),
                          "macro_f1": f1_score(full["category"].iloc[te], p, average="macro")})
    cv_summary = {
        "folds": 5,
        "grouping": "campaign_id",
        "accuracy_mean": round(float(np.mean([s["accuracy"] for s in cv_scores])), 4),
        "accuracy_std": round(float(np.std([s["accuracy"] for s in cv_scores])), 4),
        "macro_f1_mean": round(float(np.mean([s["macro_f1"] for s in cv_scores])), 4),
        "macro_f1_std": round(float(np.std([s["macro_f1"] for s in cv_scores])), 4),
    }

    version = datetime.now(timezone.utc).strftime("lr-tfidf-%Y%m%d%H%M%S")
    artifact = {
        "pipeline": final,
        "labels": list(final.classes_),
        "version": version,
        "preprocessing": PREPROCESSING_VERSION,
        "hyperparameters": {"C": best_c, "ngram_range": [1, 2], "class_weight": "balanced"},
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "training_size": len(trainval),
        "dataset": fingerprint,
        "sklearn_version": sklearn.__version__,
    }
    model_path = out_dir / "classifier.joblib" if out_dir else Path(settings.model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_path)

    metrics = {
        "model_version": version,
        "dataset": {
            "source": "synthetic (data/annotated/reports.jsonl) - see data/README.md",
            "sizes": {"train": len(train), "validation": len(val), "test": len(test)},
            "split_strategy": "60/20/20 grouped by campaign_id, stratified by category",
        },
        "model_selection": selection,
        "selected_C": best_c,
        "test": test_metrics,
        "test_errors": errors,
        "baselines_test": baselines,
        "grouped_cross_validation": cv_summary,
        "top_features": top_features(final),
        "limitations": [
            "Synthetic corpus written by a single annotator: vocabulary is more homogeneous than real CTI.",
            "16 test documents only: one error changes accuracy by 6.25 points; confidence intervals are wide.",
            "Results do not demonstrate generalisation to real-world reports.",
        ],
    }
    metrics["dataset"] = fingerprint
    metrics["sklearn_version"] = sklearn.__version__
    metrics_path = out_dir / "metrics.json" if out_dir else Path(settings.model_metrics_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps({"test": {k: test_metrics[k] for k in ("accuracy", "macro_f1")},
                      "baselines": {k: v["macro_f1"] for k, v in baselines.items()},
                      "cv": cv_summary, "errors": errors}, indent=2))
    print(f"model saved to {model_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
