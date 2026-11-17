"""Reproducible model comparison for CTI report classification (training-time only, never imported by the API).

Protocol (fixed BEFORE looking at the results):
  1. Dataset audit: class balance, lengths, exact and near duplicates across splits (TF-IDF cosine).
  2. Nested, repeated, GROUPED cross-validation on the 80 synthetic reports: outer StratifiedGroupKFold(5) x 5
     repetitions (groups = campaign_id), inner GroupKFold(3) grid search on macro-F1. Metrics per outer fold.
  3. Held-out test (16 docs, untouched): each model tuned on train+validation (grouped inner CV), evaluated once.
  4. External REAL-TEXT set (data/external/attack_eval.jsonl, MITRE ATT&CK descriptions): out-of-distribution check.
  5. Paired comparison with the deployed model family (logistic regression) using the Nadeau-Bengio corrected
     resampled t-test on the outer folds (accounts for overlapping training sets).
  Selection rule: a model replaces the deployed LogReg only if its nested-CV macro-F1 is higher with corrected
  p < 0.05 AND its macro-F1 on the external real-text set is not lower. Otherwise the deployed model is kept.

Usage (from backend/): python -m app.ml.experiments  -> docs/test-reports/ml_model_comparison.json
"""
from __future__ import annotations

import json
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import GridSearchCV, GroupKFold, StratifiedGroupKFold
from sklearn.naive_bayes import ComplementNB, MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import label_binarize
from sklearn.svm import LinearSVC

from app.core.config import PROJECT_DIR, get_settings
from app.ml import baseline
from app.ml.preprocess import CATEGORIES, build_document

SEED, OUTER, REPEATS, INNER = 42, 5, 5, 3
OUT = PROJECT_DIR / "docs" / "test-reports" / "ml_model_comparison.json"


def tfidf() -> TfidfVectorizer:
    return TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, max_df=0.9, stop_words="english")


MODELS: dict[str, tuple] = {
    "logistic_regression": (LogisticRegression(class_weight="balanced", max_iter=5000, random_state=SEED),
                            {"clf__C": [0.1, 1.0, 10.0, 100.0]}),
    "linear_svm": (LinearSVC(class_weight="balanced", random_state=SEED, max_iter=20000),
                   {"clf__C": [0.01, 0.1, 1.0, 10.0]}),
    "complement_nb": (ComplementNB(), {"clf__alpha": [0.1, 0.3, 1.0]}),
    "multinomial_nb": (MultinomialNB(), {"clf__alpha": [0.1, 0.3, 1.0]}),
    "sgd_modified_huber": (SGDClassifier(loss="modified_huber", class_weight="balanced", random_state=SEED),
                           {"clf__alpha": [1e-5, 1e-4, 1e-3]}),
    "random_forest": (RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=SEED), {}),
}


def load(path: Path) -> pd.DataFrame:
    df = pd.read_json(path, lines=True)
    df["doc"] = [build_document(t, x) for t, x in zip(df["title"], df["text"])]
    return df


def scores_of(model, docs) -> np.ndarray:
    """Class scores aligned with CATEGORIES (probabilities when available, else decision function)."""
    est = model.best_estimator_ if hasattr(model, "best_estimator_") else model
    raw = est.predict_proba(docs) if hasattr(est, "predict_proba") else est.decision_function(docs)
    classes = list(est.classes_)
    return np.column_stack([raw[:, classes.index(c)] for c in CATEGORIES])


def keyword_scores(titles, texts) -> tuple[list[str], np.ndarray]:
    preds, rows = [], []
    for t, x in zip(titles, texts):
        cat, sc, _ = baseline.predict(f"{t}. {x}")
        preds.append(cat)
        rows.append([sc[c] for c in CATEGORIES])
    return preds, np.array(rows)


def metrics(y_true, y_pred, scores=None) -> dict:
    out = {
        "accuracy": accuracy_score(y_true, y_pred),
        "macro_precision": precision_score(y_true, y_pred, labels=CATEGORIES, average="macro", zero_division=0),
        "macro_recall": recall_score(y_true, y_pred, labels=CATEGORIES, average="macro", zero_division=0),
        "macro_f1": f1_score(y_true, y_pred, labels=CATEGORIES, average="macro", zero_division=0),
        "weighted_f1": f1_score(y_true, y_pred, labels=CATEGORIES, average="weighted", zero_division=0),
    }
    if scores is not None and len(set(y_true)) == len(CATEGORIES):
        yb = label_binarize(y_true, classes=CATEGORIES)
        out["roc_auc_macro_ovr"] = roc_auc_score(yb, scores, average="macro")
        out["pr_auc_macro_ovr"] = average_precision_score(yb, scores, average="macro")
    return {k: round(float(v), 4) for k, v in out.items()}


def grid(name: str) -> GridSearchCV | Pipeline:
    est, params = MODELS[name]
    pipe = Pipeline([("tfidf", tfidf()), ("clf", clone(est))])
    return GridSearchCV(pipe, params, cv=GroupKFold(INNER), scoring="f1_macro", n_jobs=1) if params else pipe


def fit(model, X, y, groups):
    if isinstance(model, GridSearchCV):
        return model.fit(X, y, groups=groups)
    return model.fit(X, y)


def corrected_ttest(a: list[float], b: list[float], n_train: int, n_test: int) -> dict:
    d = np.array(a) - np.array(b)
    k = len(d)
    var = d.var(ddof=1)
    if var == 0:
        return {"mean_diff": round(float(d.mean()), 4), "t": None, "p_value": 1.0 if d.mean() == 0 else 0.0}
    t = d.mean() / math.sqrt((1 / k + n_test / n_train) * var)
    p = 2 * stats.t.sf(abs(t), df=k - 1)
    return {"mean_diff": round(float(d.mean()), 4), "t": round(float(t), 3), "p_value": round(float(p), 4)}


def dataset_audit(full: pd.DataFrame, splits: dict[str, pd.DataFrame], external: pd.DataFrame) -> dict:
    vec = TfidfVectorizer(sublinear_tf=True).fit(full["doc"])
    near = []
    for a, b in (("train", "test"), ("train", "validation"), ("validation", "test")):
        sims = cosine_similarity(vec.transform(splits[a]["doc"]), vec.transform(splits[b]["doc"]))
        i, j = np.unravel_index(sims.argmax(), sims.shape)
        near.append({"pair": f"{a}/{b}", "max_cosine": round(float(sims.max()), 3),
                     "docs": [splits[a]["report_id"].iloc[i], splits[b]["report_id"].iloc[j]],
                     "pairs_above_0.8": int((sims > 0.8).sum())})
    words = full["text"].str.split().str.len()
    ext_words = external["text"].str.split().str.len()
    return {
        "n_reports": len(full), "class_counts": full["category"].value_counts().to_dict(),
        "campaigns": int(full["campaign_id"].nunique()),
        "words_per_report": {"min": int(words.min()), "median": float(words.median()), "max": int(words.max())},
        "exact_duplicate_texts": int(full["text"].duplicated().sum()),
        "near_duplicates_across_splits": near,
        "campaign_overlap_across_splits": sum(len(set(splits[a]["campaign_id"]) & set(splits[b]["campaign_id"]))
                                              for a, b in (("train", "test"), ("train", "validation"),
                                                           ("validation", "test"))),
        "vocabulary_size": len(vec.vocabulary_),
        "external_set": {"n": len(external), "class_counts": external["category"].value_counts().to_dict(),
                         "label_sources": external["label_source"].value_counts().to_dict(),
                         "words_median": float(ext_words.median()),
                         "oov_rate_vs_corpus_vocabulary": round(float(np.mean([
                             np.mean([w not in vec.vocabulary_ for w in d.split()] or [0]) for d in external["doc"]])), 3)},
        "synthetic_limits": [
            "single author for all 80 texts (homogeneous style and vocabulary)",
            "category-specific vocabulary is explicit (e.g. 'ransom note', 'CVE'), which favours keyword methods",
            "short texts (median ~70 words) compared with real CTI reports",
            "one dominant label per report although real reports often mix threats",
        ],
    }


def main() -> int:
    t0 = time.time()
    root = PROJECT_DIR / "data"
    splits = {s: load(root / "splits" / f"{s}.jsonl") for s in ("train", "validation", "test")}
    full = load(root / "annotated" / "reports.jsonl")
    external = load(root / "external" / "attack_eval.jsonl")
    trainval = pd.concat([splits["train"], splits["validation"]], ignore_index=True)
    result = {"executed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "protocol": __doc__.split("Usage")[0].strip(), "dataset_audit": dataset_audit(full, splits, external)}

    # ---- nested repeated grouped CV --------------------------------------------------------------
    X, y, g = full["doc"].to_numpy(), full["category"].to_numpy(), full["campaign_id"].to_numpy()
    per_fold: dict[str, list[dict]] = {m: [] for m in [*MODELS, "keyword_baseline"]}
    fold_sizes = []
    for rep in range(REPEATS):
        outer = StratifiedGroupKFold(n_splits=OUTER, shuffle=True, random_state=SEED + rep)
        for tr, te in outer.split(X, y, groups=g):
            fold_sizes.append((len(tr), len(te)))
            kp, ks = keyword_scores(full["title"].iloc[te], full["text"].iloc[te])
            per_fold["keyword_baseline"].append(metrics(y[te], kp, ks))
            for name in MODELS:
                m = fit(grid(name), X[tr], y[tr], g[tr])
                per_fold[name].append(metrics(y[te], m.predict(X[te]), scores_of(m, X[te])))
    n_train = int(np.mean([a for a, _ in fold_sizes]))
    n_test = int(np.mean([b for _, b in fold_sizes]))
    summary = {}
    for name, folds in per_fold.items():
        df = pd.DataFrame(folds)
        summary[name] = {k: {"mean": round(float(df[k].mean()), 4), "std": round(float(df[k].std(ddof=1)), 4)}
                         for k in df.columns}
    ref = [f["macro_f1"] for f in per_fold["logistic_regression"]]
    comparisons = {name: corrected_ttest([f["macro_f1"] for f in folds], ref, n_train, n_test)
                   for name, folds in per_fold.items() if name != "logistic_regression"}
    result["nested_cv"] = {"outer_folds": OUTER, "repetitions": REPEATS, "inner_folds": INNER,
                           "avg_train_size": n_train, "avg_test_size": n_test, "summary": summary,
                           "vs_logistic_regression_macro_f1": comparisons}

    # ---- held-out test + external real-text set ---------------------------------------------------
    held, ext, cms = {}, {}, {}
    kp, ks = keyword_scores(splits["test"]["title"], splits["test"]["text"])
    held["keyword_baseline"] = metrics(splits["test"]["category"], kp, ks)
    kp, ks = keyword_scores(external["title"], external["text"])
    ext["keyword_baseline"] = metrics(external["category"], kp, ks)
    cms["keyword_baseline"] = confusion_matrix(external["category"], kp, labels=CATEGORIES).tolist()
    by_source = {}
    for name in MODELS:
        m = fit(grid(name), trainval["doc"].to_numpy(), trainval["category"].to_numpy(),
                trainval["campaign_id"].to_numpy())
        held[name] = metrics(splits["test"]["category"], m.predict(splits["test"]["doc"]),
                             scores_of(m, splits["test"]["doc"]))
        pe = m.predict(external["doc"])
        ext[name] = metrics(external["category"], pe, scores_of(m, external["doc"]))
        cms[name] = confusion_matrix(external["category"], pe, labels=CATEGORIES).tolist()
        if hasattr(m, "best_params_"):
            held[name]["selected_params"] = m.best_params_
        by_source[name] = {src: round(float(accuracy_score(external["category"][mask], pe[mask.to_numpy()])), 4)
                           for src in external["label_source"].unique()
                           for mask in [external["label_source"] == src]}
    deployed = joblib.load(get_settings().model_path)["pipeline"]
    held["deployed_model"] = metrics(splits["test"]["category"], deployed.predict(splits["test"]["doc"]),
                                     scores_of(deployed, splits["test"]["doc"]))
    pd_ext = deployed.predict(external["doc"])
    ext["deployed_model"] = metrics(external["category"], pd_ext, scores_of(deployed, external["doc"]))
    cms["deployed_model"] = confusion_matrix(external["category"], pd_ext, labels=CATEGORIES).tolist()
    result["held_out_test"] = held
    result["external_real_text"] = {"metrics": ext, "accuracy_by_label_source": by_source,
                                    "confusion_matrices": {"labels": CATEGORIES, **cms}}

    # ---- selection rule -----------------------------------------------------------------------------
    best = max(MODELS, key=lambda n: summary[n]["macro_f1"]["mean"])
    decision = {"best_nested_cv_model": best, "deployed": "logistic_regression (lr-tfidf-20261116184426)"}
    if best == "logistic_regression":
        decision["decision"] = "keep deployed model (logistic regression has the best nested-CV macro-F1)"
    else:
        test = comparisons[best]
        better_external = ext[best]["macro_f1"] >= ext["logistic_regression"]["macro_f1"]
        promote = test["p_value"] is not None and test["p_value"] < 0.05 and test["mean_diff"] > 0 and better_external
        decision["decision"] = (f"promote {best}" if promote else
                                f"keep deployed model: {best} not significantly better "
                                f"(corrected p={test['p_value']}, external macro-F1 "
                                f"{ext[best]['macro_f1']} vs {ext['logistic_regression']['macro_f1']})")
    result["selection"] = decision
    result["runtime_s"] = round(time.time() - t0, 1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    print(f"{'model':<22}{'CV macroF1':>14}{'CV acc':>9}{'CV ROC-AUC':>11}{'test F1':>9}{'ext F1':>8}{'ext acc':>8}  p vs LR")
    for name in [*MODELS, "keyword_baseline"]:
        s = summary[name]
        auc = s.get("roc_auc_macro_ovr", {}).get("mean", float("nan"))
        p = comparisons.get(name, {}).get("p_value", "-")
        print(f"{name:<22}{s['macro_f1']['mean']:>8.3f}±{s['macro_f1']['std']:<5.3f}{s['accuracy']['mean']:>9.3f}"
              f"{auc:>11.3f}{held[name]['macro_f1']:>9.3f}{ext[name]['macro_f1']:>8.3f}{ext[name]['accuracy']:>8.3f}  {p}")
    print(f"{'deployed_model':<22}{'':>14}{'':>9}{'':>11}{held['deployed_model']['macro_f1']:>9.3f}"
          f"{ext['deployed_model']['macro_f1']:>8.3f}{ext['deployed_model']['accuracy']:>8.3f}")
    print("by label source (external accuracy):", by_source)
    print("SELECTION:", decision["decision"], f"| runtime {result['runtime_s']} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
