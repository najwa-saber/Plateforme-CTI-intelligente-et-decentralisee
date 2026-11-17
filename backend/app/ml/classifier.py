"""Runtime classifier used by FastAPI (model loaded once with joblib)."""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from app.core.config import get_settings
from app.ml import baseline
from app.ml.preprocess import CATEGORIES, build_document

logger = logging.getLogger("cti.ml")


@dataclass
class Prediction:
    category: str
    probabilities: dict[str, float]
    method: str  # "logistic_regression" | "keyword_baseline"
    model_version: str
    explanation: list[dict] = field(default_factory=list)
    low_confidence: bool = False

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "probabilities": self.probabilities,
            "method": self.method,
            "model_version": self.model_version,
            "explanation": self.explanation,
            "low_confidence": self.low_confidence,
        }


class ThreatClassifier:
    LOW_CONFIDENCE = 0.5

    def __init__(self, model_path: str | None = None) -> None:
        self.model_path = Path(model_path or get_settings().model_path)
        self._artifact: dict | None = None
        self._lock = threading.Lock()
        self.load_error: str | None = None

    def load(self) -> bool:
        with self._lock:
            if self._artifact is not None:
                return True
            if not self.model_path.exists():
                self.load_error = f"model file not found ({self.model_path.name}); run `python -m app.ml.train`"
                logger.warning("ML model unavailable, keyword baseline will be used: %s", self.load_error)
                return False
            import joblib

            try:
                self._artifact = joblib.load(self.model_path)
                self.load_error = None
                logger.info("ML model loaded: %s", self._artifact.get("version"))
                return True
            except Exception as exc:  # corrupted / incompatible artifact
                self.load_error = f"cannot load model: {type(exc).__name__}"
                logger.error("ML model load failed: %s", exc)
                return False

    @property
    def available(self) -> bool:
        return self._artifact is not None or self.load()

    @property
    def version(self) -> str:
        return self._artifact["version"] if self._artifact else "keyword-baseline-v1"

    def info(self) -> dict:
        info = {"available": self.available, "version": self.version, "load_error": self.load_error,
                "categories": CATEGORIES}
        if self._artifact:
            info.update({k: self._artifact.get(k) for k in ("hyperparameters", "trained_at", "training_size",
                                                               "preprocessing")})
        metrics_path = Path(get_settings().model_metrics_path)
        if metrics_path.exists():
            info["metrics"] = json.loads(metrics_path.read_text(encoding="utf-8"))
        return info

    def predict(self, title: str | None, text: str) -> Prediction:
        if not self.available:
            cat, scores, matched = baseline.predict(f"{title or ''}. {text}")
            return Prediction(
                category=cat,
                probabilities={k: round(v, 4) for k, v in scores.items()},
                method="keyword_baseline",
                model_version=self.version,
                explanation=[{"term": k, "category": c} for c, ks in matched.items() for k in ks][:10],
                low_confidence=True,
            )
        assert self._artifact is not None
        pipe = self._artifact["pipeline"]
        doc = build_document(title, text)
        proba = pipe.predict_proba([doc])[0]
        classes = list(pipe.classes_)
        probs = {c: round(float(p), 4) for c, p in zip(classes, proba)}
        best = classes[int(np.argmax(proba))]
        return Prediction(
            category=best,
            probabilities={c: probs.get(c, 0.0) for c in CATEGORIES},
            method="logistic_regression",
            model_version=self.version,
            explanation=self._explain(pipe, doc, classes.index(best)),
            low_confidence=float(np.max(proba)) < self.LOW_CONFIDENCE,
        )

    @staticmethod
    def _explain(pipe, doc: str, class_idx: int, k: int = 8) -> list[dict]:
        """Top terms of the document pushing towards the predicted class (tf-idf x coefficient)."""
        vec = pipe.named_steps["tfidf"]
        clf = pipe.named_steps["clf"]
        x = vec.transform([doc])
        names = vec.get_feature_names_out()
        coefs = clf.coef_[class_idx]
        contrib = [(names[j], float(x[0, j] * coefs[j])) for j in x.nonzero()[1]]
        contrib.sort(key=lambda t: t[1], reverse=True)
        return [{"term": t, "weight": round(w, 4)} for t, w in contrib[:k] if w > 0]


_classifier: ThreatClassifier | None = None


def get_classifier() -> ThreatClassifier:
    global _classifier
    if _classifier is None:
        _classifier = ThreatClassifier()
    return _classifier
