"""Correlation engine between CTI reports (CDC 11, cadrage 4.8).

For a pair of reports the score in [0, 1] is a weighted sum of five explainable components:
  ioc      : shared normalised indicators. Evidence strength depends on the type
             (hash 0.9, url 0.8, domain 0.7, ipv4 0.5) and is combined as 1 - prod(1 - w_i);
             domains include URL hosts. Indicators flagged as well-known benign infrastructure
             or private addresses are ignored (they would create spurious links).
  mitre    : Jaccard index of ATT&CK techniques supported by evidence (rule / declared).
  text     : TF-IDF cosine similarity of the report texts (vectoriser fitted on the current corpus).
  time     : exp(-|delta_days| / tau) on publication (or import) dates.
  category : 1 if both reports have the same predicted category.
Weights and the threshold are configurable (.env or API query parameters).
A correlation is a POTENTIAL link supported by evidence; it never concludes that two
reports belong to the same campaign.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.core.config import get_settings
from app.ml.preprocess import clean_text

IOC_TYPE_WEIGHT = {"sha256": 0.9, "md5": 0.9, "url": 0.8, "domain": 0.7, "ipv4": 0.5}
NOISY_FLAGS = {"known_benign_infrastructure", "private_address", "loopback", "reserved_address",
               "hash_of_empty_input", "low_entropy_hash"}


@dataclass
class CorrelationWeights:
    ioc: float
    mitre: float
    text: float
    time: float
    category: float

    @classmethod
    def from_settings(cls, **overrides) -> "CorrelationWeights":
        s = get_settings()
        w = cls(ioc=s.corr_weight_ioc, mitre=s.corr_weight_mitre, text=s.corr_weight_text,
                time=s.corr_weight_time, category=s.corr_weight_category)
        for k, v in overrides.items():
            if v is not None:
                setattr(w, k, float(v))
        total = w.ioc + w.mitre + w.text + w.time + w.category
        if total <= 0:
            raise ValueError("correlation weights must not all be zero")
        # normalise so that the score stays in [0, 1]
        w.ioc, w.mitre, w.text, w.time, w.category = (x / total for x in (w.ioc, w.mitre, w.text, w.time, w.category))
        return w

    def as_dict(self) -> dict:
        return {k: round(v, 4) for k, v in self.__dict__.items()}


@dataclass
class ReportFeatures:
    report_id: str
    title: str
    text: str
    category: str | None
    date: datetime | None
    iocs: set[tuple[str, str]]
    mitre: set[str]


def report_features(report) -> ReportFeatures:
    from app.nlp.normalizer import url_host

    iocs: set[tuple[str, str]] = set()
    for i in report.iocs:
        if i.status == "malformed" or (set(i.flags or []) & NOISY_FLAGS):
            continue
        iocs.add((i.ioc_type, i.value))
        if i.ioc_type == "url":
            host = url_host(i.value)
            if host and not host.replace(".", "").isdigit():
                iocs.add(("domain", host))
            elif host:
                iocs.add(("ipv4", host))
    mitre = {m.technique_id for m in report.mitre_matches if m.method in ("rule", "declared") and m.confidence > 0}
    return ReportFeatures(report_id=report.id, title=report.title, text=report.text, category=report.category,
                          date=report.published_at or report.created_at, iocs=iocs, mitre=mitre)


def _aware(d: datetime | None) -> datetime | None:
    if d is None:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def strength_label(score: float, threshold: float) -> str:
    if score >= max(0.6, threshold + 0.3):
        return "strong"
    if score >= max(0.45, threshold + 0.15):
        return "moderate"
    return "weak"


class CorrelationEngine:
    def __init__(self, weights: CorrelationWeights | None = None, threshold: float | None = None,
                 tau_days: float | None = None) -> None:
        s = get_settings()
        self.weights = weights or CorrelationWeights.from_settings()
        self.threshold = s.corr_threshold if threshold is None else threshold
        self.tau = tau_days or s.corr_time_decay_days

    def text_similarity_matrix(self, feats: list[ReportFeatures]):
        docs = [clean_text(f"{f.title}. {f.text}") for f in feats]
        if len(docs) < 2:
            return None
        vec = TfidfVectorizer(stop_words="english", sublinear_tf=True, ngram_range=(1, 2), min_df=1)
        try:
            matrix = vec.fit_transform(docs)
        except ValueError:  # empty vocabulary
            return None
        return cosine_similarity(matrix)

    def pair(self, a: ReportFeatures, b: ReportFeatures, text_sim: float) -> dict:
        shared = sorted(a.iocs & b.iocs)
        ioc_score = 1.0 - math.prod(1.0 - IOC_TYPE_WEIGHT.get(t, 0.5) for t, _ in shared) if shared else 0.0
        union = a.mitre | b.mitre
        shared_mitre = sorted(a.mitre & b.mitre)
        mitre_score = len(shared_mitre) / len(union) if union else 0.0
        da, db_ = _aware(a.date), _aware(b.date)
        delta_days = abs((da - db_).total_seconds()) / 86400 if da and db_ else None
        time_score = math.exp(-delta_days / self.tau) if delta_days is not None else 0.0
        same_cat = bool(a.category and a.category == b.category)
        components = {
            "ioc": round(ioc_score, 4),
            "mitre": round(mitre_score, 4),
            "text": round(float(text_sim), 4),
            "time": round(time_score, 4),
            "category": 1.0 if same_cat else 0.0,
        }
        w = self.weights
        score = (w.ioc * ioc_score + w.mitre * mitre_score + w.text * float(text_sim) + w.time * time_score
                 + w.category * components["category"])
        reasons = []
        if shared:
            reasons.append(f"{len(shared)} shared indicator(s): " + ", ".join(f"{t}:{v}" for t, v in shared[:6]))
        if shared_mitre:
            reasons.append("shared ATT&CK technique(s): " + ", ".join(shared_mitre))
        if text_sim >= 0.2:
            reasons.append(f"textual similarity {text_sim:.2f}")
        if delta_days is not None and delta_days <= self.tau:
            reasons.append(f"published {delta_days:.0f} day(s) apart")
        if same_cat:
            reasons.append(f"same category ({a.category})")
        return {
            "score": round(score, 4),
            "components": components,
            "weighted": {k: round(getattr(w, k) * v, 4) for k, v in components.items()},
            "evidence": {
                "shared_iocs": [{"type": t, "value": v} for t, v in shared],
                "shared_mitre": shared_mitre,
                "text_similarity": round(float(text_sim), 4),
                "delta_days": round(delta_days, 1) if delta_days is not None else None,
                "same_category": same_cat,
                "reasons": reasons,
                "interpretation": "Potential relation supported by the evidence above; it does not prove that "
                                  "both reports describe the same campaign.",
            },
        }

    def correlate(self, target: ReportFeatures, others: list[ReportFeatures], keep_all: bool = False) -> list[dict]:
        feats = [target, *[o for o in others if o.report_id != target.report_id]]
        sims = self.text_similarity_matrix(feats)
        out = []
        for idx, other in enumerate(feats[1:], start=1):
            text_sim = float(sims[0, idx]) if sims is not None else 0.0
            res = self.pair(target, other, text_sim)
            if keep_all or res["score"] >= self.threshold:
                res["report_id"] = other.report_id
                res["strength"] = strength_label(res["score"], self.threshold)
                out.append(res)
        return sorted(out, key=lambda r: -r["score"])
