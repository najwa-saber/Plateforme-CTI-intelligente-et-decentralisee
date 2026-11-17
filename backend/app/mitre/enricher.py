"""MITRE ATT&CK enrichment engine.

Two explainable methods:
1. ``rule``: characteristic expressions (app.mitre.rules). Each proposal stores the
   matched expressions and the sentence where they appear (verifiable evidence).
2. ``similarity``: TF-IDF cosine similarity between the report and the *official*
   technique descriptions from the ATT&CK STIX data. Lower confidence suggestions,
   only shown when above a configurable threshold.
Techniques declared by the author (structured import) are verified against the
catalogue and kept with method ``declared``.
"""
from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

from app.core.config import get_settings
from app.mitre.catalog import MitreCatalog, get_catalog
from app.mitre.rules import RULES, MitreRule
from app.nlp.normalizer import refang

logger = logging.getLogger("cti.mitre")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


@dataclass
class TechniqueMatch:
    technique_id: str
    name: str
    tactics: list[str]
    method: str
    confidence: float
    justification: str
    evidence: list[dict] = field(default_factory=list)
    url: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class MitreEnricher:
    def __init__(self, catalog: MitreCatalog | None = None) -> None:
        self.catalog = catalog or get_catalog()
        self.rules: list[tuple[MitreRule, list[re.Pattern]]] = []
        self.invalid_rules: list[str] = []
        for rule in RULES:
            if not self.catalog.exists(rule.technique_id):
                self.invalid_rules.append(rule.technique_id)
                continue
            self.rules.append((rule, [re.compile(p, re.IGNORECASE) for p in rule.patterns]))
        if self.invalid_rules:
            logger.warning("MITRE rules ignored (not in ATT&CK v%s): %s", self.catalog.attack_version,
                           self.invalid_rules)
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix = None
        self._ids: list[str] = []

    # -- similarity index over official descriptions ----------------------------------
    def _ensure_index(self) -> None:
        if self._vectorizer is not None:
            return
        self._ids = list(self.catalog.techniques)
        docs = [f"{t['name']}. {t['name']}. {t['description']}" for t in self.catalog.techniques.values()]
        self._vectorizer = TfidfVectorizer(stop_words="english", sublinear_tf=True, ngram_range=(1, 2), min_df=1,
                                           max_df=0.5)
        self._matrix = self._vectorizer.fit_transform(docs)

    def _match(self, technique_id: str, method: str, confidence: float, justification: str,
               evidence: list[dict]) -> TechniqueMatch:
        t = self.catalog.get(technique_id) or {}
        return TechniqueMatch(technique_id=technique_id, name=t.get("name", "?"), tactics=t.get("tactics", []),
                              method=method, confidence=round(confidence, 2), justification=justification,
                              evidence=evidence, url=t.get("url"))

    def enrich(self, title: str | None, text: str, declared: list[str] | None = None) -> list[TechniqueMatch]:
        settings = get_settings()
        full = refang(f"{title or ''}. {text}")
        sentences = [s.strip() for s in _SENTENCE_SPLIT.split(full) if s.strip()]
        results: dict[str, TechniqueMatch] = {}

        # 1) rules
        for rule, patterns in self.rules:
            evidence: list[dict] = []
            for pat in patterns:
                for sentence in sentences:
                    m = pat.search(sentence)
                    if m:
                        evidence.append({"expression": m.group(0), "pattern": pat.pattern,
                                         "sentence": sentence[:300]})
                        break
            if not evidence:
                continue
            distinct = len({e["pattern"] for e in evidence})
            conf = min(0.95, rule.base_confidence + 0.08 * (distinct - 1))
            exprs = ", ".join(sorted({f"'{e['expression']}'" for e in evidence}))
            justification = (f"{rule.rationale} Expression(s) found: {exprs}. "
                             f"Keyword-based proposal: requires analyst confirmation.")
            results[rule.technique_id] = self._match(rule.technique_id, "rule", conf, justification, evidence[:4])

        # keep the most specific technique when a sub-technique of the same parent was found
        for tid in list(results):
            parent = self.catalog.parent_of(tid)
            if parent and parent in results and results[parent].method == "rule":
                child = results[tid]
                child.confidence = round(max(child.confidence, results[parent].confidence), 2)
                child.evidence = (child.evidence + results[parent].evidence)[:5]
                del results[parent]

        # 2) declared techniques (structured import)
        for tid in declared or []:
            tid = str(tid).strip().upper()
            if not tid:
                continue
            if not self.catalog.exists(tid):
                results[tid] = TechniqueMatch(technique_id=tid, name="Unknown / deprecated technique", tactics=[],
                                              method="declared", confidence=0.0,
                                              justification="Declared by the source but absent from ATT&CK "
                                                            f"v{self.catalog.attack_version} (revoked, deprecated or invalid).",
                                              evidence=[], url=None)
            elif tid in results:
                results[tid].justification += " Also declared by the source."
                results[tid].confidence = round(min(0.98, results[tid].confidence + 0.1), 2)
            else:
                results[tid] = self._match(tid, "declared", 0.8, "Technique declared by the report source "
                                           "(structured import), verified against the ATT&CK catalogue.", [])

        # 3) similarity with official descriptions (low-confidence suggestions)
        try:
            self._ensure_index()
            assert self._vectorizer is not None
            q = self._vectorizer.transform([full])
            sims = linear_kernel(q, self._matrix).ravel()
            ranked = sims.argsort()[::-1]
            added = 0
            for idx in ranked[:20]:
                score = float(sims[idx])
                if score < settings.mitre_similarity_threshold or added >= settings.mitre_max_similarity_suggestions:
                    break
                tid = self._ids[idx]
                parent = self.catalog.parent_of(tid)
                if tid in results or (parent and parent in results) or any(
                        k.startswith(tid + ".") for k in results):
                    continue
                vocab = self._vectorizer.get_feature_names_out()
                qv, dv = q.toarray().ravel(), self._matrix[idx].toarray().ravel()
                shared = [vocab[i] for i in (qv * dv).argsort()[::-1][:5] if qv[i] * dv[i] > 0]
                results[tid] = self._match(
                    tid, "similarity", min(0.45, 0.2 + score), (
                        f"Textual similarity {score:.2f} with the official ATT&CK description "
                        f"(shared terms: {', '.join(shared)}). Weak suggestion, not evidence."),
                    [{"similarity": round(score, 3), "shared_terms": shared}])
                added += 1
        except Exception as exc:  # pragma: no cover - defensive, enrichment must not break analysis
            logger.warning("MITRE similarity suggestions unavailable: %s", exc)

        return sorted(results.values(), key=lambda m: (-m.confidence, m.technique_id))


@lru_cache(maxsize=1)
def get_enricher() -> MitreEnricher:
    return MitreEnricher()
