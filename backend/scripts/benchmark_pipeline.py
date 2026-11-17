"""Processing-time measurement of the offline analysis stages (cadrage §9 "temps de traitement").

Measures, for each of the 80 annotated reports, the latency of: IOC extraction, ML classification, ATT&CK
enrichment, canonical SHA-256 fingerprint, and the correlation of one report against all others.
Network-bound stages (MISP push, Ethereum transactions) are measured end-to-end by scripts/run_demo_scenario.py.
Output: docs/test-reports/pipeline_benchmark.json   Usage (from backend/): python scripts/benchmark_pipeline.py
"""
from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))

from app.core.canonical import canonical_payload, sha256_hex  # noqa: E402
from app.correlation.engine import CorrelationEngine, ReportFeatures  # noqa: E402
from app.ml.classifier import ThreatClassifier  # noqa: E402
from app.mitre.enricher import MitreEnricher  # noqa: E402
from app.nlp.ioc_extractor import IOCExtractor  # noqa: E402


def ms(samples: list[float]) -> dict:
    s = sorted(samples)
    return {"mean_ms": round(statistics.mean(s) * 1000, 2), "median_ms": round(statistics.median(s) * 1000, 2),
            "p95_ms": round(s[int(0.95 * (len(s) - 1))] * 1000, 2), "max_ms": round(s[-1] * 1000, 2)}


def main() -> int:
    reports = [json.loads(line) for line in (ROOT / "data/annotated/reports.jsonl").read_text(encoding="utf-8").splitlines()]
    ex, enr, clf = IOCExtractor(), MitreEnricher(), ThreatClassifier()
    clf.load()
    enr.enrich("warm-up", "warm-up text for the similarity index")      # build the STIX TF-IDF index once
    t = {k: [] for k in ("ioc_extraction", "classification", "mitre_enrichment", "sha256_fingerprint", "correlation")}
    feats = []
    for r in reports:
        a = time.perf_counter()
        iocs = ex.extract(r["text"]).iocs
        t["ioc_extraction"].append(time.perf_counter() - a)
        a = time.perf_counter()
        cat = clf.predict(r["title"], r["text"]).category
        t["classification"].append(time.perf_counter() - a)
        a = time.perf_counter()
        mitre = enr.enrich(r["title"], r["text"])
        t["mitre_enrichment"].append(time.perf_counter() - a)
        a = time.perf_counter()
        sha256_hex(canonical_payload(report_id=r["report_id"], title=r["title"], text=r["text"], source="synthetic",
                                     published_at=r["published_at"], tlp="TLP:GREEN", submitter_code="A",
                                     iocs=[(i.ioc_type, i.value) for i in iocs]))
        t["sha256_fingerprint"].append(time.perf_counter() - a)
        feats.append(ReportFeatures(report_id=r["report_id"], title=r["title"], text=r["text"], category=cat,
                                    date=None, iocs={(i.ioc_type, i.value) for i in iocs},
                                    mitre={m.technique_id for m in mitre if m.method == "rule"}))
    engine = CorrelationEngine()
    for f in feats:
        a = time.perf_counter()
        engine.correlate(f, feats)
        t["correlation"].append(time.perf_counter() - a)
    per_report = [sum(t[k][i] for k in t) for i in range(len(reports))]
    out = {"executed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "reports": len(reports),
           "machine": {"python": platform.python_version(), "platform": platform.platform()},
           "stages": {k: ms(v) for k, v in t.items()}, "total_per_report": ms(per_report),
           "note": "Offline stages only (no network). Correlation = one report against the 80 reports."}
    (ROOT / "docs/test-reports/pipeline_benchmark.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    for k, v in out["stages"].items():
        print(f"{k:<20} median {v['median_ms']:>8} ms   p95 {v['p95_ms']:>8} ms")
    print(f"{'total/report':<20} median {out['total_per_report']['median_ms']:>8} ms   p95 {out['total_per_report']['p95_ms']:>8} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
