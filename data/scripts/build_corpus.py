"""Build the annotated CTI corpus (CDC section 4) from the authored synthetic sources.

Inputs : data/scripts/corpus/{phishing,ransomware,malware,exploitation}.py
Outputs: data/raw/reports/*.txt
         data/annotated/reports.jsonl, iocs.csv, relations.csv
         data/splits/train.jsonl, validation.jsonl, test.jsonl  (60/20/20, grouped by campaign)

Gold IOCs come from the inline markup written by the annotator, never from the
platform's extractor, so that extraction precision/recall can be measured honestly.

Usage: python data/scripts/build_corpus.py
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

DATA = Path(__file__).resolve().parents[1]
ROOT = DATA.parent
SRC = Path(__file__).resolve().parent / "corpus"
CATALOG = ROOT / "backend" / "app" / "mitre" / "data" / "enterprise_techniques.json"
CATEGORIES = ["phishing", "ransomware", "malware", "exploitation"]
SEED = 42

MARKUP = re.compile(r"<<(?P<type>ipv4|domain|url|md5|sha256)\|(?P<display>[^|>]+)(?:\|(?P<gold>[^>]+))?>>")


def _load(category: str) -> list[dict]:
    spec = importlib.util.spec_from_file_location(f"corpus_{category}", SRC / f"{category}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.REPORTS


def _hash(kind: str, seed: str) -> str:
    data = f"synthetic-cti::{seed}".encode()
    return hashlib.md5(data).hexdigest() if kind == "md5" else hashlib.sha256(data).hexdigest()


def render(text: str) -> tuple[str, list[tuple[str, str]]]:
    gold: list[tuple[str, str]] = []

    def repl(m: re.Match) -> str:
        kind, display, gold_value = m.group("type"), m.group("display").strip(), m.group("gold")
        if display.startswith("@"):
            display = _hash(kind, display[1:])
        value = (gold_value or display).strip()
        if kind in ("domain", "md5", "sha256"):
            value = value.lower()
        if kind == "url":
            scheme, rest = value.split("://", 1)
            host, _, path = rest.partition("/")
            value = f"{scheme.lower()}://{host.lower()}/{path}"
        if (kind, value) not in gold:
            gold.append((kind, value))
        return display

    rendered = MARKUP.sub(repl, text)
    rendered = re.sub(r"[ \t]*\n[ \t]*", " ", rendered).strip()  # authored line wraps are not paragraphs
    return rendered, gold


def grouped_split(records: list[dict]) -> dict[str, str]:
    """Assign whole campaigns to train/validation/test, per category, approx. 60/20/20."""
    rng = random.Random(SEED)
    assignment: dict[str, str] = {}
    for cat in CATEGORIES:
        groups: dict[str, list[str]] = defaultdict(list)
        for r in records:
            if r["category"] == cat:
                groups[r["campaign_id"]].append(r["report_id"])
        items = list(groups.items())
        rng.shuffle(items)
        items.sort(key=lambda kv: -len(kv[1]))  # place big campaigns first (stable after shuffle)
        n = sum(len(v) for _, v in items)
        target = {"train": 0.6 * n, "validation": 0.2 * n, "test": 0.2 * n}
        filled = {"train": 0, "validation": 0, "test": 0}
        for campaign, ids in items:
            split = max(target, key=lambda s: (target[s] - filled[s]) / target[s])
            filled[split] += len(ids)
            for rid in ids:
                assignment[rid] = split
    return assignment


def main() -> int:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))["techniques"] if CATALOG.exists() else {}
    records: list[dict] = []
    gold_iocs: list[dict] = []
    warnings: list[str] = []
    for cat in CATEGORIES:
        for item in _load(cat):
            text, gold = render(item["text"])
            unknown = [t for t in item["mitre"] if catalog and t not in catalog]
            if unknown:
                warnings.append(f"{item['id']}: techniques not in ATT&CK catalogue: {unknown}")
            records.append({
                "report_id": item["id"],
                "title": item["title"],
                "text": text,
                "category": cat,
                "mitre_techniques": [t for t in item["mitre"] if t not in unknown],
                "source": "synthetic",
                "source_url": None,
                "published_at": item["published"],
                "language": "en",
                "annotation_status": "validated",
                "campaign_id": item["campaign"],
                "ambiguous": item.get("ambiguous", False),
                "notes": "Synthetic report written for the academic prototype; indicators are fictitious "
                         "(RFC 5737 / RFC 2606 / RFC 6761).",
            })
            for kind, value in gold:
                gold_iocs.append({"report_id": item["id"], "ioc_type": kind, "ioc_value": value,
                                  "malicious_label": "unknown"})

    ids = [r["report_id"] for r in records]
    assert len(ids) == len(set(ids)), "duplicate report ids"

    # --- raw layer -------------------------------------------------------------------
    raw_dir = DATA / "raw" / "reports"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for r in records:
        (raw_dir / f"{r['report_id']}.txt").write_text(f"{r['title']}\n\n{r['text']}\n", encoding="utf-8")

    # --- annotated layer -------------------------------------------------------------
    ann = DATA / "annotated"
    ann.mkdir(parents=True, exist_ok=True)
    with (ann / "reports.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    with (ann / "iocs.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["report_id", "ioc_type", "ioc_value", "malicious_label"],
                           lineterminator="\n")  # LF on every OS (byte-identical regeneration in CI)
        w.writeheader()
        w.writerows(gold_iocs)

    # --- relations (for correlation evaluation) --------------------------------------
    by_report: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for g in gold_iocs:
        by_report[g["report_id"]].add((g["ioc_type"], g["ioc_value"]))
    campaign = {r["report_id"]: r["campaign_id"] for r in records}
    priority = ["sha256", "md5", "url", "domain", "ipv4"]
    names = {"sha256": "shared_hash", "md5": "shared_hash", "url": "shared_url", "domain": "shared_domain",
             "ipv4": "shared_ip"}
    relations: list[dict] = []
    positives: set[tuple[str, str]] = set()
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            shared = by_report[a] & by_report[b]
            if shared:
                kind = next(k for k in priority if any(t == k for t, _ in shared))
                relations.append({"report_id_1": a, "report_id_2": b, "relation_type": names[kind],
                                  "relation_label": 1})
                positives.add((a, b))
            elif campaign[a] == campaign[b]:
                relations.append({"report_id_1": a, "report_id_2": b, "relation_type": "same_campaign",
                                  "relation_label": 1})
                positives.add((a, b))
    rng = random.Random(SEED)
    negatives = 0
    while negatives < 120:
        a, b = sorted(rng.sample(ids, 2))
        if (a, b) in positives or campaign[a] == campaign[b]:
            continue
        positives.add((a, b))
        relations.append({"report_id_1": a, "report_id_2": b, "relation_type": "none", "relation_label": 0})
        negatives += 1
    with (ann / "relations.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["report_id_1", "report_id_2", "relation_type", "relation_label"],
                           lineterminator="\n")
        w.writeheader()
        w.writerows(relations)

    # --- splits ----------------------------------------------------------------------
    assignment = grouped_split(records)
    split_dir = DATA / "splits"
    split_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    handles = {s: (split_dir / f"{s}.jsonl").open("w", encoding="utf-8", newline="\n")
               for s in ("train", "validation", "test")}
    try:
        for r in records:
            split = assignment[r["report_id"]]
            handles[split].write(json.dumps(r, ensure_ascii=False) + "\n")
            counts[split][r["category"]] += 1
    finally:
        for h in handles.values():
            h.close()

    # Leakage guard: a campaign must never appear in two splits
    camp_split: dict[str, set[str]] = defaultdict(set)
    for r in records:
        camp_split[r["campaign_id"]].add(assignment[r["report_id"]])
    leaking = [c for c, s in camp_split.items() if len(s) > 1]
    assert not leaking, f"campaign leakage between splits: {leaking}"

    print(f"reports: {len(records)}  gold IOCs: {len(gold_iocs)}  relations: {len(relations)} "
          f"(positives {sum(r['relation_label'] for r in relations)})")
    for split in ("train", "validation", "test"):
        print(f"  {split:<10} {sum(counts[split].values()):>3}  {dict(counts[split])}")
    for w in warnings:
        print("WARNING", w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
