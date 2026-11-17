"""Build an EXTERNAL, REAL-TEXT evaluation set from the official MITRE ATT&CK Enterprise STIX bundle.

Purpose: measure how classifiers trained on the synthetic corpus behave on real, independently written CTI text
(out-of-distribution). These texts are NEVER used for training or model selection.

Source : data/raw/mitre/enterprise-attack.json (attack-stix-data, ATT&CK v20.1, downloaded 2026-11-16).
Licence: ATT&CK(R) Terms of Use - free use with attribution to The MITRE Corporation.

Labelling (documented, two kinds):
  * phishing / exploitation : ATT&CK technique descriptions, label from a fixed technique-ID -> category mapping
    decided by the analyst (independent of the wording of the descriptions) -> "expert mapping";
  * ransomware / malware     : ATT&CK *software* (malware) descriptions; ransomware = the FIRST sentence of the
    description says "ransomware" (a loader that merely deploys ransomware is not counted); malware = description names a RAT / backdoor / stealer / banking trojan / botnet / loader and does
    NOT mention ransom -> "weak label derived from the description" (favours keyword-based methods; reported apart).
Up to 15 documents per category, deterministic order (sorted by ATT&CK id / name).

Usage: python data/scripts/build_attack_eval_set.py
Output: data/external/attack_eval.jsonl
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

DATA = Path(__file__).resolve().parents[1]
SRC = DATA / "raw" / "mitre" / "enterprise-attack.json"
OUT = DATA / "external" / "attack_eval.jsonl"
CAP = 15

PHISHING = ["T1566", "T1566.001", "T1566.002", "T1566.003", "T1566.004", "T1598", "T1598.001", "T1598.002",
            "T1598.003", "T1598.004", "T1534"]
EXPLOITATION = ["T1190", "T1203", "T1210", "T1211", "T1212", "T1068", "T1595.002", "T1588.005", "T1588.006",
                "T1587.004"]
MALWARE_HINTS = re.compile(r"remote access (?:trojan|tool)|\bRAT\b|backdoor|(?:information|info|credential|password) "
                           r"stealer|infostealer|banking trojan|botnet|\bloader\b|\bdownloader\b", re.IGNORECASE)
CITATION = re.compile(r"\(Citation:[^)]*\)")


def clean(text: str) -> str:
    text = CITATION.sub("", text or "")
    text = re.sub(r"\[([^\]]+)\]\(https?://[^)]+\)", r"\1", text)
    text = re.sub(r"<code>|</code>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def ext_id(obj: dict) -> str | None:
    return next((r.get("external_id") for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"), None)


def main() -> int:
    if not SRC.exists():
        print(f"missing {SRC} - download enterprise-attack.json first (see docs/06_installation.md)")
        return 1
    objs = [o for o in json.loads(SRC.read_text(encoding="utf-8"))["objects"]
            if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    rows: list[dict] = []
    techniques = {ext_id(o): o for o in objs if o.get("type") == "attack-pattern"}
    for cat, ids in (("phishing", PHISHING), ("exploitation", EXPLOITATION)):
        for tid in ids[:CAP]:
            o = techniques.get(tid)
            if o:
                rows.append({"id": f"ATTACK-{tid}", "title": o["name"], "text": clean(o.get("description", "")),
                             "category": cat, "label_source": "expert_mapping", "attack_id": tid})
    malware = sorted((o for o in objs if o.get("type") == "malware"), key=lambda o: o.get("name", ""))
    def first(o: dict) -> str:
        return re.split(r"(?<=[.!?])\s", clean(o.get("description") or ""), maxsplit=1)[0].lower()

    ransom = [o for o in malware if "ransomware" in first(o)]  # the FIRST sentence defines the software as such
    other = [o for o in malware if "ransom" not in (o.get("description") or "").lower()
             and MALWARE_HINTS.search(o.get("description") or "")]
    for cat, items in (("ransomware", ransom), ("malware", other)):
        for o in items[:CAP]:
            rows.append({"id": f"ATTACK-{ext_id(o)}", "title": o["name"], "text": clean(o.get("description", "")),
                         "category": cat, "label_source": "weak_description_label", "attack_id": ext_id(o)})
    rows = [r for r in rows if len(r["text"].split()) >= 15]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    counts = {c: sum(r["category"] == c for r in rows) for c in ("phishing", "ransomware", "malware", "exploitation")}
    print(f"{len(rows)} real-text documents -> {OUT.relative_to(DATA.parent)}  {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
