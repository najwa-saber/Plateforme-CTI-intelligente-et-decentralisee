"""Build the compact MITRE ATT&CK technique catalogue used by the backend.

Source: official MITRE ATT&CK Enterprise STIX 2.1 bundle
(https://github.com/mitre-attack/attack-stix-data, file enterprise-attack/enterprise-attack.json).

The full bundle (~55 MB) is parsed once; only active (non revoked, non deprecated)
``attack-pattern`` objects are kept, with the fields needed for enrichment:
external id (Txxxx / Txxxx.yyy), name, tactics (kill-chain phases), platforms,
short description and the official URL.

Usage:
    python backend/scripts/build_mitre_dataset.py data/raw/mitre/enterprise-attack.json \
        backend/app/mitre/data/enterprise_techniques.json
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_CITATION = re.compile(r"\(Citation:[^)]*\)")


def _clean_description(text: str, limit: int = 600) -> str:
    text = _CITATION.sub("", text or "")
    text = re.sub(r"<code>|</code>", "", text)
    text = re.sub(r"\[([^\]]+)\]\(https?://[^)]+\)", r"\1", text)  # markdown links -> label
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "..."
    return text


def build(src: Path, dst: Path) -> dict:
    bundle = json.loads(src.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])
    collection = next((o for o in objects if o.get("type") == "x-mitre-collection"), {})
    tactics_by_shortname = {
        o["x_mitre_shortname"]: o["name"]
        for o in objects
        if o.get("type") == "x-mitre-tactic" and not o.get("revoked") and not o.get("x_mitre_deprecated")
    }
    techniques = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext or not ext.get("external_id"):
            continue
        tid = ext["external_id"]
        tactics = [
            tactics_by_shortname.get(p["phase_name"], p["phase_name"])
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques[tid] = {
            "id": tid,
            "stix_id": obj["id"],
            "name": obj.get("name"),
            "tactics": tactics,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "platforms": obj.get("x_mitre_platforms", []),
            "description": _clean_description(obj.get("description", "")),
            "url": ext.get("url"),
        }
    payload = {
        "source": "MITRE ATT&CK Enterprise (STIX 2.1) - https://github.com/mitre-attack/attack-stix-data",
        "attack_version": collection.get("x_mitre_version"),
        "attack_spec_version": collection.get("x_mitre_attack_spec_version"),
        "collection_modified": collection.get("modified"),
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "license_note": "ATT&CK(R) is a registered trademark of The MITRE Corporation. "
        "Used under the ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).",
        "technique_count": len(techniques),
        "techniques": dict(sorted(techniques.items())),
    }
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return payload


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    result = build(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"ATT&CK v{result['attack_version']}: {result['technique_count']} active techniques written")
