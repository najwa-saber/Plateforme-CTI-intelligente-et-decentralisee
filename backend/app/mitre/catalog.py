"""Access to the official MITRE ATT&CK Enterprise catalogue (derived from the STIX 2.1 bundle)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from app.core.config import get_settings


class MitreCatalog:
    def __init__(self, path: str | Path) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.techniques: dict[str, dict] = data["techniques"]
        self.attack_version: str | None = data.get("attack_version")
        self.source: str = data.get("source", "MITRE ATT&CK")

    def get(self, technique_id: str) -> dict | None:
        return self.techniques.get(technique_id.upper())

    def exists(self, technique_id: str) -> bool:
        return technique_id.upper() in self.techniques

    def parent_of(self, technique_id: str) -> str | None:
        return technique_id.split(".")[0] if "." in technique_id else None

    def __len__(self) -> int:
        return len(self.techniques)


@lru_cache(maxsize=1)
def get_catalog() -> MitreCatalog:
    return MitreCatalog(get_settings().mitre_catalog_path)
