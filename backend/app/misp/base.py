"""Common MISP adapter interface (real PyMISP instance or simulated fallback)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

# Platform IOC type -> (MISP attribute type, MISP category)
IOC_TO_MISP = {
    "ipv4": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "md5": ("md5", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
}
MISP_TO_IOC = {"ip-dst": "ipv4", "ip-src": "ipv4", "domain": "domain", "hostname": "domain", "url": "url",
               "md5": "md5", "sha256": "sha256"}
THREAT_LEVEL = {"high": 1, "medium": 2, "low": 3, "undefined": 4}


def tag_key(tag: str) -> str | None:
    """'cti-platform:status="PENDING"' -> 'cti-platform:status=' (machine tags with a value)."""
    return tag.split("=", 1)[0] + "=" if "=" in tag and ":" in tag.split("=", 1)[0] else None


def superseded_tags(existing: list[str], new_tags: list[str]) -> list[str]:
    """Existing machine tags whose key is re-set with another value (e.g. a previous status)."""
    keys = {tag_key(t) for t in new_tags} - {None}
    return [t for t in existing if tag_key(t) in keys and t not in new_tags]


@dataclass
class MispEventPayload:
    """Everything the platform pushes to MISP for one report (off-chain data)."""

    report_id: str
    title: str
    description: str
    submitter: str
    tlp: str
    category: str | None
    published_at: str | None
    source: str | None
    iocs: list[dict] = field(default_factory=list)  # {type, value, status, context, confidence, flags}
    mitre: list[dict] = field(default_factory=list)  # {technique_id, name, method, confidence}
    tags: list[str] = field(default_factory=list)

    def all_tags(self) -> list[str]:
        tags = [self.tlp.lower().replace("tlp:", "tlp:"), f'cti-platform:report-id="{self.report_id}"',
                f'cti-platform:submitter="{self.submitter}"']
        if self.category:
            tags.append(f'cti-platform:category="{self.category}"')
        for m in self.mitre:
            if m.get("method") != "similarity":  # weak suggestions are not exported as tags
                tags.append(f'misp-galaxy:mitre-attack-pattern="{m["name"]} - {m["technique_id"]}"')
        tags.extend(self.tags)
        return list(dict.fromkeys(tags))

    def threat_level(self) -> int:
        return THREAT_LEVEL["high"] if self.category in {"ransomware", "exploitation"} else THREAT_LEVEL["medium"]


class MispAdapter(ABC):
    mode: str = "abstract"

    @abstractmethod
    def health(self) -> dict: ...

    @abstractmethod
    def push_report(self, payload: MispEventPayload) -> dict:
        """Create the event; returns {event_id, event_uuid, attribute_count, tags}."""

    @abstractmethod
    def add_tags(self, event_ref: str, tags: list[str]) -> None:
        """Add tags; machine tags 'ns:key="value"' replace the previous value of the same key."""

    @abstractmethod
    def search_ioc(self, value: str) -> list[dict]:
        """Return [{event_id, event_uuid, event_info, type, value}] for attributes equal to value."""

    @abstractmethod
    def list_events(self, limit: int = 50) -> list[dict]: ...

    @abstractmethod
    def get_event(self, event_ref: str) -> dict: ...
