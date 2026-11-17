"""Detection of inconsistencies / points requiring analyst verification (CDC F04).

The result is a list of *anomalies* with a severity. Severities feed the quality
component Q of the reliability score (high -15, medium -7, low -3, info 0).
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

SEVERITY_PENALTY = {"high": 15.0, "medium": 7.0, "low": 3.0, "info": 0.0}

FLAG_DESCRIPTIONS = {
    "known_benign_infrastructure": ("medium", "Indicator belongs to well-known legitimate infrastructure "
                                              "(probable false positive or abused service)"),
    "private_address": ("low", "Private (RFC 1918) address: internal asset rather than attacker infrastructure"),
    "loopback": ("medium", "Loopback address cannot be an external indicator"),
    "reserved_address": ("medium", "Reserved / multicast / broadcast address"),
    "hash_of_empty_input": ("medium", "Hash of an empty file (copy/paste error in the report?)"),
    "low_entropy_hash": ("medium", "Hash with abnormally low entropy"),
    "documentation_range": ("info", "RFC 5737 documentation range: test / fictitious data"),
    "reserved_test_domain": ("info", "RFC 2606/6761 reserved test domain: fictitious data"),
    "tor_onion_service": ("info", "Tor onion service (RFC 7686): not resolvable on the public DNS"),
    "email_domain": ("info", "Domain extracted from an email address (sender infrastructure)"),
}


def anomaly(code: str, severity: str, message: str, **details) -> dict:
    return {"code": code, "severity": severity, "message": message, "details": details}


def detect_anomalies(
    *,
    iocs: list[dict],
    text: str,
    prediction: dict,
    declared_category: str | None,
    mitre: list[dict],
    published_at: datetime | None,
    near_duplicates: list[dict],
    rejected_overlap: dict[str, list[str]],
) -> list[dict]:
    out: list[dict] = []

    malformed = [i for i in iocs if i["status"] == "malformed"]
    if malformed:
        by_type = Counter(i["ioc_type"] for i in malformed)
        out.append(anomaly("malformed_iocs", "medium",
                           f"{len(malformed)} malformed indicator(s) detected and excluded from sharing",
                           by_type=dict(by_type), values=[i["raw_value"] for i in malformed][:10]))

    flag_hits: dict[str, list[str]] = {}
    for i in iocs:
        for f in i.get("flags") or []:
            if f in FLAG_DESCRIPTIONS:
                flag_hits.setdefault(f, []).append(i["value"])
            elif f.startswith("declared_type_mismatch"):
                flag_hits.setdefault("declared_type_mismatch", []).append(i["value"])
    for flag, values in flag_hits.items():
        if flag == "declared_type_mismatch":
            out.append(anomaly(flag, "low", "Declared IOC type differs from the detected type", values=values[:10]))
            continue
        severity, message = FLAG_DESCRIPTIONS[flag]
        out.append(anomaly(flag, severity, message, count=len(values), values=values[:10]))

    if not [i for i in iocs if i["status"] != "malformed"]:
        out.append(anomaly("no_ioc", "low", "No usable indicator of compromise found in the report"))

    words = len(text.split())
    if words < 50:
        out.append(anomaly("short_report", "low", f"Very short report ({words} words): limited context"))

    if declared_category and prediction.get("category") and declared_category != prediction["category"]:
        out.append(anomaly("category_mismatch", "medium",
                           f"Declared category '{declared_category}' differs from the ML prediction "
                           f"'{prediction['category']}'", declared=declared_category,
                           predicted=prediction["category"]))
    if prediction.get("low_confidence"):
        top = max((prediction.get("probabilities") or {"?": 0}).items(), key=lambda kv: kv[1])
        out.append(anomaly("low_classification_confidence", "low",
                           f"Classifier confidence is low ({top[1]:.2f}): category to be confirmed",
                           method=prediction.get("method")))

    unknown_mitre = [m["technique_id"] for m in mitre if m.get("method") == "declared" and m.get("confidence") == 0]
    if unknown_mitre:
        out.append(anomaly("unknown_mitre_technique", "low", "Declared ATT&CK technique(s) not in the current "
                           "catalogue (revoked / deprecated / invalid)", techniques=unknown_mitre))

    if published_at is not None:
        pub = published_at if published_at.tzinfo else published_at.replace(tzinfo=timezone.utc)
        if pub > datetime.now(timezone.utc):
            out.append(anomaly("future_publication_date", "medium", "Publication date is in the future",
                               published_at=pub.isoformat()))

    for dup in near_duplicates:
        out.append(anomaly("near_duplicate_report", "medium",
                           f"Report is very similar to {dup['report_id']} (cosine {dup['similarity']:.2f})",
                           **dup))

    if rejected_overlap:
        out.append(anomaly("ioc_in_rejected_report", "low",
                           "Some indicators were previously reported in reports REJECTED by validators",
                           overlap=rejected_overlap))
    return out


def penalty(anomalies: list[dict]) -> float:
    return min(40.0, sum(SEVERITY_PENALTY.get(a["severity"], 0.0) for a in anomalies))
