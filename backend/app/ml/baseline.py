"""Rule-based keyword baseline (cadrage 4.3: fallback when no labelled data / model).

Also used as a scientific reference point to measure what the learned model adds.
"""
from __future__ import annotations

import math
import re

KEYWORDS: dict[str, list[str]] = {
    "phishing": ["phishing", "phish", "credential", "login page", "lure", "spoof", "impersonat", "smishing",
                 "sms", "email", "mailbox", "sign-in", "harvest", "fake portal", "lookalike", "qr code",
                 "voice", "social engineering"],
    "ransomware": ["ransom", "encrypt", "decrypt", "extortion", "leak site", "locker", "shadow cop",
                   "backup", "affiliate", "negotiat", "bitcoin", "note"],
    "malware": ["trojan", "stealer", "rat ", "backdoor", "loader", "botnet", "miner", "spyware", "wiper",
                "implant", "payload", "beacon", "dropper", "keylog", "persistence", "plugin", "c2"],
    "exploitation": ["cve", "vulnerab", "exploit", "patch", "injection", "remote code execution",
                     "privilege escalation", "zero-day", "overflow", "web shell", "unauthenticated",
                     "bypass", "scanning", "advisory", "deserializ", "traversal"],
}


def keyword_scores(text: str) -> dict[str, float]:
    t = (text or "").lower()
    counts = {cat: sum(len(re.findall(re.escape(k), t)) for k in words) for cat, words in KEYWORDS.items()}
    # softmax over counts -> pseudo-probabilities (NOT calibrated)
    exps = {c: math.exp(v) for c, v in counts.items()}
    total = sum(exps.values())
    return {c: exps[c] / total for c in counts}


def predict(text: str) -> tuple[str, dict[str, float], dict[str, list[str]]]:
    scores = keyword_scores(text)
    t = (text or "").lower()
    matched = {cat: [k for k in words if k in t] for cat, words in KEYWORDS.items()}
    best = max(scores, key=scores.get)
    return best, scores, matched
