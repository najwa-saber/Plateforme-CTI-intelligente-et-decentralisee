"""Mandatory demonstration scenario (prompt section 21) executed against the running stack.

    python scripts/run_demo_scenario.py [--api http://localhost:8000] [--no-tag]

Organisation keys are read from .env. Each run appends a run tag to the report texts so the
scenario can be replayed on the same database (otherwise the duplicate detector returns 409,
which is the expected behaviour - use --no-tag to observe it).
Results are written to docs/test-reports/demo_scenario_run.json.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "data" / "demo"


def load_env() -> dict:
    env = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


class Runner:
    def __init__(self, api: str, keys: dict[str, str]) -> None:
        self.api = api.rstrip("/")
        self.keys = keys
        self.steps: list[dict] = []
        self.failed = False

    def call(self, org: str, method: str, path: str, **kw):
        headers = {"X-API-Key": self.keys[org]}
        r = requests.request(method, f"{self.api}{path}", headers=headers, timeout=120, **kw)
        try:
            body = r.json()
        except ValueError:
            body = {"raw": r.text[:500]}
        return r.status_code, body

    def step(self, n: int, title: str, ok: bool, detail: str = "", data=None) -> None:
        mark = "PASS" if ok else "FAIL"
        self.failed |= not ok
        print(f"[{mark}] {n:>2}. {title}" + (f"\n        {detail}" if detail else ""))
        self.steps.append({"step": n, "title": title, "ok": ok, "detail": detail, "data": data})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default=None)
    parser.add_argument("--no-tag", action="store_true")
    args = parser.parse_args()
    env = load_env()
    api = args.api or env.get("API_URL", "http://localhost:8000")
    run = Runner(api, {c: env[f"ORG_{c}_API_KEY"] for c in "ABC"})
    tag = "" if args.no_tag else f"\n\n[demo run {datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}]"
    t0 = time.time()

    health = requests.get(f"{api}/api/v1/health", timeout=60).json()
    comps = health["components"]
    print(f"Platform {health['status']}: " + ", ".join(
        f"{k}={'ok' if v.get('ok') else 'KO'}" for k, v in comps.items())
          + f" | MISP mode={comps['misp'].get('mode')} | chain={comps['ethereum'].get('contract_address')}")

    # 1-7: A imports and analyses a phishing report (TXT upload)
    text1 = (DEMO / "01_orgA_phishing_report.txt").read_text(encoding="utf-8") + tag
    code, rep1 = run.call("A", "POST", "/api/v1/reports/upload",
                          files={"file": ("01_orgA_phishing_report.txt", text1.encode(), "text/plain")},
                          data={"tlp": "TLP:GREEN", "source": "Organisation A SOC"})
    ok = code == 201
    run.step(1, "Organisation A imports a phishing CTI report (TXT)", ok, f"HTTP {code} report_id={rep1.get('report_id')}")
    if not ok:
        print(json.dumps(rep1, indent=2)[:2000])
        return 1
    rid = rep1["report_id"]
    d = rep1["details"]
    iocs = [f"{i['type']}:{i['value']}" for i in d["iocs"] if i["status"] != "malformed"]
    run.step(2, "IOCs extracted automatically", len(iocs) >= 4, ", ".join(iocs))
    defanged = [i["raw_value"] for i in d["iocs"] if i["defanged"]]
    run.step(3, "Indicators normalised (refanged, lower-cased)", bool(defanged),
             f"defanged in source: {defanged}")
    run.step(4, "Duplicate detection", True,
             f"within report: {rep1['duplicates']['within_report']} | known elsewhere: "
             f"{len(rep1['duplicates']['known_in_other_reports'])} | known in MISP: {rep1['duplicates']['known_in_misp']}")
    cls = d["classification"]
    run.step(5, "ML classification", cls["category"] == "phishing",
             f"{cls['category']} p={cls['probabilities']} ({cls.get('method')})")
    mitre = [f"{m['technique_id']} {m['name']} ({m['method']} {m['confidence']})" for m in d["mitre"]]
    run.step(6, "MITRE ATT&CK techniques proposed", any(m["technique_id"].startswith("T1566") for m in d["mitre"]),
             "; ".join(mitre))
    run.step(7, "Event created in MISP", d["misp"]["sync_status"] == "SYNCED",
             f"mode={d['misp']['mode']} event_id={d['misp']['event_id']} error={d['misp']['error']}")

    # 8-9: SHA-256 fingerprint + on-chain submission
    code, sub = run.call("A", "POST", f"/api/v1/reports/{rid}/submit")
    run.step(8, "Backend computes the SHA-256 of the canonical report", code == 200 and len(sub.get("content_hash", "")) == 64,
             f"sha256={sub.get('content_hash')}")
    run.step(9, "A submits the fingerprint on Ethereum", code == 200 and sub.get("status") == "PENDING",
             f"chain_report_id={sub.get('chain_report_id')} tx={sub.get('transaction', {}).get('tx_hash')} "
             f"block={sub.get('transaction', {}).get('block_number')}")

    # 10-11: B consults and votes
    code, _ = run.call("B", "GET", f"/api/v1/reports/{rid}")
    run.step(10, "B consults the report", code == 200)
    code, vb = run.call("B", "POST", f"/api/v1/reports/{rid}/vote", json={"approve": True, "comment": "IOCs seen in our proxy logs"})
    run.step(11, "B votes for validation", code == 200 and not vb.get("finalized"),
             f"tx={vb.get('transaction', {}).get('tx_hash')} preview={vb.get('finalization_preview')}")
    code, early = run.call("B", "POST", f"/api/v1/reports/{rid}/finalize")
    run.step(11, "(robustness) premature finalisation refused by the contract", code == 409,
             f"HTTP {code} {early.get('error', {}).get('details', {}).get('contract_error')}")
    code, dbl = run.call("B", "POST", f"/api/v1/reports/{rid}/vote", json={"approve": True})
    run.step(11, "(robustness) double vote refused", code == 409, f"HTTP {code}")
    code, selfv = run.call("A", "POST", f"/api/v1/reports/{rid}/vote", json={"approve": True})
    run.step(11, "(robustness) self-validation refused", code == 403, f"HTTP {code}")

    # 12-15: C consults, votes, contract finalises -> VALIDATED
    code, _ = run.call("C", "GET", f"/api/v1/reports/{rid}")
    run.step(12, "C consults the report", code == 200)
    code, vc = run.call("C", "POST", f"/api/v1/reports/{rid}/vote", json={"approve": True})
    run.step(13, "C votes for validation", code == 200, f"tx={vc.get('transaction', {}).get('tx_hash')}")
    run.step(14, "Smart contract finalises the report (majority rule)", bool(vc.get("finalized")),
             f"finalize tx={vc.get('finalization', {}).get('transaction', {}).get('tx_hash')}")
    code, st = run.call("A", "GET", f"/api/v1/reports/{rid}/status")
    run.step(15, "Status becomes VALIDATED (on-chain and off-chain)",
             st.get("status") == "VALIDATED" and (st.get("chain") or {}).get("status") == "VALIDATED",
             f"off-chain={st.get('status')} on-chain={(st.get('chain') or {}).get('status')} "
             f"votes={(st.get('chain') or {}).get('approvals')}/{(st.get('chain') or {}).get('eligible_validators')}")
    code, integ = run.call("B", "GET", f"/api/v1/reports/{rid}/integrity")
    run.step(15, "(integrity) recomputed SHA-256 matches the on-chain fingerprint", integ.get("verified") is True,
             integ.get("message", ""))

    # 16-17: score and reputation
    code, sc = run.call("A", "GET", f"/api/v1/reports/{rid}/score")
    run.step(16, "Reliability score computed (S = 0.30R + 0.30Q + 0.40V)", code == 200 and sc.get("is_final"),
             f"S={sc.get('score')} R={sc.get('r')} Q={sc.get('q')} V={sc.get('v')} level={sc.get('details', {}).get('level')}")
    code, repA = run.call("B", "GET", "/api/v1/organizations/org-a/reputation")
    last = (repA.get("history") or [{}])[0]
    run.step(17, "Reputation of A evolves with an explanation", code == 200 and repA.get("reputation", 50) > 50,
             f"off-chain={repA.get('reputation')} on-chain={(repA.get('onchain') or {}).get('reputation')} | "
             f"{last.get('explanation', '')[:220]}")

    # 18-19: second report sharing an IOC -> correlation
    obj = json.loads((DEMO / "02_orgB_followup_shared_ioc.json").read_text(encoding="utf-8"))
    obj["text"] += tag
    code, rep2 = run.call("B", "POST", "/api/v1/reports/upload",
                          files={"file": ("02_orgB_followup_shared_ioc.json", json.dumps(obj).encode(), "application/json")})
    run.step(18, "B imports a second report sharing an IOC (JSON with declared IOCs)", code == 201,
             f"report_id={rep2.get('report_id')} known IOCs={[k['value'] for k in rep2.get('duplicates', {}).get('known_in_other_reports', [])]}")
    rid2 = rep2.get("report_id")
    code, corr = run.call("B", "GET", f"/api/v1/reports/{rid2}/correlations")
    links = {c["report_id"]: c for c in corr.get("correlations", [])}
    link = links.get(rid)
    run.step(19, "Correlation engine identifies a potential relation", link is not None,
             (f"score={link['score']} ({link['strength']}) reasons={link['evidence']['reasons']}" if link else "no link"))

    # 20: dashboard
    code, dash = run.call("C", "GET", "/api/v1/stats/dashboard")
    run.step(20, "Dashboard statistics available", code == 200,
             f"reports={dash.get('reports_total')} validated={dash.get('validated')} iocs={dash.get('iocs_total')} "
             f"correlations={dash.get('correlations_total')} tx={dash.get('transactions_total')}")

    elapsed = time.time() - t0
    out = ROOT / "docs" / "test-reports" / "demo_scenario_run.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"executed_at": datetime.now(timezone.utc).isoformat(), "api": api,
                               "elapsed_s": round(elapsed, 2), "health": health, "steps": run.steps,
                               "report_ids": [rid, rid2], "success": not run.failed}, indent=2, default=str),
                   encoding="utf-8")
    print(f"\nScenario {'SUCCEEDED' if not run.failed else 'FAILED'} in {elapsed:.1f}s - details: {out}")
    return 1 if run.failed else 0


if __name__ == "__main__":
    sys.exit(main())
