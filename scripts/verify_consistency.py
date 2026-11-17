"""Independent consistency check: API / Streamlit values vs PostgreSQL vs Ethereum vs MISP.

Reads the last demonstration run (docs/test-reports/demo_scenario_run.json) and, for its validated report,
compares what the API returns (what the frontend displays) with:
  * PostgreSQL  - direct SQL through `docker compose exec postgres psql` (not the platform code);
  * Ethereum    - raw Web3 calls on the deployed contract (ABI copied from the hardhat container);
  * MISP        - MISP REST API (/events/view) with the admin key from .env.
Writes docs/test-reports/consistency_check.json. Read-only: nothing is modified.

Usage: python scripts/verify_consistency.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import warnings
from pathlib import Path

import requests
from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
STATUS = ["NONE", "PENDING", "VALIDATED", "REJECTED", "DISPUTED", "INCOMPLETE"]


def env() -> dict:
    return {ln.split("=", 1)[0]: ln.split("=", 1)[1] for ln in (ROOT / ".env").read_text(encoding="utf-8").splitlines()
            if "=" in ln and not ln.lstrip().startswith("#")}


def psql(sql: str) -> list[list[str]]:
    out = subprocess.run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "cti", "-d", "cti", "-At", "-F", "|",
                          "-c", sql], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [line.split("|") for line in out.strip().splitlines() if line]


def main() -> int:
    e = env()
    run = json.loads((ROOT / "docs" / "test-reports" / "demo_scenario_run.json").read_text(encoding="utf-8"))
    rid = run["report_ids"][0]
    api = e.get("API_URL", "http://127.0.0.1:8000").rstrip("/")
    h = {"X-API-Key": e["ORG_B_API_KEY"]}
    d = requests.get(f"{api}/api/v1/reports/{rid}", headers=h, timeout=60).json()
    score = requests.get(f"{api}/api/v1/reports/{rid}/score", headers=h, timeout=60).json()
    rep_a = requests.get(f"{api}/api/v1/organizations/org-a/reputation", headers=h, timeout=60).json()

    # --- PostgreSQL (direct SQL)
    row = psql(f"select status, content_hash, chain_report_id, misp_event_id from reports where id='{rid}'")[0]
    votes = psql(f"select o.code, v.approve from votes v join organizations o on o.id=v.org_id where v.report_id='{rid}' order by o.code")
    sc = psql(f"select score from score_snapshots where report_id='{rid}' order by id desc limit 1")[0][0]
    rep_db = psql("select reputation from organizations where id='org-a'")[0][0]

    # --- Ethereum (raw Web3 with the deployed ABI)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["docker", "compose", "cp", "hardhat:/deployments/localhost.json", f"{tmp}/d.json"], cwd=ROOT,
                       check=True, capture_output=True)
        dep = json.loads(Path(tmp, "d.json").read_text(encoding="utf-8"))
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    c = w3.eth.contract(address=dep["address"], abi=dep["abi"])
    r = c.functions.getReport(int(row[2])).call()
    a_addr = next(o["address"] for o in dep["organizations"] if o["code"] == "A")
    rep_chain = c.functions.getReputation(a_addr).call() / 100

    # --- MISP (REST)
    warnings.filterwarnings("ignore")
    ev = requests.get(f"{e['MISP_URL']}/events/view/{row[3]}", headers={"Authorization": e["MISP_KEY"],
                      "Accept": "application/json"}, verify=False, timeout=30).json()["Event"]
    misp_status = [t["name"] for t in ev.get("Tag", []) if t["name"].startswith("cti-platform:status=")]

    checks = [
        ("status API = PostgreSQL", d["status"], row[0]),
        ("status PostgreSQL = contrat", row[0], STATUS[r[8]]),
        ("SHA-256 API = PostgreSQL", d["blockchain"]["content_hash"], row[1]),
        ("SHA-256 PostgreSQL = contrat", row[1], bytes(r[0]).hex()),
        ("externalId contrat = rapport", r[1], rid),
        ("votes API = PostgreSQL", sorted((v["org"]["code"], v["approve"]) for v in d["votes_detail"]),
         sorted((code, flag == "t") for code, flag in votes)),
        ("approbations PostgreSQL = contrat", sum(1 for _, f in votes if f == "t"), r[6]),
        ("score API = dernier snapshot PostgreSQL", round(score["score"], 2), round(float(sc), 2)),
        ("réputation A API = PostgreSQL", round(rep_a["reputation"], 2), round(float(rep_db), 2)),
        ("réputation A on-chain (API) = contrat", (rep_a.get("onchain") or {}).get("reputation"), rep_chain),
        ("tag statut MISP = statut", misp_status, [f'cti-platform:status="{row[0]}"']),
        ("ancrage", d.get("chain_anchor"), "current"),
    ]
    results = [{"check": n, "platform": str(a), "reference": str(b), "ok": a == b} for n, a, b in checks]
    out = {"report_id": rid, "chain_report_id": int(row[2]), "misp_event_id": row[3], "checks": results,
           "all_ok": all(x["ok"] for x in results)}
    (ROOT / "docs" / "test-reports" / "consistency_check.json").write_text(json.dumps(out, indent=2, ensure_ascii=False),
                                                                          encoding="utf-8")
    for x in results:
        print(f"[{'OK' if x['ok'] else 'KO'}] {x['check']}: {x['platform']} | {x['reference']}")
    print("ALL CONSISTENT" if out["all_ok"] else "INCONSISTENCIES FOUND")
    return 0 if out["all_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
