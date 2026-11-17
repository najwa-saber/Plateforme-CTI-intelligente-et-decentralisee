"""Read-only audit of on-chain anchors: PostgreSQL rows vs the records actually stored in the running contract.

For every report with a chain_report_id it prints the PostgreSQL id, on-chain id, stored fingerprint, recorded chain
instance, status, then what the contract holds under that on-chain id (externalId, fingerprint, submitter) and the
verdict. It also checks the chain_transactions table (duplicate tx hashes, transactions of historical reports issued
on the current instance). Writes docs/test-reports/chain_anchor_audit.json. Nothing is modified.

Usage: python scripts/audit_chain_anchors.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
STATUS = ["NONE", "PENDING", "VALIDATED", "REJECTED", "DISPUTED", "INCOMPLETE"]


def psql(sql: str) -> list[list[str]]:
    out = subprocess.run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "cti", "-d", "cti", "-At", "-F", "|",
                          "-c", sql], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [line.split("|") for line in out.strip().splitlines() if line]


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["docker", "compose", "cp", "hardhat:/deployments/localhost.json", f"{tmp}/d.json"], cwd=ROOT,
                       check=True, capture_output=True)
        dep = json.loads(Path(tmp, "d.json").read_text(encoding="utf-8"))
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    contract = w3.eth.contract(address=dep["address"], abi=dep["abi"])
    instance = "0x" + bytes(w3.eth.get_block(int(dep["deploymentBlock"]))["hash"]).hex().removeprefix("0x")
    count = contract.functions.reportCount().call()
    orgs = {o["address"].lower(): o["code"] for o in dep["organizations"]}

    rows = psql("select r.id, r.chain_report_id, coalesce(r.content_hash,''), coalesce(r.chain_instance,''), r.status, "
                "o.code, coalesce(o.eth_address,''), r.submitted_at from reports r join organizations o "
                "on o.id = r.submitter_id where r.chain_report_id is not null order by r.submitted_at")
    reports = []
    for rid, cid, h, inst, status, code, addr, submitted in rows:
        cid = int(cid)
        rec = None
        if 1 <= cid <= count:
            r = contract.functions.getReport(cid).call()
            rec = {"external_id": r[1], "content_hash": bytes(r[0]).hex(), "submitter": orgs.get(r[2].lower(), r[2]),
                   "status": STATUS[r[8]]}
        if inst and inst != instance:
            verdict = "previous_instance (recorded instance differs)"
        elif rec is None:
            verdict = "previous_instance (id absent on current chain)"
        elif rec["external_id"] != rid:
            verdict = f"previous_instance (id now holds {rec['external_id']})"
        elif rec["content_hash"] != h:
            verdict = "INTEGRITY FAILURE (same report, different fingerprint)"
        else:
            verdict = "current - fingerprint, externalId and submitter match" if rec["submitter"] == code \
                else "SUBMITTER MISMATCH"
        reports.append({"report_id": rid, "chain_report_id": cid, "pg_fingerprint": h,
                        "pg_instance": inst or None, "pg_status": status, "pg_submitter": code,
                        "onchain_record_at_this_id": rec, "verdict": verdict})

    dup_tx = psql("select tx_hash, count(*) from chain_transactions group by tx_hash having count(*) > 1")
    historical = [r["report_id"] for r in reports if r["verdict"].startswith("previous_instance")]
    # a tx belongs to the current chain if the node knows it
    misattributed = []
    for txh, rid, action in psql("select tx_hash, coalesce(report_id,''), action from chain_transactions"):
        try:
            on_current = w3.eth.get_transaction(txh) is not None
        except Exception:
            on_current = False
        if on_current and rid in historical:
            misattributed.append({"tx": txh, "report_id": rid, "action": action})
    out = {"contract": dep["address"], "current_instance": instance, "onchain_report_count": count,
           "reports": reports, "duplicate_tx_hashes": dup_tx, "current_chain_tx_linked_to_historical_reports": misattributed,
           "ok": not dup_tx and not misattributed and all(not r["verdict"].startswith(("INTEGRITY", "SUBMITTER"))
                                                         for r in reports)}
    (ROOT / "docs" / "test-reports" / "chain_anchor_audit.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"contract {dep['address']}  instance {instance[:14]}…  on-chain reports: {count}")
    for r in reports:
        rec = r["onchain_record_at_this_id"] or {}
        print(f"{r['report_id']}  id={r['chain_report_id']}  pg_inst={(r['pg_instance'] or 'NULL')[:10]}  "
              f"pg_status={r['pg_status']:<9} chain[{r['chain_report_id']}]={rec.get('external_id')}  -> {r['verdict']}")
    print("duplicate tx hashes:", dup_tx, "| current-chain tx linked to historical reports:", misattributed)
    print("AUDIT OK" if out["ok"] else "AUDIT FOUND PROBLEMS")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
