"""In-memory test double of the CTIValidation contract (same rules as the Solidity code).

Used ONLY by the Python unit/API tests so that they run without an Ethereum node.
The real contract is tested with Hardhat (blockchain/test) and through the real
Web3 client in tests/test_chain_integration.py.
"""
from __future__ import annotations

import time

from app.blockchain.client import STATUS_NAMES, TxResult
from app.core.errors import BlockchainError, ContractRevertError


class FakeChain:
    def __init__(self, voting_period: int = 7 * 24 * 3600) -> None:
        self.addresses = {"A": "0x" + "a" * 40, "B": "0x" + "b" * 40, "C": "0x" + "c" * 40}
        self.reputation = {a: 5000 for a in self.addresses.values()}
        self.reports: dict[int, dict] = {}
        self.by_hash: dict[str, int] = {}
        self.votes: dict[tuple[int, str], bool] = {}
        self.voting_period = voting_period
        self.block = 1
        self.contract = None
        self.down = False
        self.now_offset = 0
        self.instance = "0x" + "01" * 32
        self.restart_during_submit = False

    def instance_id(self) -> str:
        self._check()
        return self.instance

    def simulate_restart(self) -> None:
        """Same contract address, empty state, new deployment block hash (like a Hardhat restart)."""
        self.reports.clear()
        self.by_hash.clear()
        self.votes.clear()
        self.reputation = {a: 5000 for a in self.addresses.values()}
        self.instance = "0x" + "02" * 32

    # -- helpers
    def _now(self) -> int:
        return int(time.time()) + self.now_offset

    def _tx(self, events: list[dict]) -> TxResult:
        if self.down:
            raise BlockchainError("Ethereum node unreachable")
        self.block += 1
        return TxResult(tx_hash="0x" + f"{self.block:064x}", block_number=self.block, gas_used=50_000,
                        status="success", events=events)

    def _revert(self, name: str, msg: str):
        raise ContractRevertError(msg, {"contract_error": name, "args": []})

    def _check(self):
        if self.down:
            raise BlockchainError("Ethereum node unreachable")

    # -- interface used by the services
    def health(self) -> dict:
        return {"connected": not self.down, "contract_deployed": not self.down, "chain_id": 31337,
                "contract_address": "0xFAKE", "report_count": len(self.reports)}

    def is_ready(self) -> bool:
        return not self.down

    def address_for(self, org) -> str:
        return self.addresses[org.code]

    def submit_report(self, org, content_hash: str, external_id: str):
        self._check()
        sender = self.address_for(org)
        if content_hash in self.by_hash:
            self._revert("DuplicateReport", "This fingerprint was already submitted on-chain")
        rid = len(self.reports) + 1
        eligible = [a for a in self.addresses.values() if a != sender]
        self.reports[rid] = {"hash": content_hash, "submitter": sender, "eligible": eligible, "approvals": 0,
                             "rejections": 0, "status": 1, "deadline": self._now() + self.voting_period,
                             "external_id": external_id}
        self.by_hash[content_hash] = rid
        if self.restart_during_submit:  # the node restarts right after mining the submission
            self.restart_during_submit = False
            self.instance = "0x" + "03" * 32
        return rid, self._tx([{"event": "ReportSubmitted", "args": {"reportId": rid}}])

    def vote(self, org, rid: int, approve: bool) -> TxResult:
        self._check()
        sender = self.address_for(org)
        r = self.reports.get(rid) or self._revert("ReportNotFound", "Unknown on-chain report")
        if r["status"] != 1:
            self._revert("NotPending", "Report is not pending (already finalised)")
        if sender == r["submitter"]:
            self._revert("SelfValidation", "The submitter cannot validate its own report")
        if sender not in r["eligible"]:
            self._revert("NotEligible", "Organisation is not an eligible validator for this report")
        if (rid, sender) in self.votes:
            self._revert("AlreadyVoted", "This organisation has already voted on this report")
        if self._now() > r["deadline"]:
            self._revert("VotingClosed", "Voting deadline has passed")
        self.votes[(rid, sender)] = approve
        r["approvals" if approve else "rejections"] += 1
        return self._tx([{"event": "VoteCast", "args": {"reportId": rid, "approve": approve}}])

    def preview_finalization(self, rid: int):
        r = self.reports[rid]
        if r["status"] != 1:
            return False, STATUS_NAMES[r["status"]]
        n = len(r["eligible"])
        threshold = n // 2 + 1
        if r["approvals"] >= threshold:
            return True, "VALIDATED"
        if r["rejections"] >= threshold:
            return True, "REJECTED"
        if r["approvals"] + r["rejections"] == n:
            return True, "DISPUTED"
        if self._now() > r["deadline"]:
            return True, "INCOMPLETE"
        return False, "PENDING"

    def finalize(self, org, rid: int) -> TxResult:
        self._check()
        r = self.reports[rid]
        if r["status"] != 1:
            self._revert("NotPending", "Report is not pending (already finalised)")
        can, outcome = self.preview_finalization(rid)
        if not can:
            self._revert("FinalizationTooEarly", "Votes are incomplete: finalisation is not yet possible")
        r["status"] = STATUS_NAMES.index(outcome)
        deltas = {"VALIDATED": 300, "REJECTED": -500}
        if outcome in deltas:
            self.reputation[r["submitter"]] = max(1000, min(9000, self.reputation[r["submitter"]] + deltas[outcome]))
        return self._tx([{"event": "ReportFinalized", "args": {"reportId": rid, "status": outcome}}])

    def get_report(self, rid: int) -> dict:
        self._check()
        if rid not in self.reports:
            self._revert("ReportNotFound", "Unknown on-chain report")
        r = self.reports[rid]
        return {"chain_report_id": rid, "content_hash": "0x" + r["hash"], "external_id": r["external_id"],
                "submitter": r["submitter"], "eligible_validators": len(r["eligible"]), "approvals": r["approvals"],
                "rejections": r["rejections"], "status": STATUS_NAMES[r["status"]], "deadline": r["deadline"],
                "threshold": len(r["eligible"]) // 2 + 1}

    def get_eligible_validators(self, rid: int) -> list[str]:
        return list(self.reports[rid]["eligible"])

    def get_reputation(self, address: str) -> float:
        return self.reputation[address] / 100

    def get_organization(self, address: str) -> dict:
        return {"registered": True, "active": True, "reputation": self.reputation[address] / 100}

    def verify_integrity(self, rid: int, content_hash: str) -> bool:
        self._check()
        return self.reports[rid]["hash"] == content_hash.lower().removeprefix("0x")

    def report_events(self, rid: int) -> list[dict]:
        return [{"event": "ReportSubmitted", "args": {"reportId": rid}}]
