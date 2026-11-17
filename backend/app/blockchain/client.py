"""Web3.py client for the CTIValidation smart contract (local Hardhat network).

* Contract address + ABI are read from the deployment file written by
  ``blockchain/scripts/deploy.js``.
* Organisation accounts: if ORG_X_PRIVATE_KEY is set the transaction is signed locally,
  otherwise the account unlocked by the Hardhat node (by index) is used. No key is
  ever hard-coded.
* Every transaction is first simulated with ``eth_call`` so that business-rule reverts
  (custom Solidity errors) are decoded and returned as explicit 409 errors.
"""
from __future__ import annotations

import json
import logging
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eth_abi import decode as abi_decode
from eth_utils import keccak, to_checksum_address
from web3 import Web3
from web3.exceptions import ContractCustomError, ContractLogicError, Web3Exception
from web3.logs import DISCARD

from app.core.config import OrgConfig, get_settings
from app.core.errors import BlockchainError, ContractRevertError

logger = logging.getLogger("cti.chain")

STATUS_NAMES = ["NONE", "PENDING", "VALIDATED", "REJECTED", "DISPUTED", "INCOMPLETE"]
REVERT_MESSAGES = {
    "NotRegistered": "Account is not a registered organisation",
    "OrganizationInactive": "Organisation is deactivated",
    "EmptyHash": "Empty fingerprint",
    "InvalidExternalId": "Invalid external report identifier",
    "DuplicateReport": "This fingerprint was already submitted on-chain",
    "NoEligibleValidators": "No eligible validator for this report",
    "ReportNotFound": "Unknown on-chain report",
    "NotPending": "Report is not pending (already finalised)",
    "SelfValidation": "The submitter cannot validate its own report",
    "NotEligible": "Organisation is not an eligible validator for this report",
    "AlreadyVoted": "This organisation has already voted on this report",
    "VotingClosed": "Voting deadline has passed",
    "FinalizationTooEarly": "Votes are incomplete: finalisation is not yet possible",
    "Unauthorized": "Account not allowed to finalise",
    "EnforcedPause": "Contract is paused",
}


@dataclass
class TxResult:
    tx_hash: str
    block_number: int
    gas_used: int
    status: str
    events: list[dict]

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


class ChainClient:
    def __init__(self, rpc_url: str | None = None, deployment_file: str | None = None) -> None:
        settings = get_settings()
        self.rpc_url = rpc_url or settings.eth_rpc_url
        self.deployment_file = Path(deployment_file or settings.eth_deployment_file)
        self.timeout = settings.eth_tx_timeout_s
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 10}))
        self.deployment: dict | None = None
        self.contract = None
        self._errors: dict[str, tuple[str, list[str]]] = {}
        self._lock = threading.Lock()  # serialise nonces of locally-signed transactions
        self._deployment_mtime: float | None = None
        self._instance: str | None = None

    # ------------------------------------------------------------------ setup
    def _load(self) -> None:
        # The deployment file is rewritten when the Hardhat container restarts: reload it when it changes.
        if self.contract is not None and self.deployment_file.exists()                 and self.deployment_file.stat().st_mtime == self._deployment_mtime:
            return
        self.contract, self._instance = None, None
        if not self.deployment_file.exists():
            raise BlockchainError("Smart contract deployment file not found (is the Hardhat service deployed?)",
                                  {"file": self.deployment_file.name})
        self._deployment_mtime = self.deployment_file.stat().st_mtime
        self.deployment = json.loads(self.deployment_file.read_text(encoding="utf-8"))
        abi = self.deployment["abi"]
        self.contract = self.w3.eth.contract(address=to_checksum_address(self.deployment["address"]), abi=abi)
        for item in abi:
            if item.get("type") == "error":
                types = [i["type"] for i in item.get("inputs", [])]
                selector = "0x" + keccak(text=f"{item['name']}({','.join(types)})")[:4].hex()
                self._errors[selector] = (item["name"], types)
        # OpenZeppelin errors inherited (already in ABI) + Pausable
        for sig in ("EnforcedPause()", "ExpectedPause()", "OwnableUnauthorizedAccount(address)"):
            name = sig.split("(")[0]
            types = [t for t in sig[sig.index("(") + 1:-1].split(",") if t]
            self._errors.setdefault("0x" + keccak(text=sig)[:4].hex(), (name, types))

    def reset(self) -> None:
        self.contract = None
        self.deployment = None
        self._instance = None

    def instance_id(self) -> str:
        """Identity of the running chain + contract deployment: hash of the deployment block.

        The local Hardhat network is in-memory and the contract is redeployed at the SAME
        (deterministic) address after a restart; the deployment block hash differs because it
        includes the block timestamp. Reports store this value at submission time so that an
        anchor on a previous chain instance is detected instead of being silently misread.
        """
        self._load()
        if self._instance is None:
            assert self.deployment is not None
            try:
                block = self.w3.eth.get_block(int(self.deployment.get("deploymentBlock") or 0))
            except (Web3Exception, ConnectionError, OSError, ValueError) as exc:
                raise BlockchainError("Ethereum node unreachable") from exc
            self._instance = "0x" + bytes(block["hash"]).hex().removeprefix("0x")
        return self._instance

    def health(self) -> dict:
        info: dict[str, Any] = {"rpc_url": self.rpc_url, "connected": False}
        try:
            info["connected"] = self.w3.is_connected()
            if not info["connected"]:
                return info
            info["chain_id"] = self.w3.eth.chain_id
            info["block_number"] = self.w3.eth.block_number
            self.reset()
            self._load()
            assert self.deployment is not None
            code = self.w3.eth.get_code(self.contract.address)
            info.update({
                "contract_address": self.contract.address,
                "contract_deployed": len(code) > 0,
                "deployment_block": self.deployment.get("deploymentBlock"),
                "voting_period_s": self.contract.functions.votingPeriod().call() if len(code) else None,
                "report_count": self.contract.functions.reportCount().call() if len(code) else None,
                "chain_instance": self.instance_id() if len(code) else None,
            })
            if not len(code):
                info["warning"] = "No contract code at the deployed address: the Hardhat node was restarted. " \
                                  "Redeploy (docker compose restart hardhat) and reset the database."
        except BlockchainError as exc:
            info["error"] = exc.message
        except Exception as exc:  # network errors
            info["error"] = f"{type(exc).__name__}"
        return info

    def is_ready(self) -> bool:
        h = self.health()
        return bool(h.get("connected") and h.get("contract_deployed"))

    # ------------------------------------------------------------------ accounts
    def address_for(self, org: OrgConfig) -> str:
        self._load()
        if org.private_key:
            return self.w3.eth.account.from_key(org.private_key).address
        assert self.deployment is not None
        for item in self.deployment.get("organizations", []):
            if item.get("code") == org.code:
                return to_checksum_address(item["address"])
        try:
            return to_checksum_address(self.w3.eth.accounts[org.account_index])
        except (IndexError, Web3Exception) as exc:
            raise BlockchainError(f"No Ethereum account for organisation {org.code}") from exc

    # ------------------------------------------------------------------ errors
    def _decode_revert(self, exc: Exception) -> ContractRevertError | BlockchainError:
        data = getattr(exc, "data", None)
        if isinstance(data, dict):
            data = data.get("data")
        if not isinstance(data, str) or not data.startswith("0x"):
            m = re.search(r"0x[0-9a-fA-F]{8,}", " ".join(str(a) for a in getattr(exc, "args", ())) or str(exc))
            data = m.group(0) if m else None
        if data and len(data) >= 10:
            selector = data[:10].lower()
            if selector in self._errors:
                name, types = self._errors[selector]
                args: list = []
                if types:
                    try:
                        args = [_jsonable(a) for a in abi_decode(types, bytes.fromhex(data[10:]))]
                    except Exception:  # pragma: no cover - malformed revert payload
                        args = []
                return ContractRevertError(REVERT_MESSAGES.get(name, name), {"contract_error": name, "args": args})
        if isinstance(exc, ContractLogicError):
            return ContractRevertError("Transaction rejected by the smart contract", {"reason": str(exc)[:200]})
        return BlockchainError("Ethereum node error", {"reason": type(exc).__name__})

    # ------------------------------------------------------------------ transactions
    def _send(self, org: OrgConfig, fn) -> TxResult:
        self._load()
        sender = self.address_for(org)
        try:
            fn.call({"from": sender})  # simulation: decode business reverts before spending gas
        except (ContractCustomError, ContractLogicError) as exc:
            raise self._decode_revert(exc) from exc
        except Web3Exception as exc:
            raise self._decode_revert(exc) from exc
        except (ConnectionError, OSError) as exc:
            raise BlockchainError("Ethereum node unreachable") from exc
        try:
            with self._lock:
                if org.private_key:
                    tx = fn.build_transaction({"from": sender, "nonce": self.w3.eth.get_transaction_count(sender),
                                               "chainId": self.w3.eth.chain_id})
                    signed = self.w3.eth.account.sign_transaction(tx, org.private_key)
                    tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
                else:
                    tx_hash = fn.transact({"from": sender})
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=self.timeout)
        except (ContractCustomError, ContractLogicError) as exc:
            raise self._decode_revert(exc) from exc
        except Web3Exception as exc:
            raise BlockchainError("Ethereum transaction failed", {"reason": type(exc).__name__}) from exc
        except (ConnectionError, OSError) as exc:
            raise BlockchainError("Ethereum node unreachable") from exc
        events = self._decode_events(receipt)
        result = TxResult(tx_hash="0x" + bytes(receipt["transactionHash"]).hex().removeprefix("0x"),
                          block_number=receipt["blockNumber"], gas_used=receipt["gasUsed"],
                          status="success" if receipt["status"] == 1 else "failed", events=events)
        if result.status != "success":
            raise BlockchainError("Transaction reverted on-chain", {"tx_hash": result.tx_hash})
        return result

    def _decode_events(self, receipt) -> list[dict]:
        out = []
        for ev_abi in [e for e in self.contract.abi if e.get("type") == "event"]:
            event = getattr(self.contract.events, ev_abi["name"])()
            for log in event.process_receipt(receipt, errors=DISCARD):
                out.append({"event": log["event"], "args": _jsonable(dict(log["args"])),
                            "log_index": log["logIndex"]})
        return sorted(out, key=lambda e: e["log_index"])

    @staticmethod
    def hash_to_bytes32(hex_hash: str) -> bytes:
        h = hex_hash.lower().removeprefix("0x")
        if len(h) != 64:
            raise ValueError("SHA-256 fingerprint must be 32 bytes")
        return bytes.fromhex(h)

    def submit_report(self, org: OrgConfig, content_hash: str, external_id: str) -> tuple[int, TxResult]:
        self._load()
        fn = self.contract.functions.submitReport(self.hash_to_bytes32(content_hash), external_id)
        res = self._send(org, fn)
        submitted = next((e for e in res.events if e["event"] == "ReportSubmitted"), None)
        if not submitted:
            raise BlockchainError("ReportSubmitted event missing from receipt")
        return int(submitted["args"]["reportId"]), res

    def vote(self, org: OrgConfig, chain_report_id: int, approve: bool) -> TxResult:
        self._load()
        return self._send(org, self.contract.functions.voteReport(chain_report_id, approve))

    def finalize(self, org: OrgConfig, chain_report_id: int) -> TxResult:
        self._load()
        return self._send(org, self.contract.functions.finalizeReport(chain_report_id))

    # ------------------------------------------------------------------ views
    def _call(self, fn):
        try:
            return fn.call()
        except (ContractCustomError, ContractLogicError, Web3Exception) as exc:
            raise self._decode_revert(exc) from exc
        except (ConnectionError, OSError) as exc:
            raise BlockchainError("Ethereum node unreachable") from exc

    def preview_finalization(self, chain_report_id: int) -> tuple[bool, str]:
        self._load()
        can, outcome = self._call(self.contract.functions.previewFinalization(chain_report_id))
        return bool(can), STATUS_NAMES[outcome]

    def get_report(self, chain_report_id: int) -> dict:
        self._load()
        r = self._call(self.contract.functions.getReport(chain_report_id))
        return {
            "chain_report_id": chain_report_id,
            "content_hash": "0x" + bytes(r[0]).hex(),
            "external_id": r[1],
            "submitter": r[2],
            "submitted_at": r[3],
            "deadline": r[4],
            "eligible_validators": r[5],
            "approvals": r[6],
            "rejections": r[7],
            "status": STATUS_NAMES[r[8]],
            "finalized_at": r[9] or None,
            "threshold": r[5] // 2 + 1,
        }

    def get_eligible_validators(self, chain_report_id: int) -> list[str]:
        self._load()
        return list(self._call(self.contract.functions.getEligibleValidators(chain_report_id)))

    def get_vote(self, chain_report_id: int, address: str) -> str:
        self._load()
        v = self._call(self.contract.functions.votes(chain_report_id, to_checksum_address(address)))
        return ["NONE", "APPROVE", "REJECT"][v]

    def get_reputation(self, address: str) -> float:
        self._load()
        return self._call(self.contract.functions.getReputation(to_checksum_address(address))) / 100.0

    def get_organization(self, address: str) -> dict:
        self._load()
        o = self._call(self.contract.functions.organizations(to_checksum_address(address)))
        return {"name": o[0], "registered": o[1], "active": o[2], "reputation": o[3] / 100.0,
                "reports_submitted": o[4], "votes_cast": o[5], "registered_at": o[6]}

    def verify_integrity(self, chain_report_id: int, content_hash: str) -> bool:
        self._load()
        return bool(self._call(self.contract.functions.verifyIntegrity(chain_report_id,
                                                                       self.hash_to_bytes32(content_hash))))

    def report_events(self, chain_report_id: int) -> list[dict]:
        """On-chain audit trail of one report (submission, votes, finalisation, reputation)."""
        self._load()
        assert self.deployment is not None
        start = int(self.deployment.get("deploymentBlock") or 0)
        out: list[dict] = []
        for name in ("ReportSubmitted", "VoteCast", "ReportFinalized", "ReputationUpdated"):
            event = getattr(self.contract.events, name)
            try:
                logs = event.get_logs(from_block=start, argument_filters={"reportId": chain_report_id})
            except Web3Exception as exc:
                raise BlockchainError("Unable to read contract events", {"reason": type(exc).__name__}) from exc
            for log in logs:
                out.append({"event": name, "block_number": log["blockNumber"],
                            "tx_hash": "0x" + bytes(log["transactionHash"]).hex().removeprefix("0x"),
                            "args": _jsonable(dict(log["args"]))})
        return sorted(out, key=lambda e: e["block_number"])


_client: ChainClient | None = None


def get_chain_client() -> ChainClient:
    global _client
    if _client is None:
        _client = ChainClient()
    return _client


def set_chain_client(client) -> None:
    """Dependency injection for tests."""
    global _client
    _client = client
