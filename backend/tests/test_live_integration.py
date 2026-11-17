"""LIVE integration tests against the real services started with Docker Compose.

* live_chain : deploys a FRESH CTIValidation instance (compiled Hardhat artefact) on the running
               Hardhat node, registers three dedicated test accounts and drives it through the real
               Web3.py client (the demo contract and its reputations are not touched).
* live_misp  : creates / tags / searches / deletes an event on the real MISP instance via PyMISP.

They are skipped automatically when the services are not reachable:
    pytest -m "live_chain or live_misp"        (stack running: docker compose --profile misp up -d)
"""
from __future__ import annotations

import json
import os
import secrets
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RPC = os.environ.get("LIVE_ETH_RPC_URL", "http://127.0.0.1:8545")
ARTIFACT = ROOT / "blockchain" / "artifacts" / "contracts" / "CTIValidation.sol" / "CTIValidation.json"


def _env_file() -> dict:
    p = ROOT / ".env"
    if not p.exists():
        return {}
    return {line.split("=", 1)[0]: line.split("=", 1)[1] for line in p.read_text(encoding="utf-8").splitlines()
            if "=" in line and not line.lstrip().startswith("#")}


# ----------------------------------------------------------------------------- Ethereum
@pytest.fixture(scope="module")
def live_contract(tmp_path_factory):
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 5}))
    try:
        connected = w3.is_connected()
    except Exception:
        connected = False
    if not connected or not ARTIFACT.exists():
        pytest.skip("Hardhat node not reachable or contract artefact not compiled")
    art = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    owner, a, b, c = w3.eth.accounts[0], w3.eth.accounts[4], w3.eth.accounts[5], w3.eth.accounts[6]
    factory = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(factory.constructor(owner).transact({"from": owner}))
    contract = w3.eth.contract(address=receipt.contractAddress, abi=art["abi"])
    for addr, name in ((a, "Test A"), (b, "Test B"), (c, "Test C")):
        w3.eth.wait_for_transaction_receipt(contract.functions.registerOrganization(addr, name).transact({"from": owner}))
    deployment = {"address": receipt.contractAddress, "abi": art["abi"], "deploymentBlock": receipt.blockNumber,
                  "organizations": [{"code": "A", "address": a}, {"code": "B", "address": b}, {"code": "C", "address": c}]}
    path = tmp_path_factory.mktemp("live") / "deployment.json"
    path.write_text(json.dumps(deployment), encoding="utf-8")
    from app.blockchain.client import ChainClient

    return ChainClient(rpc_url=RPC, deployment_file=str(path))


def _orgs():
    from app.core.config import OrgConfig

    return {code: OrgConfig(code, f"Test {code}", "unused-key-unused-key", 0) for code in "ABC"}


@pytest.mark.live_chain
def test_live_contract_full_validation_flow(live_contract):
    from app.core.errors import ContractRevertError

    orgs = _orgs()
    digest = secrets.token_hex(32)
    assert live_contract.is_ready()
    rid, tx = live_contract.submit_report(orgs["A"], digest, "CTI-LIVE-1")
    assert tx.status == "success" and any(e["event"] == "ReportSubmitted" for e in tx.events)
    view = live_contract.get_report(rid)
    assert view["status"] == "PENDING" and view["eligible_validators"] == 2
    assert view["content_hash"] == "0x" + digest

    with pytest.raises(ContractRevertError) as exc:  # self-validation
        live_contract.vote(orgs["A"], rid, True)
    assert exc.value.details["contract_error"] == "SelfValidation"

    live_contract.vote(orgs["B"], rid, True)
    with pytest.raises(ContractRevertError) as exc:  # double vote
        live_contract.vote(orgs["B"], rid, True)
    assert exc.value.details["contract_error"] == "AlreadyVoted"
    with pytest.raises(ContractRevertError) as exc:  # premature finalisation
        live_contract.finalize(orgs["B"], rid)
    assert exc.value.details["contract_error"] == "FinalizationTooEarly"
    assert exc.value.details["args"][1:3] == [1, 2]

    live_contract.vote(orgs["C"], rid, True)
    assert live_contract.preview_finalization(rid) == (True, "VALIDATED")
    fin = live_contract.finalize(orgs["C"], rid)
    names = [e["event"] for e in fin.events]
    assert "ReportFinalized" in names and names.count("ReputationUpdated") == 3
    assert live_contract.get_report(rid)["status"] == "VALIDATED"
    a_addr = live_contract.address_for(orgs["A"])
    assert live_contract.get_reputation(a_addr) == 53.0
    assert live_contract.verify_integrity(rid, digest) is True
    assert live_contract.verify_integrity(rid, secrets.token_hex(32)) is False
    events = [e["event"] for e in live_contract.report_events(rid)]
    assert events[0] == "ReportSubmitted" and events.count("VoteCast") == 2


@pytest.mark.live_chain
def test_live_contract_duplicate_and_disputed(live_contract):
    from app.core.errors import ContractRevertError

    orgs = _orgs()
    digest = secrets.token_hex(32)
    rid, _ = live_contract.submit_report(orgs["B"], digest, "CTI-LIVE-2")
    with pytest.raises(ContractRevertError) as exc:
        live_contract.submit_report(orgs["C"], digest, "CTI-LIVE-3")
    assert exc.value.details["contract_error"] == "DuplicateReport"
    live_contract.vote(orgs["A"], rid, True)
    live_contract.vote(orgs["C"], rid, False)
    live_contract.finalize(orgs["A"], rid)
    assert live_contract.get_report(rid)["status"] == "DISPUTED"


# ----------------------------------------------------------------------------- MISP
@pytest.fixture(scope="module")
def live_misp():
    env = _env_file()
    url = os.environ.get("LIVE_MISP_URL", env.get("MISP_URL", "https://localhost:8443"))
    key = os.environ.get("LIVE_MISP_KEY", env.get("MISP_KEY", ""))
    if not key or key.startswith("change-me"):
        pytest.skip("No MISP key configured")
    from app.core.config import Settings
    from app.core.errors import MispError
    from app.misp.pymisp_adapter import PyMispAdapter

    settings = Settings(misp_url=url, misp_key=key, misp_verify_ssl=False, misp_timeout_s=20)
    adapter = PyMispAdapter(settings)
    try:
        adapter.health()
    except MispError:
        pytest.skip("MISP instance not reachable")
    return adapter


@pytest.mark.live_misp
def test_live_misp_event_lifecycle(live_misp):
    from app.misp.base import MispEventPayload

    marker = secrets.token_hex(4)
    payload = MispEventPayload(
        report_id=f"CTI-LIVE-{marker}", title="Live integration test event (synthetic)",
        description="Synthetic report used by the automated integration test suite.", submitter="Test org",
        tlp="TLP:GREEN", category="phishing", published_at=None, source="pytest",
        iocs=[{"type": "domain", "value": f"live-{marker}.example", "status": "valid", "confidence": 0.8, "flags": []},
              {"type": "ipv4", "value": "192.0.2.123", "status": "valid", "confidence": 0.8, "flags": []},
              {"type": "md5", "value": "zz-bad", "status": "malformed", "confidence": None, "flags": []}],
        mitre=[{"technique_id": "T1566.002", "name": "Spearphishing Link", "method": "rule", "confidence": 0.8}],
    )
    res = live_misp.push_report(payload)
    event_id = res["event_id"]
    try:
        assert res["attribute_count"] == 2  # malformed IOC not exported
        ev = live_misp.get_event(event_id)
        values = {a["value"] for a in ev["attributes"]}
        assert f"live-{marker}.example" in values and "192.0.2.123" in values
        assert all(a["to_ids"] is False for a in ev["attributes"])
        assert "tlp:green" in ev["tags"]
        assert any("Spearphishing Link - T1566.002" in t for t in ev["tags"])
        hits = live_misp.search_ioc(f"live-{marker}.example")
        assert any(h["event_id"] == event_id for h in hits)
        live_misp.add_tags(event_id, ['cti-platform:status="PENDING"'])
        live_misp.add_tags(event_id, ['cti-platform:status="VALIDATED"'])
        tags = live_misp.get_event(event_id)["tags"]
        assert 'cti-platform:status="VALIDATED"' in tags and 'cti-platform:status="PENDING"' not in tags
        assert any(e["id"] == event_id for e in live_misp.list_events(limit=100))
    finally:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            live_misp.client.delete_event(event_id)


@pytest.mark.live_misp
def test_live_misp_unknown_event_is_404(live_misp):
    from app.core.errors import NotFoundError

    with pytest.raises(NotFoundError):
        live_misp.get_event("987654321")
