from __future__ import annotations

from veip_sdk.authorize import classify
from veip_sdk.evidence import generate_evidence
from veip_sdk.veip_types import ActionProposal, AuthorityEnvelope

from oat.veip.falsifiers import EVALUATORS, evaluate
from oat.veip.subject import invoke


def _objects():
    authority = {"scope_id": "s", "issuer": "i", "permitted_actions": ["read"], "valid": True}
    proposal = {"action_type": "read", "payload": {"x": 1}}
    a = AuthorityEnvelope(**authority)
    p = ActionProposal(**proposal)
    pack = generate_evidence(a, p, classify(a, p))
    return authority, proposal, pack


def test_all_thirteen_ready_falsifiers_have_subject_invocations():
    authority, proposal, pack = _objects()
    cases = {
        "FALS-VEIP-P-02": {"authority": authority, "proposal": proposal, "repetitions": 2},
        "FALS-VEIP-P-03": {"classifications": "ALLOW", "transition_table": {}},
        "FALS-VEIP-P-05": {"authority": authority, "proposal": proposal, "evidence_pack": pack},
        "FALS-VEIP-P-09": {"authority": authority, "proposal": proposal},
        "FALS-VEIP-P-11": {"evidence_pack": pack},
        "FALS-VEIP-P-12A": {
            "authority": authority,
            "proposal": proposal,
            "decision": "ALLOW",
            "repetitions": 2,
        },
        "FALS-VEIP-P-14": {
            "pack.schema_version": "0.1.0",
            "pinned_sha256": "x",
            "schema_file": "x",
        },
        "FALS-VEIP-P-17": {"current_state": "UNKNOWN", "next_state": "EXECUTED"},
        "FALS-VEIP-P-18": {"evidence_pack": pack, "proposal": proposal},
        "FALS-VEIP-P-19": {"evidence_pack": pack},
        "FALS-VEIP-P-20": {"http_request": {"body": pack}},
        "FALS-VEIP-P-01S": {"transition_table": {}},
        "FALS-VEIP-P-07S": {"transition_table": {}},
    }
    assert set(cases) == set(EVALUATORS)
    for fid, inputs in cases.items():
        assert evaluate(fid, invoke(fid, inputs))["disposition"] != "UNEVALUABLE"
