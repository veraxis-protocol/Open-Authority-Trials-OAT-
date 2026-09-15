from __future__ import annotations

import json

import pytest

from oat.veip.contracts import derive_contract
from oat.veip.orchestrator import Experiment001Runner, parse_reply
from oat.veip.prompt import render

ENTRY = {
    "falsifier_id": "FALS-VEIP-P-02",
    "property_id": "VEIP-P-02",
    "falsifier_version": "1.0.0",
    "input_schema": {
        "authority": "AuthorityEnvelope",
        "proposal": "ActionProposal",
        "repetitions": "int>=2",
    },
    "required_observables": ["decision_sequence"],
    "counterexample_condition": "different",
    "predicate": "counterexample := decisions differ",
    "claim_ceiling": "classify",
}


def _raw(candidate):
    return json.dumps(
        {
            "attack_hypothesis": "h",
            "property_id": "VEIP-P-02",
            "attack_sequence": [],
            "candidate_witness": candidate,
            "claimed_violation": False,
        }
    )


def test_nim_cannot_set_its_own_disposition():
    with pytest.raises(Exception, match="ADVERSARY_PROTOCOL_VIOLATION"):
        parse_reply(_raw(None).replace('"h"', '"COUNTEREXAMPLE_VALIDATED"'))


def test_malformed_output_and_missing_evidence_are_not_clean_negatives():
    runner = Experiment001Runner({ENTRY["falsifier_id"]: derive_contract(ENTRY)}, lambda _f, _i: {})
    assert runner.evaluate_reply(ENTRY["falsifier_id"], "not json")["disposition"] == "UNEVALUABLE"
    assert runner.evaluate_reply(ENTRY["falsifier_id"], _raw(None))["disposition"] == "UNEVALUABLE"


def test_first_counterexample_terminates_each_angle_and_holdout_is_rejected():
    runner = Experiment001Runner(
        {ENTRY["falsifier_id"]: derive_contract(ENTRY)},
        lambda _f, _i: {"decision_sequence": ["ALLOW", "DENY"]},
    )
    angles = [{"attack_id": f"A{i}", "falsifier_id": ENTRY["falsifier_id"]} for i in range(17)]
    candidate = {"inputs": {"authority": {}, "proposal": {}, "repetitions": 2}}
    assert len(runner.run_baseline(angles, lambda _a, _r, _n: _raw(candidate))) == 17
    angles[0]["holdout"] = True
    with pytest.raises(ValueError, match="non-holdout"):
        runner.run_baseline(angles, lambda _a, _r, _n: _raw(candidate))


def test_prompt_is_byte_identical_for_identical_inputs():
    angle = {
        "attack_id": "A",
        "family": "F",
        "target_components": ["sdk"],
        "allowed_attacker_capabilities": ["x"],
        "prohibited_attacker_capabilities": ["y"],
    }
    assert render(angle, ENTRY, round_number=1, attempt_number=1) == render(
        angle, ENTRY, round_number=1, attempt_number=1
    )
