from __future__ import annotations

import pytest

from oat.veip.contracts import AdmissionError, admit, derive_contract

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
    "counterexample_condition": "different decisions",
    "claim_ceiling": "classify only",
}


def test_contract_is_mechanically_derived_and_admits_valid_candidate():
    contract = derive_contract(ENTRY)
    candidate = {"inputs": {"authority": {}, "proposal": {}, "repetitions": 2}}
    assert admit(contract, candidate) == candidate
    assert contract.required_observables == ("decision_sequence",)


@pytest.mark.parametrize(
    "candidate",
    [
        None,
        {},
        {"inputs": {"authority": {}, "proposal": {}, "repetitions": 1}},
        {"inputs": {"authority": {}, "proposal": {}, "repetitions": 2, "extra": 1}},
    ],
)
def test_malformed_missing_and_unknown_inputs_are_unevaluable(candidate):
    with pytest.raises(AdmissionError):
        admit(derive_contract(ENTRY), candidate)
