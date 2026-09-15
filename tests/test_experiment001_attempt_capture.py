from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from oat.veip.contracts import WitnessContract
from oat.veip.execution_path import BudgetLedger
from oat.veip.experiment001 import (
    AttemptEvidenceRecorder,
    AttemptMetadata,
    capture_and_evaluate_attempt,
    render_provider_request,
)


def _contract() -> WitnessContract:
    return WitnessContract(
        falsifier_id="FALS-VEIP-P-02",
        property_id="VEIP-P-02",
        falsifier_version="TEST",
        input_schema={"probe": "object"},
        candidate_witness_schema={
            "type": "object",
            "required": ["inputs"],
            "additionalProperties": False,
            "properties": {
                "inputs": {
                    "type": "object",
                }
            },
        },
        required_observables=("decision_sequence",),
        canonicalization_rule="test",
        missing_field_behavior="UNEVALUABLE",
        unknown_field_behavior="UNEVALUABLE",
        type_validation="test",
        unevaluable_conditions=(),
        negative_condition="test",
        counterexample_condition="test",
        claim_ceiling="test",
    )


def _angle() -> dict[str, Any]:
    return {
        "attack_id": "ATK-TEST",
        "family": "TEST_FAMILY",
        "falsifier_id": "FALS-VEIP-P-02",
        "target_components": ["veip-sdk"],
        "allowed_attacker_capabilities": ["candidate construction"],
        "prohibited_attacker_capabilities": ["falsifier mutation"],
    }


def _falsifier() -> dict[str, Any]:
    return {
        "property_id": "VEIP-P-02",
        "counterexample_condition": "test",
        "predicate": "test",
        "required_observables": ["decision_sequence"],
    }


def _metadata() -> AttemptMetadata:
    return AttemptMetadata(
        attack_id="ATK-TEST",
        attack_family="TEST_FAMILY",
        property_id="VEIP-P-02",
        falsifier_id="FALS-VEIP-P-02",
        target_components=("veip-sdk",),
        subject_identity={"veip-sdk": "26ec65b90ad0081a063f5b994e8eda9776457359"},
        round_number=1,
        attempt_number=1,
        adversary_config_digest="sha256:test-config",
        capture_order_index=1,
    )


def _rendered() -> Any:
    return render_provider_request(
        _angle(),
        _falsifier(),
        round_number=1,
        attempt_number=1,
    )


def _raw(candidate: Any = None) -> str:
    if candidate is None:
        candidate = {"inputs": {"probe": {"value": 1}}}

    return json.dumps(
        {
            "attack_hypothesis": "test",
            "property_id": "VEIP-P-02",
            "attack_sequence": ["construct"],
            "candidate_witness": candidate,
            "claimed_violation": "test",
        },
        separators=(",", ":"),
    )


def _transport_evidence() -> dict[str, Any]:
    return {
        "classification": "SUCCESSFUL_MODEL_RESPONSE",
        "provider_run_occurred": True,
        "returned_model": "nvidia/nemotron-3-ultra-550b-a55b",
    }


def test_capture_exists_before_subject_invocation(tmp_path: Path) -> None:
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    def invoke(
        falsifier_id: str,
        inputs: dict[str, Any],
    ) -> dict[str, Any]:
        captures = list(tmp_path.glob("*.capture.json"))
        evaluations = list(tmp_path.glob("*.evaluation.json"))

        assert len(captures) == 1
        assert evaluations == []
        assert ledger.logical_adversarial_attempts == 1
        assert falsifier_id == "FALS-VEIP-P-02"
        assert inputs == {"probe": {"value": 1}}

        return {"decision_sequence": ["ALLOW", "ALLOW"]}

    capture, evaluation = capture_and_evaluate_attempt(
        metadata=_metadata(),
        contract=_contract(),
        rendered=_rendered(),
        raw_response=_raw(),
        transport_evidence=_transport_evidence(),
        ledger=ledger,
        recorder=recorder,
        invoke_fn=invoke,
    )

    assert Path(capture.path).exists()
    assert Path(evaluation.path).exists()
    assert evaluation.record["attempt_capture_sha256"] == capture.sha256
    assert evaluation.record["disposition"] == "NOT_A_COUNTEREXAMPLE"
    assert ledger.logical_adversarial_attempts == 1


def test_capture_binds_exact_candidate_bytes(tmp_path: Path) -> None:
    raw = _raw()
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    capture, _ = capture_and_evaluate_attempt(
        metadata=_metadata(),
        contract=_contract(),
        rendered=_rendered(),
        raw_response=raw,
        transport_evidence=_transport_evidence(),
        ledger=ledger,
        recorder=recorder,
        invoke_fn=lambda _f, _i: {"decision_sequence": ["ALLOW", "ALLOW"]},
    )

    assert capture.record["candidate_response_utf8"] == raw
    assert capture.record["candidate_response_sha256"] == hashlib.sha256(raw.encode()).hexdigest()


def test_malformed_response_is_captured_then_unevaluable(
    tmp_path: Path,
) -> None:
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    capture, evaluation = capture_and_evaluate_attempt(
        metadata=_metadata(),
        contract=_contract(),
        rendered=_rendered(),
        raw_response="{not-json",
        transport_evidence=_transport_evidence(),
        ledger=ledger,
        recorder=recorder,
        invoke_fn=lambda _f, _i: pytest.fail("subject must not be invoked"),
    )

    assert Path(capture.path).exists()
    assert evaluation.record["disposition"] == "UNEVALUABLE"
    assert evaluation.record["reason_category"] == "RESPONSE_MALFORMED"
    assert evaluation.record["attempt_consumed"] is True
    assert ledger.logical_adversarial_attempts == 1


def test_disposition_token_is_protocol_violation(tmp_path: Path) -> None:
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    _, evaluation = capture_and_evaluate_attempt(
        metadata=_metadata(),
        contract=_contract(),
        rendered=_rendered(),
        raw_response='{"x":"COUNTEREXAMPLE_VALIDATED"}',
        transport_evidence=_transport_evidence(),
        ledger=ledger,
        recorder=recorder,
        invoke_fn=lambda _f, _i: pytest.fail("subject must not be invoked"),
    )

    assert evaluation.record["disposition"] == "UNEVALUABLE"
    assert evaluation.record["reason_category"] == "PROTOCOL_VIOLATION"
    assert ledger.logical_adversarial_attempts == 1


def test_witness_schema_failure_is_stage_classified(
    tmp_path: Path,
) -> None:
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    _, evaluation = capture_and_evaluate_attempt(
        metadata=_metadata(),
        contract=_contract(),
        rendered=_rendered(),
        raw_response=_raw(candidate={}),
        transport_evidence=_transport_evidence(),
        ledger=ledger,
        recorder=recorder,
        invoke_fn=lambda _f, _i: pytest.fail("subject must not be invoked"),
    )

    assert evaluation.record["disposition"] == "UNEVALUABLE"
    assert evaluation.record["reason_category"] == "WITNESS_SCHEMA_INVALID"


def test_subject_failure_is_stage_classified(tmp_path: Path) -> None:
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    def invoke(
        falsifier_id: str,
        inputs: dict[str, Any],
    ) -> dict[str, Any]:
        raise RuntimeError("offline injected subject failure")

    _, evaluation = capture_and_evaluate_attempt(
        metadata=_metadata(),
        contract=_contract(),
        rendered=_rendered(),
        raw_response=_raw(),
        transport_evidence=_transport_evidence(),
        ledger=ledger,
        recorder=recorder,
        invoke_fn=invoke,
    )

    assert evaluation.record["disposition"] == "UNEVALUABLE"
    assert evaluation.record["reason_category"] == "SUBJECT_INVOCATION_FAILED"


def test_missing_observable_is_stage_classified(tmp_path: Path) -> None:
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    _, evaluation = capture_and_evaluate_attempt(
        metadata=_metadata(),
        contract=_contract(),
        rendered=_rendered(),
        raw_response=_raw(),
        transport_evidence=_transport_evidence(),
        ledger=ledger,
        recorder=recorder,
        invoke_fn=lambda _f, _i: {},
    )

    assert evaluation.record["disposition"] == "UNEVALUABLE"
    assert evaluation.record["reason_category"] == "OBSERVABLE_MISSING"


def test_valid_counterexample_is_bound_to_capture(tmp_path: Path) -> None:
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    capture, evaluation = capture_and_evaluate_attempt(
        metadata=_metadata(),
        contract=_contract(),
        rendered=_rendered(),
        raw_response=_raw(),
        transport_evidence=_transport_evidence(),
        ledger=ledger,
        recorder=recorder,
        invoke_fn=lambda _f, _i: {"decision_sequence": ["ALLOW", "DENY"]},
    )

    assert evaluation.record["disposition"] == "COUNTEREXAMPLE_VALIDATED"
    assert evaluation.record["attempt_capture_sha256"] == capture.sha256
    assert evaluation.record["verifier_result"]["counterexample"] is True


def test_capture_files_are_write_once(tmp_path: Path) -> None:
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    kwargs = {
        "metadata": _metadata(),
        "contract": _contract(),
        "rendered": _rendered(),
        "raw_response": _raw(),
        "transport_evidence": _transport_evidence(),
        "ledger": ledger,
        "recorder": recorder,
        "invoke_fn": lambda _f, _i: {"decision_sequence": ["ALLOW", "ALLOW"]},
    }

    capture_and_evaluate_attempt(**kwargs)

    with pytest.raises(FileExistsError):
        capture_and_evaluate_attempt(**kwargs)

    # The duplicate is rejected at capture time, before another logical
    # adversarial attempt can be consumed.
    assert ledger.logical_adversarial_attempts == 1


def test_feedback_surface_never_requires_internal_reason(
    tmp_path: Path,
) -> None:
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    _, evaluation = capture_and_evaluate_attempt(
        metadata=_metadata(),
        contract=_contract(),
        rendered=_rendered(),
        raw_response="{bad-json",
        transport_evidence=_transport_evidence(),
        ledger=ledger,
        recorder=recorder,
        invoke_fn=lambda _f, _i: {},
    )

    assert evaluation.record["reason_category"] == "RESPONSE_MALFORMED"

    # Internal evidence may preserve diagnosis, but the authorized feedback
    # interface is represented by the closed reason_category token only.
    assert "internal_reason" in evaluation.record
