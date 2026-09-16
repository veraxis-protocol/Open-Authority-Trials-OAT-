from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oat.veip.contracts import WitnessContract
from oat.veip.execution_path import BudgetLedger
from oat.veip.experiment001 import (
    AttemptEvidenceRecorder,
    AttemptMetadata,
    RenderedProviderRequest,
    capture_and_evaluate_bound_attempt,
)
from oat.veip.launch_binding import (
    OPEN_DISCOVERY_ATTACK_ID,
    OPEN_DISCOVERY_SENTINEL,
    aggregate_falsifier_evaluations,
    ready_falsifiers_for_property,
    resolve_angle_binding,
)


def _entry(fid: str, pid: str, *, status: str = "READY") -> dict[str, Any]:
    return {
        "falsifier_id": fid,
        "property_id": pid,
        "status": status,
        "counterexample_condition": f"condition-{fid}",
        "predicate": f"predicate-{fid}",
        "required_observables": [f"observable-{fid}"],
    }


def _contract(fid: str, pid: str) -> WitnessContract:
    return WitnessContract(
        falsifier_id=fid,
        property_id=pid,
        falsifier_version="1.0.0",
        input_schema={"mode": "string"},
        candidate_witness_schema={
            "type": "object",
            "required": ["inputs"],
            "additionalProperties": False,
            "properties": {
                "inputs": {
                    "type": "object",
                    "required": ["mode"],
                    "additionalProperties": False,
                    "properties": {"mode": {"type": "string"}},
                }
            },
        },
        required_observables=(f"observable-{fid}",),
        canonicalization_rule="test",
        missing_field_behavior="UNEVALUABLE",
        unknown_field_behavior="UNEVALUABLE",
        type_validation="test",
        unevaluable_conditions=(),
        negative_condition="test",
        counterexample_condition=f"condition-{fid}",
        claim_ceiling="test",
    )


def _metadata() -> AttemptMetadata:
    return AttemptMetadata(
        attack_id="ATK-MULTI",
        attack_family="test",
        property_id="P-1|P-2",
        falsifier_id="F-1|F-2",
        target_components=("component",),
        subject_identity={"subject": "frozen"},
        round_number=1,
        attempt_number=1,
        adversary_config_digest="sha256:test",
        capture_order_index=1,
    )


def _rendered() -> RenderedProviderRequest:
    body = b"{}"
    return RenderedProviderRequest(
        prompt_bytes=b"prompt",
        prompt_digest="sha256:prompt",
        body={},
        body_bytes=body,
        request_sha256="request",
        feedback=(),
    )


def _reply(property_id: str = "P-1", mode: str = "NEG") -> str:
    return json.dumps(
        {
            "attack_hypothesis": "test",
            "property_id": property_id,
            "attack_sequence": ["construct"],
            "candidate_witness": {"inputs": {"mode": mode}},
            "claimed_violation": mode == "CE",
        },
        separators=(",", ":"),
    )


def test_multi_falsifier_binding_preserves_taxonomy_order_and_filters_non_ready() -> None:
    falsifiers = {
        "F-1": _entry("F-1", "P-1"),
        "F-X": _entry("F-X", "P-X", status="AMBIGUOUS"),
        "F-2": _entry("F-2", "P-2"),
    }
    angle = {
        "attack_id": "ATK-MULTI",
        "family": "multi",
        "falsifiers": ["F-1", "F-X", "F-2"],
    }

    binding = resolve_angle_binding(angle, falsifiers)

    assert binding.ready_falsifier_ids == ("F-1", "F-2")
    assert binding.property_ids == ("P-1", "P-2")
    assert binding.open_discovery is False
    assert binding.render_falsifier["property_id"] == "P-1 | P-2"
    assert "condition-F-1" in binding.render_falsifier["counterexample_condition"]
    assert "condition-F-2" in binding.render_falsifier["counterexample_condition"]


def test_open_discovery_has_no_preselected_falsifier() -> None:
    angle = {
        "attack_id": OPEN_DISCOVERY_ATTACK_ID,
        "family": "open discovery",
        "falsifiers": [OPEN_DISCOVERY_SENTINEL],
        "target_property_ids": ["ANY_IN_SCOPE", "OR_NEWLY_PROPOSED"],
    }

    binding = resolve_angle_binding(angle, {})

    assert binding.open_discovery is True
    assert binding.ready_falsifier_ids == ()
    assert binding.falsifier_label == "NONE"
    assert "ANY_IN_SCOPE" in binding.render_falsifier["property_id"]


def test_ready_property_lookup_preserves_frozen_register_order() -> None:
    falsifiers = {
        "F-2": _entry("F-2", "P"),
        "F-X": _entry("F-X", "P", status="AMBIGUOUS"),
        "F-1": _entry("F-1", "P"),
    }
    assert ready_falsifiers_for_property("P", falsifiers) == ("F-2", "F-1")


def test_aggregation_is_fail_closed() -> None:
    assert aggregate_falsifier_evaluations(
        [
            {"disposition": "NOT_A_COUNTEREXAMPLE"},
            {"disposition": "NOT_A_COUNTEREXAMPLE"},
        ]
    ) == ("NOT_A_COUNTEREXAMPLE", None)

    assert aggregate_falsifier_evaluations(
        [
            {"disposition": "UNEVALUABLE", "reason_category": "WITNESS_SCHEMA_INVALID"},
            {"disposition": "NOT_A_COUNTEREXAMPLE"},
        ]
    ) == ("UNEVALUABLE", "WITNESS_SCHEMA_INVALID")

    assert aggregate_falsifier_evaluations(
        [
            {"disposition": "UNEVALUABLE", "reason_category": "OTHER"},
            {"disposition": "COUNTEREXAMPLE_VALIDATED"},
        ]
    ) == ("COUNTEREXAMPLE_VALIDATED", None)


def test_multi_falsifier_attempt_consumes_one_attempt_and_evaluates_all(
    tmp_path: Path,
) -> None:
    falsifiers = {
        "F-1": _entry("F-1", "P-1"),
        "F-2": _entry("F-2", "P-2"),
    }
    angle = {
        "attack_id": "ATK-MULTI",
        "family": "multi",
        "falsifiers": ["F-1", "F-2"],
    }
    binding = resolve_angle_binding(angle, falsifiers)
    contracts = {"F-1": _contract("F-1", "P-1"), "F-2": _contract("F-2", "P-2")}
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)
    invoked: list[str] = []

    def invoke(fid: str, inputs: dict[str, Any]) -> dict[str, Any]:
        invoked.append(fid)
        return {f"observable-{fid}": inputs["mode"]}

    def evaluate(fid: str, trace: dict[str, Any]) -> dict[str, Any]:
        return {
            "disposition": ("COUNTEREXAMPLE_VALIDATED" if fid == "F-2" else "NOT_A_COUNTEREXAMPLE"),
            "counterexample": fid == "F-2",
            "trace": trace,
        }

    _capture, evaluation = capture_and_evaluate_bound_attempt(
        metadata=_metadata(),
        binding=binding,
        contracts=contracts,
        falsifiers=falsifiers,
        rendered=_rendered(),
        raw_response=_reply(),
        transport_evidence={},
        ledger=ledger,
        recorder=recorder,
        invoke_fn=invoke,
        evaluate_fn=evaluate,
    )

    assert invoked == ["F-1", "F-2"]
    assert ledger.logical_adversarial_attempts == 1
    assert evaluation.record["disposition"] == "COUNTEREXAMPLE_VALIDATED"
    assert evaluation.record["evaluated_falsifier_ids"] == ["F-1", "F-2"]


def test_open_discovery_unmapped_property_is_outside_scope_without_invocation(
    tmp_path: Path,
) -> None:
    binding = resolve_angle_binding(
        {
            "attack_id": OPEN_DISCOVERY_ATTACK_ID,
            "family": "open discovery",
            "falsifiers": [OPEN_DISCOVERY_SENTINEL],
        },
        {},
    )
    ledger = BudgetLedger()
    recorder = AttemptEvidenceRecorder(tmp_path)

    def forbidden_invoke(_fid: str, _inputs: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("open discovery unmapped property must not invoke subject")

    _capture, evaluation = capture_and_evaluate_bound_attempt(
        metadata=AttemptMetadata(
            attack_id=OPEN_DISCOVERY_ATTACK_ID,
            attack_family="open discovery",
            property_id="OPEN_DISCOVERY",
            falsifier_id="NONE",
            target_components=("any",),
            subject_identity={"subject": "frozen"},
            round_number=1,
            attempt_number=1,
            adversary_config_digest="sha256:test",
            capture_order_index=1,
        ),
        binding=binding,
        contracts={},
        falsifiers={},
        rendered=_rendered(),
        raw_response=_reply(property_id="NEW-PROPERTY"),
        transport_evidence={},
        ledger=ledger,
        recorder=recorder,
        invoke_fn=forbidden_invoke,
    )

    assert ledger.logical_adversarial_attempts == 1
    assert evaluation.record["disposition"] == "OUTSIDE_SCOPE"
    assert evaluation.record["mapped_ready_falsifier_ids"] == []


def test_owner_disposition_resolves_the_frozen_17_angle_matrix() -> None:
    falsifiers = {
        "FALS-VEIP-P-02": _entry("FALS-VEIP-P-02", "VEIP-P-02"),
        "FALS-VEIP-P-03": _entry("FALS-VEIP-P-03", "VEIP-P-03"),
        "FALS-VEIP-P-05": _entry("FALS-VEIP-P-05", "VEIP-P-05"),
        "FALS-VEIP-P-09": _entry("FALS-VEIP-P-09", "VEIP-P-09"),
        "FALS-VEIP-P-11": _entry("FALS-VEIP-P-11", "VEIP-P-11"),
        "FALS-VEIP-P-14": _entry("FALS-VEIP-P-14", "VEIP-P-14"),
        "FALS-VEIP-P-17": _entry("FALS-VEIP-P-17", "VEIP-P-17"),
        "FALS-VEIP-P-18": _entry("FALS-VEIP-P-18", "VEIP-P-18"),
        "FALS-VEIP-P-19": _entry("FALS-VEIP-P-19", "VEIP-P-19"),
        "FALS-VEIP-P-19B": _entry("FALS-VEIP-P-19B", "VEIP-P-19B", status="AMBIGUOUS"),
        "FALS-VEIP-P-20": _entry("FALS-VEIP-P-20", "VEIP-P-20"),
    }
    declared = [
        ("ATK-F04", ["FALS-VEIP-P-09"]),
        ("ATK-F06", ["FALS-VEIP-P-18"]),
        ("ATK-F07", ["FALS-VEIP-P-18"]),
        ("ATK-F08", ["FALS-VEIP-P-05"]),
        ("ATK-F17", ["FALS-VEIP-P-02", "FALS-VEIP-P-03"]),
        ("ATK-F18", ["FALS-VEIP-P-05"]),
        ("ATK-F19", ["FALS-VEIP-P-11"]),
        ("ATK-F20", ["FALS-VEIP-P-11", "FALS-VEIP-P-19"]),
        ("ATK-F21", ["FALS-VEIP-P-19"]),
        ("ATK-F22", ["FALS-VEIP-P-11"]),
        ("ATK-F25", ["FALS-VEIP-P-14"]),
        ("ATK-F29", ["FALS-VEIP-P-11", "FALS-VEIP-P-20"]),
        ("ATK-F30", ["FALS-VEIP-P-17", "FALS-VEIP-P-19B"]),
        ("ATK-F31", ["FALS-VEIP-P-17"]),
        ("ATK-F38", ["FALS-VEIP-P-19"]),
        ("ATK-F39", ["FALS-VEIP-P-03", "FALS-VEIP-P-17"]),
        (OPEN_DISCOVERY_ATTACK_ID, [OPEN_DISCOVERY_SENTINEL]),
    ]

    bindings = {
        attack_id: resolve_angle_binding(
            {"attack_id": attack_id, "family": "frozen", "falsifiers": fids},
            falsifiers,
        )
        for attack_id, fids in declared
    }

    assert len(bindings) == 17
    assert bindings["ATK-F17"].ready_falsifier_ids == (
        "FALS-VEIP-P-02",
        "FALS-VEIP-P-03",
    )
    assert bindings["ATK-F20"].ready_falsifier_ids == (
        "FALS-VEIP-P-11",
        "FALS-VEIP-P-19",
    )
    assert bindings["ATK-F29"].ready_falsifier_ids == (
        "FALS-VEIP-P-11",
        "FALS-VEIP-P-20",
    )
    assert bindings["ATK-F30"].ready_falsifier_ids == ("FALS-VEIP-P-17",)
    assert bindings["ATK-F39"].ready_falsifier_ids == (
        "FALS-VEIP-P-03",
        "FALS-VEIP-P-17",
    )
    assert bindings[OPEN_DISCOVERY_ATTACK_ID].open_discovery is True
    assert bindings[OPEN_DISCOVERY_ATTACK_ID].ready_falsifier_ids == ()
