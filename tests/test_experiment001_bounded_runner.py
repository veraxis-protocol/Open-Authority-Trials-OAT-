from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from oat.adversaries.provider import TransportError
from oat.veip.contracts import WitnessContract
from oat.veip.execution_path import (
    PHYSICAL_PROVIDER_CALL_CEILING,
    RESERVED_OUTPUT_TOKEN_CEILING,
    BudgetLedger,
)
from oat.veip.experiment001 import (
    NVIDIA_MODEL,
    run_experiment001_baseline,
)
from oat.veip.transport import (
    TransportClass,
    TransportEvidence,
    canonical_request_body,
)


def _contract() -> WitnessContract:
    return WitnessContract(
        falsifier_id="FALS-TEST",
        property_id="VEIP-P-TEST",
        falsifier_version="TEST",
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
                    "properties": {
                        "mode": {"type": "string"},
                    },
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


def _falsifier() -> dict[str, Any]:
    return {
        "falsifier_id": "FALS-TEST",
        "property_id": "VEIP-P-TEST",
        "counterexample_condition": "test condition",
        "predicate": "test predicate",
        "required_observables": ["decision_sequence"],
    }


def _angles() -> list[dict[str, Any]]:
    return [
        {
            "attack_id": f"ATK-{index:02d}",
            "family": "TEST_FAMILY",
            "falsifier_id": "FALS-TEST",
            "target_components": ["veip-sdk"],
            "allowed_attacker_capabilities": ["candidate construction"],
            "prohibited_attacker_capabilities": ["falsifier mutation"],
            "holdout": False,
        }
        for index in range(1, 18)
    ]


def _reply(mode: str) -> str:
    return json.dumps(
        {
            "attack_hypothesis": "test",
            "property_id": "VEIP-P-TEST",
            "attack_sequence": ["construct"],
            "candidate_witness": {
                "inputs": {
                    "mode": mode,
                }
            },
            "claimed_violation": mode == "CE",
        },
        separators=(",", ":"),
    )


def _invoke(
    falsifier_id: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    assert falsifier_id == "FALS-TEST"
    return {
        "decision_sequence": [
            str(inputs["mode"]),
        ]
    }


def _evaluate(
    falsifier_id: str,
    trace: dict[str, Any],
) -> dict[str, Any]:
    assert falsifier_id == "FALS-TEST"
    counterexample = trace["decision_sequence"][0] == "CE"

    return {
        "disposition": ("COUNTEREXAMPLE_VALIDATED" if counterexample else "NOT_A_COUNTEREXAMPLE"),
        "counterexample": counterexample,
        "trace": trace,
    }


@dataclass
class _FakeFailure:
    retry_ordinal: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": "HTTP_5XX_TRANSPORT_FAILURE",
            "retryable": True,
            "retry_ordinal": self.retry_ordinal,
            "provider_run_occurred": True,
        }


Behavior = Callable[[int, dict[str, Any]], str]


class _FakeTransport:
    def __init__(
        self,
        ledger: BudgetLedger,
        behavior: Behavior,
    ) -> None:
        self.ledger = ledger
        self.behavior = behavior
        self.calls = 0
        self.requests: list[dict[str, Any]] = []
        self.transport_failures: list[_FakeFailure] = []

    def complete_with_retries(
        self,
        body: dict[str, Any],
    ) -> TransportEvidence:
        self.calls += 1
        self.requests.append(body)

        action = self.behavior(self.calls, body)

        if action == "__TRANSPORT_FAIL__":
            for retry_ordinal in range(3):
                self.ledger.reserve_provider_call()
                self.transport_failures.append(_FakeFailure(retry_ordinal))
            raise TransportError("HTTP_5XX_TRANSPORT_FAILURE")

        self.ledger.reserve_provider_call()

        returned_model = NVIDIA_MODEL
        raw_response = action

        if action == "__MODEL_MISMATCH__":
            returned_model = "unexpected/provider-model"
            raw_response = _reply("NEG")

        request_body = canonical_request_body(body)
        request_sha = hashlib.sha256(request_body).hexdigest()

        raw = raw_response.encode()

        return TransportEvidence(
            classification=(TransportClass.SUCCESSFUL_MODEL_RESPONSE),
            request_body=request_body,
            request_sha256=request_sha,
            http_status=200,
            response_headers={
                "nvcf-status": "fulfilled",
            },
            raw_sse=raw,
            reconstructed_content=raw_response,
            returned_model=returned_model,
            done_seen=True,
            elapsed_ms=1,
            response_sha256=hashlib.sha256(raw).hexdigest(),
            provider_run_occurred=True,
        )


def _run(
    tmp_path: Path,
    behavior: Behavior,
    *,
    angles: list[dict[str, Any]] | None = None,
    ledger: BudgetLedger | None = None,
    seed_capability_verified: bool = True,
) -> tuple[Any, _FakeTransport, BudgetLedger]:
    active_ledger = ledger if ledger is not None else BudgetLedger()

    transport = _FakeTransport(
        active_ledger,
        behavior,
    )

    result = run_experiment001_baseline(
        angles if angles is not None else _angles(),
        contracts={
            "FALS-TEST": _contract(),
        },
        falsifiers={
            "FALS-TEST": _falsifier(),
        },
        subject_identity={"veip-sdk": ("26ec65b90ad0081a063f5b994e8eda9776457359")},
        adversary_config_digest="sha256:test-config",
        evidence_root=tmp_path / "evidence",
        seed_capability_verified=seed_capability_verified,
        ledger=active_ledger,
        transport_override=transport,
        invoke_fn=_invoke,
        evaluate_fn=_evaluate,
    )

    return result, transport, active_ledger


def test_holdout_firewall_rejects_before_dispatch(
    tmp_path: Path,
) -> None:
    angles = _angles()
    angles[4]["holdout"] = True

    ledger = BudgetLedger()
    transport = _FakeTransport(
        ledger,
        lambda _n, _body: pytest.fail("provider dispatch must not occur"),
    )

    with pytest.raises(
        ValueError,
        match="holdout material rejected",
    ):
        run_experiment001_baseline(
            angles,
            contracts={
                "FALS-TEST": _contract(),
            },
            falsifiers={
                "FALS-TEST": _falsifier(),
            },
            subject_identity={"veip-sdk": "frozen"},
            adversary_config_digest="sha256:test",
            evidence_root=tmp_path / "evidence",
            seed_capability_verified=True,
            ledger=ledger,
            transport_override=transport,
            invoke_fn=_invoke,
            evaluate_fn=_evaluate,
        )

    assert transport.calls == 0
    assert ledger.physical_provider_calls == 0
    assert ledger.logical_adversarial_attempts == 0


def test_seed_capability_must_be_preverified(
    tmp_path: Path,
) -> None:
    ledger = BudgetLedger()
    transport = _FakeTransport(
        ledger,
        lambda _n, _body: pytest.fail("provider dispatch must not occur"),
    )

    with pytest.raises(
        ValueError,
        match="seed capability must be verified",
    ):
        run_experiment001_baseline(
            _angles(),
            contracts={
                "FALS-TEST": _contract(),
            },
            falsifiers={
                "FALS-TEST": _falsifier(),
            },
            subject_identity={"veip-sdk": "frozen"},
            adversary_config_digest="sha256:test",
            evidence_root=tmp_path / "evidence",
            seed_capability_verified=False,
            ledger=ledger,
            transport_override=transport,
            invoke_fn=_invoke,
            evaluate_fn=_evaluate,
        )

    assert transport.calls == 0
    assert ledger.physical_provider_calls == 0


def test_physical_budget_exhaustion_terminalizes_all_remaining_angles(
    tmp_path: Path,
) -> None:
    ledger = BudgetLedger(
        physical_provider_calls=(PHYSICAL_PROVIDER_CALL_CEILING),
        reserved_output_token_units=(RESERVED_OUTPUT_TOKEN_CEILING),
    )

    result, _transport, active = _run(
        tmp_path,
        lambda _n, _body: _reply("NEG"),
        ledger=ledger,
    )

    assert result.execution_stopped is True
    assert result.stop_reason == "PHYSICAL_PROVIDER_BUDGET_EXHAUSTED"
    assert len(result.attempt_records) == 0
    assert len(result.angle_terminals) == 17

    assert all(item["disposition"] == "COVERAGE_LIMITED" for item in result.angle_terminals)
    assert all(
        item["terminal_reason"] == "PHYSICAL_PROVIDER_BUDGET_EXHAUSTED"
        for item in result.angle_terminals
    )

    assert active.physical_provider_calls == 1275
    assert active.reserved_output_token_units == 5_222_400
    assert active.logical_adversarial_attempts == 0

    assert not list((tmp_path / "evidence").glob("*.capture.json"))


def test_terminal_transport_failure_consumes_physical_not_logical(
    tmp_path: Path,
) -> None:
    result, transport, ledger = _run(
        tmp_path,
        lambda _n, _body: "__TRANSPORT_FAIL__",
    )

    assert result.execution_stopped is True
    assert result.stop_reason == "PROVIDER_TRANSPORT_EXHAUSTED"
    assert len(result.attempt_records) == 0
    assert len(result.angle_terminals) == 17

    assert ledger.physical_provider_calls == 3
    assert ledger.reserved_output_token_units == 12_288
    assert ledger.logical_adversarial_attempts == 0

    assert len(transport.transport_failures) == 3
    assert result.angle_terminals[0]["terminal_reason"] == "PROVIDER_TRANSPORT_EXHAUSTED"
    assert result.angle_terminals[1]["not_executed_due_to_upstream_stop"] is True


def test_first_counterexample_terminates_only_that_angle(
    tmp_path: Path,
) -> None:
    def behavior(
        call: int,
        body: dict[str, Any],
    ) -> str:
        if call == 1:
            return _reply("CE")
        return "__TRANSPORT_FAIL__"

    result, _transport, ledger = _run(
        tmp_path,
        behavior,
    )

    assert len(result.attempt_records) == 1
    assert result.attempt_records[0]["disposition"] == "COUNTEREXAMPLE_VALIDATED"

    assert result.angle_terminals[0]["disposition"] == "COUNTEREXAMPLE_VALIDATED"

    assert result.angle_terminals[1]["disposition"] == "COVERAGE_LIMITED"

    assert result.angle_terminals[1]["terminal_reason"] == "PROVIDER_TRANSPORT_EXHAUSTED"

    assert ledger.logical_adversarial_attempts == 1
    assert ledger.physical_provider_calls == 4


def test_round_two_receives_only_round_one_closed_feedback(
    tmp_path: Path,
) -> None:
    def behavior(
        call: int,
        body: dict[str, Any],
    ) -> str:
        if call <= 25:
            return "{malformed-json"

        if call == 26:
            return _reply("CE")

        return "__TRANSPORT_FAIL__"

    result, transport, ledger = _run(
        tmp_path,
        behavior,
    )

    assert len(result.attempt_records) == 26
    assert ledger.logical_adversarial_attempts == 26

    # Request 26 is round 2 / attempt 1 for the first angle.
    round_two_user = transport.requests[25]["messages"][1]["content"]

    assert "FEEDBACK ON YOUR PREVIOUS ROUND FOR THIS ANGLE ONLY" in round_two_user
    assert "attempt 1: UNEVALUABLE, RESPONSE_MALFORMED" in round_two_user
    assert "attempt 25: UNEVALUABLE, RESPONSE_MALFORMED" in round_two_user

    # Raw parser diagnosis never enters the adversary feedback.
    assert "MODEL_RESPONSE_MALFORMED" not in round_two_user

    assert result.angle_terminals[0]["disposition"] == "COUNTEREXAMPLE_VALIDATED"


def test_completed_planned_depth_is_coverage_limited_not_clean_pass(
    tmp_path: Path,
) -> None:
    def behavior(
        call: int,
        body: dict[str, Any],
    ) -> str:
        # First sixteen angles terminate immediately with a validated
        # counterexample. The seventeenth then runs all 75 planned attempts.
        if call <= 16:
            return _reply("CE")
        return _reply("NEG")

    result, transport, ledger = _run(
        tmp_path,
        behavior,
    )

    assert result.execution_stopped is False
    assert result.stop_reason is None

    assert transport.calls == 91
    assert ledger.physical_provider_calls == 91
    assert ledger.logical_adversarial_attempts == 91

    assert len(result.angle_terminals) == 17

    assert all(
        item["disposition"] == "COUNTEREXAMPLE_VALIDATED" for item in result.angle_terminals[:16]
    )

    last = result.angle_terminals[-1]

    assert last["disposition"] == "COVERAGE_LIMITED"
    assert last["terminal_reason"] == "PLANNED_ANGLE_DEPTH_EXHAUSTED"

    assert Path(result.run_summary_path).exists()


def test_provider_model_mismatch_is_captured_and_stops_run(
    tmp_path: Path,
) -> None:
    result, _transport, ledger = _run(
        tmp_path,
        lambda _n, _body: "__MODEL_MISMATCH__",
    )

    assert result.execution_stopped is True
    assert result.stop_reason == "PROVIDER_MODEL_IDENTITY_MISMATCH"

    assert len(result.attempt_records) == 1
    assert result.attempt_records[0]["disposition"] == "UNEVALUABLE"

    assert ledger.physical_provider_calls == 1
    assert ledger.logical_adversarial_attempts == 1

    captures = list((tmp_path / "evidence").glob("*.capture.json"))
    assert len(captures) == 1


def test_run_summary_binds_three_budget_counters(
    tmp_path: Path,
) -> None:
    result, _transport, ledger = _run(
        tmp_path,
        lambda _n, _body: "__TRANSPORT_FAIL__",
    )

    summary = json.loads(Path(result.run_summary_path).read_text())

    assert summary["budget"] == {
        "logical_adversarial_attempts": 0,
        "physical_provider_calls": 3,
        "reserved_output_token_units": 12_288,
    }

    assert result.budget == ledger.to_dict()
