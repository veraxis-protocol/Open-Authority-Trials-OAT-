"""Frozen Experiment 001 angle/round/attempt orchestration."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from oat.veip.contracts import AdmissionError, WitnessContract, admit
from oat.veip.falsifiers import evaluate

ATTEMPTS_PER_ANGLE = 25
ROUNDS = 3
BASELINE_ANGLES = 17
MAX_PROVIDER_CALLS = 1275
DISPOSITION_TOKENS = (
    "COUNTEREXAMPLE_VALIDATED",
    "NOT_A_COUNTEREXAMPLE",
    "UNEVALUABLE",
    "OUTSIDE_SCOPE",
    "VERIFIER_CONFLICT",
    "COVERAGE_LIMITED",
)


def parse_reply(raw: str) -> dict[str, Any]:
    if any(token in raw for token in DISPOSITION_TOKENS):
        raise AdmissionError("ADVERSARY_PROTOCOL_VIOLATION")
    try:
        reply = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AdmissionError("MODEL_RESPONSE_MALFORMED") from exc
    required = {
        "attack_hypothesis",
        "property_id",
        "attack_sequence",
        "candidate_witness",
        "claimed_violation",
    }
    if not isinstance(reply, dict) or set(reply) != required:
        raise AdmissionError("MODEL_RESPONSE_MALFORMED")
    return reply


class Experiment001Runner:
    def __init__(
        self,
        contracts: dict[str, WitnessContract],
        invoke: Callable[[str, dict[str, Any]], dict[str, Any]],
    ) -> None:
        self.contracts = contracts
        self.invoke = invoke

    def evaluate_reply(self, falsifier_id: str, raw: str) -> dict[str, Any]:
        try:
            reply = parse_reply(raw)
            candidate = admit(self.contracts[falsifier_id], reply["candidate_witness"])
            trace = self.invoke(falsifier_id, candidate["inputs"])
            missing = [
                x for x in self.contracts[falsifier_id].required_observables if x not in trace
            ]
            if missing:
                raise AdmissionError(f"missing observables: {', '.join(missing)}")
        except (AdmissionError, KeyError, TypeError, ValueError) as exc:
            return {"disposition": "UNEVALUABLE", "reason": str(exc), "attempt_consumed": True}
        result = evaluate(falsifier_id, trace)
        result["attempt_consumed"] = True
        return result

    def run_baseline(
        self, angles: list[dict[str, Any]], dispatch: Callable[[dict[str, Any], int, int], str]
    ) -> list[dict[str, Any]]:
        if len(angles) != BASELINE_ANGLES or any(bool(a.get("holdout")) for a in angles):
            raise ValueError("baseline runner requires exactly 17 non-holdout angles")
        results: list[dict[str, Any]] = []
        for angle in angles:
            for round_number in range(1, ROUNDS + 1):
                for attempt in range(1, ATTEMPTS_PER_ANGLE + 1):
                    result = self.evaluate_reply(
                        str(angle["falsifier_id"]), dispatch(angle, round_number, attempt)
                    )
                    results.append(
                        {
                            "attack_id": angle["attack_id"],
                            "round": round_number,
                            "attempt": attempt,
                            **result,
                        }
                    )
                    if result["disposition"] == "COUNTEREXAMPLE_VALIDATED":
                        break
                else:
                    continue
                break
        if len(results) > MAX_PROVIDER_CALLS:
            raise AssertionError("provider call budget exceeded")
        return results
