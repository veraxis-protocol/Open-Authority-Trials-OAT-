"""Exact trace predicates for the thirteen frozen READY falsifiers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class Unevaluable(ValueError):
    """The observable trace is incomplete or malformed."""


def _need(trace: dict[str, Any], *names: str) -> list[Any]:
    missing = [name for name in names if name not in trace]
    if missing:
        raise Unevaluable(f"missing observables: {', '.join(missing)}")
    return [trace[name] for name in names]


def _p02(t: dict[str, Any]) -> bool:
    (seq,) = _need(t, "decision_sequence")
    return len(set(seq)) > 1


def _p03(t: dict[str, Any]) -> bool:
    _need(t, "transition_table", "raised_exception")
    return bool(t.get("undefined_producible_transition", False))


def _p05(t: dict[str, Any]) -> bool:
    replay, recomputed, recorded = _need(
        t, "replay_result", "recomputed_decision", "pack.decision.classification"
    )
    return bool(replay["ok"]) and recorded != recomputed


def _p09(t: dict[str, Any]) -> bool:
    decision, permitted, action = _need(t, "decision", "permitted_actions", "action_type")
    return decision == "ALLOW" and action not in permitted


def _p11(t: dict[str, Any]) -> bool:
    validation, missing = _need(t, "validation_outcome", "missing_fields")
    return (bool(t.get("emitted_by_generate_evidence")) and not validation["ok"]) or (
        bool(missing) and validation["ok"]
    )


def _p12a(t: dict[str, Any]) -> bool:
    (seq,) = _need(t, "classification_sequence")
    return len(set(seq)) > 1


def _p14(t: dict[str, Any]) -> bool:
    digest, raised, replay = _need(t, "schema_digest", "raised_exception", "replay_result")
    return (digest != t["pinned_schema_digest"] and not raised) or (
        t["pack_schema_version"] != t["spec_version"] and bool(replay["ok"])
    )


def _p17(t: dict[str, Any]) -> bool:
    (raised,) = _need(t, "raised_exception")
    return not bool(raised)


def _p18(t: dict[str, Any]) -> bool:
    action_id, recomputed, replay = _need(t, "action_id", "recomputed_fingerprint", "replay_result")
    return bool(replay["ok"]) and action_id != recomputed


def _p19(t: dict[str, Any]) -> bool:
    stored, computed, result = _need(t, "stored_binding", "computed_binding", "IntegrityResult")
    return bool(result["ok"]) and stored != computed


def _p20(t: dict[str, Any]) -> bool:
    status, stored = _need(t, "http_status", "stored_pack")
    invalid_accepted = 200 <= int(status) < 300 and not bool(t["submitted_pack_valid"])
    invalid_retrieved = stored is not None and not bool(t["stored_pack_valid"])
    return invalid_accepted or invalid_retrieved


def _p01s(t: dict[str, Any]) -> bool:
    _need(t, "transition_table", "reachability_paths")
    return any(
        path[-1:] == ["EXECUTED"] and "AUTHORIZED" not in path for path in t["reachability_paths"]
    )


def _p07s(t: dict[str, Any]) -> bool:
    (table,) = _need(t, "transition_table")
    return "EXECUTED" in table.get("SUPERVISORY", [])


EVALUATORS: dict[str, Callable[[dict[str, Any]], bool]] = {
    "FALS-VEIP-P-02": _p02,
    "FALS-VEIP-P-03": _p03,
    "FALS-VEIP-P-05": _p05,
    "FALS-VEIP-P-09": _p09,
    "FALS-VEIP-P-11": _p11,
    "FALS-VEIP-P-12A": _p12a,
    "FALS-VEIP-P-14": _p14,
    "FALS-VEIP-P-17": _p17,
    "FALS-VEIP-P-18": _p18,
    "FALS-VEIP-P-19": _p19,
    "FALS-VEIP-P-20": _p20,
    "FALS-VEIP-P-01S": _p01s,
    "FALS-VEIP-P-07S": _p07s,
}


def evaluate(falsifier_id: str, trace: dict[str, Any]) -> dict[str, Any]:
    try:
        counterexample = EVALUATORS[falsifier_id](trace)
    except (KeyError, TypeError, ValueError, Unevaluable) as exc:
        return {"disposition": "UNEVALUABLE", "reason": str(exc), "trace": trace}
    return {
        "disposition": "COUNTEREXAMPLE_VALIDATED" if counterexample else "NOT_A_COUNTEREXAMPLE",
        "counterexample": counterexample,
        "trace": trace,
    }
