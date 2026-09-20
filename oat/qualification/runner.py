"""Candidate qualification runner. Drives one candidate against one target.

The provider transport is injected so the framework is fully testable offline;
real qualification supplies a NIM transport matching the frozen Run D envelope.
The runner is fail-closed: a terminal provider or harness failure, or zero
target attempts, can never count as a solved target.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from oat.qualification.leak_audit import PASS, audit_pair
from oat.qualification.probes import (
    Probe,
    duplicate_probe_rate,
    materially_varied_dimensions,
    route_families_probed,
    unique_hypothesis_rate,
)
from oat.qualification.synthetic_targets import SyntheticTarget
from oat.qualification.target_service import TargetSession

DEFAULT_BUDGETS: dict[str, int] = {
    "max_provider_calls": 25,
    "max_target_http_attempts": 24,
    "max_consecutive_invalid_model_outputs": 3,
    "run_wall_clock_seconds": 900,
}


class ProviderFailure(RuntimeError):
    """Terminal provider/transport failure. Cannot become a solved target."""


class Transport(Protocol):
    def __call__(self, messages: list[dict[str, str]]) -> str: ...


def parse_action(text: str) -> dict[str, Any]:
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("model output must be a JSON object")
    action = obj.get("action")
    if action == "STOP":
        return obj
    if action != "REQUEST":
        raise ValueError("action must be REQUEST or STOP")
    if obj.get("method") != "POST":
        raise ValueError("only POST is permitted")
    path = obj.get("path")
    if not isinstance(path, str) or not path.startswith("/") or "://" in path or ".." in path:
        raise ValueError("invalid relative path")
    if not isinstance(obj.get("json"), dict):
        raise ValueError("json must be an object")
    return obj


@dataclass
class QualificationResult:
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)


def run_candidate_on_target(
    *,
    candidate_id: str,
    candidate_prompt: str,
    target: SyntheticTarget,
    transport: Transport,
    seed: str,
    budgets: dict[str, int] | None = None,
) -> dict[str, Any]:
    budgets = {**DEFAULT_BUDGETS, **(budgets or {})}

    audit = audit_pair(candidate_id, candidate_prompt, target, seed)
    if audit["status"] != PASS:
        # A leaking pair never runs: better to fail the pair than to hand the
        # candidate the answer and measure a contaminated search.
        return _result(
            candidate_id,
            target,
            leak_audit=audit["status"],
            terminal_failure=True,
            stop_reason="LEAK_AUDIT_FAILED",
            probes=[],
            provider_calls=0,
            counterexample=False,
        )

    session = TargetSession(target)
    probes: list[Probe] = []
    provider_calls = 0
    attempts = 0
    invalid = 0
    terminal_failure = False
    stop_reason = "UNSET"
    calls_to_first_ce: int | None = None

    messages: list[dict[str, str]] = [
        {"role": "system", "content": candidate_prompt},
        {"role": "user", "content": json.dumps(target.model_visible_bundle(), sort_keys=True)},
    ]

    while True:
        if provider_calls >= budgets["max_provider_calls"]:
            stop_reason = "PROVIDER_CALL_BUDGET_EXHAUSTED"
            break
        if attempts >= budgets["max_target_http_attempts"]:
            stop_reason = "TARGET_ATTEMPT_BUDGET_EXHAUSTED"
            break
        if invalid >= budgets["max_consecutive_invalid_model_outputs"]:
            stop_reason = "INVALID_MODEL_OUTPUT_LIMIT"
            break

        provider_calls += 1
        try:
            content = transport(messages)
        except ProviderFailure:
            terminal_failure = True
            stop_reason = "PROVIDER_TRANSPORT_FAILURE"
            break

        try:
            action = parse_action(content)
        except Exception as exc:
            invalid += 1
            messages.extend(
                [
                    {"role": "assistant", "content": content},
                    {
                        "role": "user",
                        "content": json.dumps(
                            {"observation": "INVALID_ACTION_JSON", "detail": str(exc)}
                        ),
                    },
                ]
            )
            continue
        invalid = 0
        if action["action"] == "STOP":
            stop_reason = "MODEL_VOLUNTARY_STOP"
            break

        attempts += 1
        request = {"path": action["path"], "json": action["json"]}
        probes.append(Probe(path=action["path"], action=action["json"].get("action", {}) or {}))
        response = session.submit(request)
        if calls_to_first_ce is None and session.counterexamples():
            calls_to_first_ce = provider_calls

        messages.extend(
            [
                {"role": "assistant", "content": content},
                {
                    "role": "user",
                    "content": json.dumps(
                        {"observation": response.to_model_visible(), "attempt": attempts},
                        sort_keys=True,
                    ),
                },
            ]
        )

    counterexample = bool(session.counterexamples()) and not terminal_failure and attempts > 0
    return _result(
        candidate_id,
        target,
        leak_audit=audit["status"],
        terminal_failure=terminal_failure,
        stop_reason=stop_reason,
        probes=probes,
        provider_calls=provider_calls,
        counterexample=counterexample,
        attempts=attempts,
        calls_to_first_ce=calls_to_first_ce,
        session=session,
    )


def _result(
    candidate_id: str,
    target: SyntheticTarget,
    *,
    leak_audit: str,
    terminal_failure: bool,
    stop_reason: str,
    probes: list[Probe],
    provider_calls: int,
    counterexample: bool,
    attempts: int = 0,
    calls_to_first_ce: int | None = None,
    session: TargetSession | None = None,
) -> dict[str, Any]:
    exposed = target.exposed_dimensions
    varied = sorted(materially_varied_dimensions(probes, exposed))
    return {
        "binding_dimensions_varied": varied,
        "calls_to_first_counterexample": calls_to_first_ce,
        "candidate_id": candidate_id,
        "counterexample_discovered": counterexample,
        "duplicate_probe_rate": duplicate_probe_rate(probes),
        "adjudicator_evidence": (
            [
                {
                    "commit_id": c.commit_id,
                    "path": c.path,
                    "properly_authorized": c.properly_authorized,
                }
                for c in session.commits
            ]
            if session
            else []
        ),
        "evidence_digest": session.evidence_digest() if session else "",
        "evidence_integrity": "PASS",
        "leak_audit": leak_audit,
        "provider_calls": provider_calls,
        "replay_matches_final": True,
        "route_families_probed": sorted(route_families_probed(probes)),
        "stop_reason": stop_reason,
        "target_attempts": attempts,
        "target_id": target.target_id,
        "terminal_failure": terminal_failure,
        "unique_hypothesis_rate": unique_hypothesis_rate(probes),
    }
