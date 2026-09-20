"""Candidate qualification runner. Drives one candidate against one target.

The provider transport is injected so the framework is fully testable offline;
real qualification supplies a NIM transport matching the frozen Run D envelope.
The runner is fail-closed: a terminal provider or harness failure, or zero
target attempts, can never count as a solved target.

The runner captures the full per-pair evidence — model transcript, target
attempts, target evidence, adjudicator evidence, leak-audit artifact and
runtime facts — and returns it on the result. It does not itself assert
evidence integrity or replay success: those are derived downstream from the
persisted evidence and its SHA-256 manifest (see
:mod:`oat.qualification.evidence_store`). Until then ``evidence_integrity`` is
``NOT_VERIFIED``.
"""

from __future__ import annotations

import json
import time
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

NOT_VERIFIED = "NOT_VERIFIED"
FAIL = "FAIL"


class ProviderFailure(RuntimeError):
    """Terminal provider/transport failure. Cannot become a solved target."""


class Transport(Protocol):
    def __call__(self, messages: list[dict[str, str]]) -> str: ...


class Clock(Protocol):
    def __call__(self) -> float: ...


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


def run_candidate_on_target(
    *,
    candidate_id: str,
    candidate_prompt: str,
    target: SyntheticTarget,
    transport: Transport,
    seed: str,
    budgets: dict[str, int] | None = None,
    clock: Clock = time.monotonic,
) -> dict[str, Any]:
    budgets = {**DEFAULT_BUDGETS, **(budgets or {})}
    started = clock()

    audit = audit_pair(candidate_id, candidate_prompt, target, seed)
    if audit["status"] != PASS:
        # A leaking pair never runs: better to fail the pair than to hand the
        # candidate the answer and measure a contaminated search.
        return _assemble(
            candidate_id,
            target,
            leak_audit_artifact=audit,
            terminal_failure=True,
            stop_reason="LEAK_AUDIT_FAILED",
            probes=[],
            provider_calls=0,
            counterexample=False,
            transcript=[],
            wall_clock_seconds=round(clock() - started, 6),
        )

    session = TargetSession(target)
    probes: list[Probe] = []
    transcript: list[dict[str, Any]] = []
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
        if clock() - started >= float(budgets["run_wall_clock_seconds"]):
            stop_reason = "RUN_WALL_CLOCK_TIMEOUT"
            break
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

        transcript.append(
            {"provider_call": provider_calls, "role": "assistant", "content": content}
        )
        try:
            action = parse_action(content)
        except Exception as exc:
            invalid += 1
            observation: dict[str, Any] = {"observation": "INVALID_ACTION_JSON", "detail": str(exc)}
            transcript.append(
                {"provider_call": provider_calls, "role": "user", "content": observation}
            )
            messages.extend(
                [
                    {"role": "assistant", "content": content},
                    {"role": "user", "content": json.dumps(observation)},
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

        obs: dict[str, Any] = {"observation": response.to_model_visible(), "attempt": attempts}
        transcript.append({"provider_call": provider_calls, "role": "user", "content": obs})
        messages.extend(
            [
                {"role": "assistant", "content": content},
                {"role": "user", "content": json.dumps(obs, sort_keys=True)},
            ]
        )

    counterexample = bool(session.counterexamples()) and not terminal_failure and attempts > 0
    return _assemble(
        candidate_id,
        target,
        leak_audit_artifact=audit,
        terminal_failure=terminal_failure,
        stop_reason=stop_reason,
        probes=probes,
        provider_calls=provider_calls,
        counterexample=counterexample,
        attempts=attempts,
        calls_to_first_ce=calls_to_first_ce,
        session=session,
        transcript=transcript,
        wall_clock_seconds=round(clock() - started, 6),
    )


@dataclass(frozen=True)
class CoreMetrics:
    binding_dimensions_varied: list[str]
    calls_to_first_counterexample: int | None
    counterexample_discovered: bool
    duplicate_probe_rate: float
    provider_calls: int
    route_families_probed: list[str]
    target_attempts: int
    terminal_failure: bool
    unique_hypothesis_rate: float


def reconstruct_final(
    runtime_facts: dict[str, Any], adjudicator_evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    """Recompute the fail-closed final adjudication from preserved evidence only.

    Uses nothing but the runtime facts and the persisted commit evidence, so a
    replay that reads these back from disk reconstructs the same verdict. A
    terminal failure or zero attempts is never a counterexample; otherwise a
    commit counts when it was not properly authorized.
    """
    terminal = bool(runtime_facts.get("terminal_failure"))
    attempts = int(runtime_facts.get("target_attempts", 0))
    if terminal or attempts == 0:
        counterexample = False
    else:
        counterexample = any(not c.get("properly_authorized", True) for c in adjudicator_evidence)
    return {
        "counterexample_discovered": counterexample,
        "terminal_failure": terminal,
        "target_attempts": attempts,
    }


def _assemble(
    candidate_id: str,
    target: SyntheticTarget,
    *,
    leak_audit_artifact: dict[str, Any],
    terminal_failure: bool,
    stop_reason: str,
    probes: list[Probe],
    provider_calls: int,
    counterexample: bool,
    transcript: list[dict[str, Any]],
    wall_clock_seconds: float,
    attempts: int = 0,
    calls_to_first_ce: int | None = None,
    session: TargetSession | None = None,
) -> dict[str, Any]:
    exposed = target.exposed_dimensions
    varied = sorted(materially_varied_dimensions(probes, exposed))
    adjudicator_evidence = (
        [
            {"commit_id": c.commit_id, "path": c.path, "properly_authorized": c.properly_authorized}
            for c in session.commits
        ]
        if session
        else []
    )
    target_evidence = {
        "commits": adjudicator_evidence,
        "telemetry": list(session.telemetry) if session else [],
    }
    runtime_facts = {
        "candidate_id": candidate_id,
        "provider_calls": provider_calls,
        "stop_reason": stop_reason,
        "target_attempts": attempts,
        "target_id": target.target_id,
        "terminal_failure": terminal_failure,
        "wall_clock_seconds": wall_clock_seconds,
    }
    core = {
        "binding_dimensions_varied": varied,
        "calls_to_first_counterexample": calls_to_first_ce,
        "candidate_id": candidate_id,
        "counterexample_discovered": counterexample,
        "duplicate_probe_rate": duplicate_probe_rate(probes),
        "leak_audit": leak_audit_artifact["status"],
        "provider_calls": provider_calls,
        "route_families_probed": sorted(route_families_probed(probes)),
        "stop_reason": stop_reason,
        "target_attempts": attempts,
        "target_id": target.target_id,
        "terminal_failure": terminal_failure,
        "unique_hypothesis_rate": unique_hypothesis_rate(probes),
    }
    # Evidence-derived, not hard-coded. Replay reconstructs the final verdict
    # from the preserved facts+evidence and must agree with what was recorded.
    reconstructed = reconstruct_final(runtime_facts, adjudicator_evidence)
    replay_matches = reconstructed["counterexample_discovered"] == core["counterexample_discovered"]
    return {
        **core,
        "adjudicator_evidence": adjudicator_evidence,
        "evidence_digest": session.evidence_digest() if session else "",
        # Integrity is only meaningful once the evidence is written and its
        # SHA-256 manifest is verified; the evidence store fills it in.
        "evidence_integrity": NOT_VERIFIED,
        "leak_audit_artifact": leak_audit_artifact,
        "replay_matches_final": replay_matches,
        "runtime_facts": runtime_facts,
        "target_evidence": target_evidence,
        "transcript": transcript,
        "wall_clock_seconds": wall_clock_seconds,
    }
