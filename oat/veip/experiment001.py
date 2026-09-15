"""Bound Experiment 001 provider request and feedback construction."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Protocol

from oat.adversaries.provider import TransportError
from oat.canonical import canonical_bytes
from oat.veip.contracts import AdmissionError, WitnessContract, admit
from oat.veip.execution_path import (
    UNEVALUABLE_REASON_CATEGORIES,
    BudgetExhausted,
    BudgetLedger,
)
from oat.veip.falsifiers import evaluate
from oat.veip.orchestrator import (
    ATTEMPTS_PER_ANGLE,
    BASELINE_ANGLES,
    ROUNDS,
    parse_reply,
)
from oat.veip.prompt import SYSTEM_PROMPT, render
from oat.veip.subject import invoke as invoke_subject
from oat.veip.transport import (
    ENDPOINT,
    NvidiaSSETransport,
    TransportEvidence,
    canonical_request_body,
)

NVIDIA_MODEL: Final = "nvidia/nemotron-3-ultra-550b-a55b"
EXPERIMENT_SEED: Final = 20260915
MAX_TOKENS: Final = 4096


@dataclass(frozen=True)
class RenderedProviderRequest:
    """Exact frozen provider request plus independently recomputable bindings."""

    prompt_bytes: bytes
    prompt_digest: str
    body: dict[str, Any]
    body_bytes: bytes
    request_sha256: str
    feedback: tuple[dict[str, str], ...]


def feedback_for_round(
    history: list[dict[str, Any]],
    *,
    attack_id: str,
    round_number: int,
) -> list[dict[str, str]] | None:
    """Return only the frozen previous-round, same-angle feedback projection."""

    if round_number == 1:
        return None

    previous_round = round_number - 1
    projected: list[dict[str, str]] = []

    for record in history:
        if str(record.get("attack_id")) != attack_id:
            continue
        if int(record.get("round", -1)) != previous_round:
            continue

        disposition = str(record["disposition"])

        item = {
            "attempt": str(record["attempt"]),
            "disposition": disposition,
        }

        if disposition == "UNEVALUABLE":
            category = str(record.get("reason_category", "OTHER"))
            if category not in UNEVALUABLE_REASON_CATEGORIES:
                category = "OTHER"
            item["reason_category"] = category

        projected.append(item)

    projected.sort(key=lambda item: int(item["attempt"]))
    return projected


def render_provider_request(
    angle: dict[str, Any],
    falsifier: dict[str, Any],
    *,
    round_number: int,
    attempt_number: int,
    history: list[dict[str, Any]] | None = None,
) -> RenderedProviderRequest:
    """Render exactly one frozen Experiment 001 NVIDIA request.

    The canonical OAT prompt renderer remains the source of truth for prompt
    bytes and prompt digest. The combined prompt is then split at its frozen
    SYSTEM_PROMPT boundary into the two message roles required by the frozen
    NVIDIA request configuration.
    """

    feedback = feedback_for_round(
        history or [],
        attack_id=str(angle["attack_id"]),
        round_number=round_number,
    )

    prompt_bytes, prompt_digest = render(
        angle,
        falsifier,
        round_number=round_number,
        attempt_number=attempt_number,
        feedback=feedback,
    )

    prefix = f"{SYSTEM_PROMPT}\n\n".encode()

    if not prompt_bytes.startswith(prefix):
        raise AssertionError("frozen prompt renderer/system boundary changed")

    user_content = prompt_bytes[len(prefix) :].decode("utf-8")

    body: dict[str, Any] = {
        "model": NVIDIA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": user_content,
            },
        ],
        "temperature": 0.0,
        "top_p": 1.0,
        "max_tokens": MAX_TOKENS,
        "stream": True,
        "seed": EXPERIMENT_SEED,
    }

    body_bytes = canonical_request_body(body)

    return RenderedProviderRequest(
        prompt_bytes=prompt_bytes,
        prompt_digest=prompt_digest,
        body=body,
        body_bytes=body_bytes,
        request_sha256=hashlib.sha256(body_bytes).hexdigest(),
        feedback=tuple(feedback or []),
    )


def make_budgeted_transport(
    ledger: BudgetLedger,
    *,
    api_key_env: str = "NVIDIA_API_KEY",
    timeout: int = 120,
) -> NvidiaSSETransport:
    """Create the actual retry transport with pre-dispatch budget reservation."""

    return NvidiaSSETransport(
        api_key_env=api_key_env,
        timeout=timeout,
        before_provider_call=ledger.reserve_provider_call,
    )


@dataclass(frozen=True)
class AttemptMetadata:
    """Identity required to bind one Experiment 001 candidate attempt."""

    attack_id: str
    attack_family: str
    property_id: str
    falsifier_id: str
    target_components: tuple[str, ...]
    subject_identity: dict[str, str]
    round_number: int
    attempt_number: int
    adversary_config_digest: str
    capture_order_index: int


@dataclass(frozen=True)
class AttemptCaptureReceipt:
    """Write-once pre-verification capture identity."""

    path: str
    sha256: str
    record: dict[str, Any]


@dataclass(frozen=True)
class AttemptEvaluationReceipt:
    """Write-once evaluation record bound to a prior capture."""

    path: str
    sha256: str
    record: dict[str, Any]


class AttemptEvidenceRecorder:
    """Application-level write-once storage for Experiment 001 attempts."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _attack_tag(attack_id: str) -> str:
        return hashlib.sha256(attack_id.encode()).hexdigest()[:16]

    def _stem(self, metadata: AttemptMetadata) -> str:
        return (
            f"{self._attack_tag(metadata.attack_id)}"
            f"-r{metadata.round_number:02d}"
            f"-a{metadata.attempt_number:03d}"
        )

    @staticmethod
    def _write_once(path: Path, record: dict[str, Any]) -> str:
        payload = canonical_bytes(record)
        with path.open("xb") as handle:
            handle.write(payload)
        return hashlib.sha256(payload).hexdigest()

    def capture(
        self,
        metadata: AttemptMetadata,
        *,
        rendered: RenderedProviderRequest,
        raw_response: str,
        transport_evidence: dict[str, Any],
        ledger: BudgetLedger,
    ) -> AttemptCaptureReceipt:
        """Persist provider/model output before parsing, admission, or verification."""

        raw_bytes = raw_response.encode()

        record: dict[str, Any] = {
            "form": "oat-exp001-attempt-capture/1",
            "stage": "PRE_VERIFICATION_CAPTURE",
            "attack_id": metadata.attack_id,
            "attack_family": metadata.attack_family,
            "property_id": metadata.property_id,
            "falsifier_id": metadata.falsifier_id,
            "target_components": list(metadata.target_components),
            "subject_identity": dict(metadata.subject_identity),
            "round": metadata.round_number,
            "attempt": metadata.attempt_number,
            "capture_order_index": metadata.capture_order_index,
            "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            "provider": "NVIDIA",
            "endpoint": ENDPOINT,
            "model": NVIDIA_MODEL,
            "transport": "NvidiaSSETransport.complete_with_retries",
            "adversary_config_digest": metadata.adversary_config_digest,
            "prompt_digest": rendered.prompt_digest,
            "prompt_bytes_sha256": hashlib.sha256(rendered.prompt_bytes).hexdigest(),
            "request_sha256": rendered.request_sha256,
            "candidate_response_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "candidate_response_utf8": raw_response,
            "transport_evidence": transport_evidence,
            "budget_after_transport": ledger.to_dict(),
        }

        path = self.root / f"{self._stem(metadata)}.capture.json"
        digest = self._write_once(path, record)

        return AttemptCaptureReceipt(
            path=str(path),
            sha256=digest,
            record=record,
        )

    def append_evaluation(
        self,
        metadata: AttemptMetadata,
        *,
        capture: AttemptCaptureReceipt,
        record: dict[str, Any],
    ) -> AttemptEvaluationReceipt:
        """Append, never replace, evaluation evidence bound to a capture digest."""

        evaluation = {
            "form": "oat-exp001-attempt-evaluation/1",
            "attempt_capture_sha256": capture.sha256,
            **record,
        }

        path = self.root / f"{self._stem(metadata)}.evaluation.json"
        digest = self._write_once(path, evaluation)

        return AttemptEvaluationReceipt(
            path=str(path),
            sha256=digest,
            record=evaluation,
        )


InvokeFn = Callable[[str, dict[str, Any]], dict[str, Any]]
EvaluateFn = Callable[[str, dict[str, Any]], dict[str, Any]]


def _unevaluable_record(
    *,
    metadata: AttemptMetadata,
    category: str,
    internal_reason: str,
    ledger: BudgetLedger,
    parsed_reply: dict[str, Any] | None = None,
    admitted_candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if category not in UNEVALUABLE_REASON_CATEGORIES:
        category = "OTHER"

    return {
        "attack_id": metadata.attack_id,
        "round": metadata.round_number,
        "attempt": metadata.attempt_number,
        "disposition": "UNEVALUABLE",
        "reason_category": category,
        "internal_reason": internal_reason,
        "parsed_reply": parsed_reply,
        "admitted_candidate": admitted_candidate,
        "attempt_consumed": True,
        "budget_after_attempt": ledger.to_dict(),
    }


def capture_and_evaluate_attempt(
    *,
    metadata: AttemptMetadata,
    contract: WitnessContract,
    rendered: RenderedProviderRequest,
    raw_response: str,
    transport_evidence: dict[str, Any],
    ledger: BudgetLedger,
    recorder: AttemptEvidenceRecorder,
    invoke_fn: InvokeFn = invoke_subject,
    evaluate_fn: EvaluateFn = evaluate,
) -> tuple[AttemptCaptureReceipt, AttemptEvaluationReceipt]:
    """Capture first; only then parse, admit, invoke, and evaluate.

    A model response of any quality consumes exactly one logical adversarial
    attempt. Transport failures with no model response never enter this
    function and therefore consume no logical attempt.
    """

    capture = recorder.capture(
        metadata,
        rendered=rendered,
        raw_response=raw_response,
        transport_evidence=transport_evidence,
        ledger=ledger,
    )

    # The response now exists in write-once evidence. Only after this point may
    # it consume an adversarial attempt or reach parsing/verifier logic.
    ledger.consume_logical_attempt()

    try:
        reply = parse_reply(raw_response)
    except AdmissionError as exc:
        reason = str(exc)
        category = (
            "PROTOCOL_VIOLATION"
            if reason == "ADVERSARY_PROTOCOL_VIOLATION"
            else "RESPONSE_MALFORMED"
        )
        evaluation_record = _unevaluable_record(
            metadata=metadata,
            category=category,
            internal_reason=reason,
            ledger=ledger,
        )
        return capture, recorder.append_evaluation(
            metadata,
            capture=capture,
            record=evaluation_record,
        )

    try:
        candidate = admit(contract, reply["candidate_witness"])
    except (AdmissionError, KeyError, TypeError, ValueError) as exc:
        evaluation_record = _unevaluable_record(
            metadata=metadata,
            category="WITNESS_SCHEMA_INVALID",
            internal_reason=str(exc),
            ledger=ledger,
            parsed_reply=reply,
        )
        return capture, recorder.append_evaluation(
            metadata,
            capture=capture,
            record=evaluation_record,
        )

    try:
        trace = invoke_fn(metadata.falsifier_id, candidate["inputs"])
    except Exception as exc:
        evaluation_record = _unevaluable_record(
            metadata=metadata,
            category="SUBJECT_INVOCATION_FAILED",
            internal_reason=f"{type(exc).__name__}: {exc}",
            ledger=ledger,
            parsed_reply=reply,
            admitted_candidate=candidate,
        )
        return capture, recorder.append_evaluation(
            metadata,
            capture=capture,
            record=evaluation_record,
        )

    missing = [
        observable for observable in contract.required_observables if observable not in trace
    ]

    if missing:
        evaluation_record = _unevaluable_record(
            metadata=metadata,
            category="OBSERVABLE_MISSING",
            internal_reason="missing observables: " + ", ".join(missing),
            ledger=ledger,
            parsed_reply=reply,
            admitted_candidate=candidate,
        )
        evaluation_record["observable_trace"] = trace

        return capture, recorder.append_evaluation(
            metadata,
            capture=capture,
            record=evaluation_record,
        )

    result = evaluate_fn(metadata.falsifier_id, trace)

    if result.get("disposition") == "UNEVALUABLE":
        evaluation_record = _unevaluable_record(
            metadata=metadata,
            category="OTHER",
            internal_reason=str(result.get("reason", "UNEVALUABLE")),
            ledger=ledger,
            parsed_reply=reply,
            admitted_candidate=candidate,
        )
        evaluation_record["observable_trace"] = trace

        return capture, recorder.append_evaluation(
            metadata,
            capture=capture,
            record=evaluation_record,
        )

    evaluation_record = {
        "attack_id": metadata.attack_id,
        "round": metadata.round_number,
        "attempt": metadata.attempt_number,
        "disposition": str(result["disposition"]),
        "parsed_reply": reply,
        "admitted_candidate": candidate,
        "observable_trace": trace,
        "verifier_result": result,
        "attempt_consumed": True,
        "budget_after_attempt": ledger.to_dict(),
    }

    return capture, recorder.append_evaluation(
        metadata,
        capture=capture,
        record=evaluation_record,
    )


class RetryTransport(Protocol):
    """Structural contract used by the bounded execution path."""

    transport_failures: list[Any]

    def complete_with_retries(
        self,
        body: dict[str, Any],
    ) -> TransportEvidence: ...


@dataclass(frozen=True)
class AngleTerminalReceipt:
    path: str
    sha256: str
    record: dict[str, Any]


@dataclass(frozen=True)
class Experiment001RunResult:
    attempt_records: tuple[dict[str, Any], ...]
    angle_terminals: tuple[dict[str, Any], ...]
    budget: dict[str, int]
    execution_stopped: bool
    stop_reason: str | None
    run_summary_path: str
    run_summary_sha256: str


def _write_angle_terminal(
    recorder: AttemptEvidenceRecorder,
    *,
    angle: dict[str, Any],
    disposition: str,
    terminal_reason: str,
    ledger: BudgetLedger,
    attempts_completed: int,
    not_executed_due_to_upstream_stop: bool = False,
    transport_failures: list[dict[str, Any]] | None = None,
) -> AngleTerminalReceipt:
    record: dict[str, Any] = {
        "form": "oat-exp001-angle-terminal/1",
        "attack_id": str(angle["attack_id"]),
        "family": str(angle["family"]),
        "falsifier_id": str(angle["falsifier_id"]),
        "disposition": disposition,
        "terminal_reason": terminal_reason,
        "attempts_completed": attempts_completed,
        "not_executed_due_to_upstream_stop": (not_executed_due_to_upstream_stop),
        "budget": ledger.to_dict(),
        "transport_failures": transport_failures or [],
    }

    tag = recorder._attack_tag(str(angle["attack_id"]))
    terminal_path = recorder.root / f"{tag}.terminal.json"
    digest = recorder._write_once(terminal_path, record)

    return AngleTerminalReceipt(
        path=str(terminal_path),
        sha256=digest,
        record=record,
    )


def _transport_failure_slice(
    transport: RetryTransport,
    start_index: int,
) -> list[dict[str, Any]]:
    return [failure.to_dict() for failure in transport.transport_failures[start_index:]]


def _validate_baseline_inputs(
    angles: list[dict[str, Any]],
    contracts: dict[str, WitnessContract],
    falsifiers: dict[str, dict[str, Any]],
    *,
    seed_capability_verified: bool,
    adversary_config_digest: str,
    subject_identity: dict[str, str],
) -> None:
    if not seed_capability_verified:
        raise ValueError("seed capability must be verified before baseline execution")

    if len(angles) != BASELINE_ANGLES:
        raise ValueError(f"baseline requires exactly {BASELINE_ANGLES} angles")

    if any(bool(angle.get("holdout")) for angle in angles):
        raise ValueError("holdout material rejected by baseline firewall")

    attack_ids = [str(angle["attack_id"]) for angle in angles]
    if len(set(attack_ids)) != len(attack_ids):
        raise ValueError("baseline attack_id values must be unique")

    if not adversary_config_digest.startswith("sha256:"):
        raise ValueError("adversary configuration digest is not bound")

    if not subject_identity:
        raise ValueError("subject identity is not bound")

    for angle in angles:
        falsifier_id = str(angle["falsifier_id"])

        if falsifier_id not in contracts:
            raise ValueError(f"missing witness contract for {falsifier_id}")

        if falsifier_id not in falsifiers:
            raise ValueError(f"missing frozen falsifier entry for {falsifier_id}")


def run_experiment001_baseline(
    angles: list[dict[str, Any]],
    *,
    contracts: dict[str, WitnessContract],
    falsifiers: dict[str, dict[str, Any]],
    subject_identity: dict[str, str],
    adversary_config_digest: str,
    evidence_root: Path,
    seed_capability_verified: bool,
    ledger: BudgetLedger | None = None,
    transport_override: RetryTransport | None = None,
    invoke_fn: InvokeFn = invoke_subject,
    evaluate_fn: EvaluateFn = evaluate,
) -> Experiment001RunResult:
    """Run the frozen baseline with physical-call fail-closed semantics.

    ``transport_override`` exists for deterministic offline validation. The
    production path creates ``NvidiaSSETransport`` through
    ``make_budgeted_transport`` so every actual request and retry passes the
    same pre-dispatch physical-call/token reservation hook.
    """

    _validate_baseline_inputs(
        angles,
        contracts,
        falsifiers,
        seed_capability_verified=seed_capability_verified,
        adversary_config_digest=adversary_config_digest,
        subject_identity=subject_identity,
    )

    active_ledger = ledger if ledger is not None else BudgetLedger()

    transport: RetryTransport
    if transport_override is None:
        transport = make_budgeted_transport(active_ledger)
    else:
        transport = transport_override

    recorder = AttemptEvidenceRecorder(evidence_root)

    attempt_records: list[dict[str, Any]] = []
    terminal_records: list[dict[str, Any]] = []

    def attempts_for(attack_id: str) -> int:
        return sum(1 for item in attempt_records if item["attack_id"] == attack_id)

    def finalize(
        *,
        execution_stopped: bool,
        stop_reason: str | None,
    ) -> Experiment001RunResult:
        summary: dict[str, Any] = {
            "form": "oat-exp001-run-summary/1",
            "method_status": "METHOD_DEVELOPMENT_ONLY",
            "claim_bearing_use": "PROHIBITED",
            "baseline_angle_count": len(angles),
            "attempt_records": attempt_records,
            "angle_terminals": terminal_records,
            "budget": active_ledger.to_dict(),
            "execution_stopped": execution_stopped,
            "stop_reason": stop_reason,
            "seed_capability_verified": seed_capability_verified,
            "adversary_config_digest": adversary_config_digest,
            "subject_identity": dict(subject_identity),
        }

        summary_path = recorder.root / "run-summary.json"
        summary_sha256 = recorder._write_once(
            summary_path,
            summary,
        )

        return Experiment001RunResult(
            attempt_records=tuple(attempt_records),
            angle_terminals=tuple(terminal_records),
            budget=active_ledger.to_dict(),
            execution_stopped=execution_stopped,
            stop_reason=stop_reason,
            run_summary_path=str(summary_path),
            run_summary_sha256=summary_sha256,
        )

    def stop_current_and_remaining(
        angle_index: int,
        *,
        reason: str,
        current_transport_failures: list[dict[str, Any]] | None = None,
    ) -> Experiment001RunResult:
        for index in range(angle_index, len(angles)):
            angle = angles[index]
            attack_id = str(angle["attack_id"])

            receipt = _write_angle_terminal(
                recorder,
                angle=angle,
                disposition="COVERAGE_LIMITED",
                terminal_reason=reason,
                ledger=active_ledger,
                attempts_completed=attempts_for(attack_id),
                not_executed_due_to_upstream_stop=index > angle_index,
                transport_failures=(current_transport_failures if index == angle_index else []),
            )

            terminal_records.append(
                {
                    "attack_id": attack_id,
                    "disposition": "COVERAGE_LIMITED",
                    "terminal_reason": reason,
                    "receipt_sha256": receipt.sha256,
                    "receipt_path": receipt.path,
                    "not_executed_due_to_upstream_stop": (index > angle_index),
                }
            )

        return finalize(
            execution_stopped=True,
            stop_reason=reason,
        )

    for angle_index, angle in enumerate(angles):
        attack_id = str(angle["attack_id"])
        falsifier_id = str(angle["falsifier_id"])
        contract = contracts[falsifier_id]
        falsifier = falsifiers[falsifier_id]

        angle_history: list[dict[str, Any]] = []
        counterexample_found = False

        for round_number in range(1, ROUNDS + 1):
            for attempt_number in range(1, ATTEMPTS_PER_ANGLE + 1):
                rendered = render_provider_request(
                    angle,
                    falsifier,
                    round_number=round_number,
                    attempt_number=attempt_number,
                    history=angle_history,
                )

                failure_start = len(transport.transport_failures)

                try:
                    transport_evidence = transport.complete_with_retries(rendered.body)
                except BudgetExhausted:
                    failures = _transport_failure_slice(
                        transport,
                        failure_start,
                    )
                    return stop_current_and_remaining(
                        angle_index,
                        reason="PHYSICAL_PROVIDER_BUDGET_EXHAUSTED",
                        current_transport_failures=failures,
                    )
                except TransportError as exc:
                    failures = _transport_failure_slice(
                        transport,
                        failure_start,
                    )

                    reason = (
                        "LOCAL_RUNTIME_PRECONDITION_FAILED"
                        if str(exc).startswith("missing runtime secret")
                        else "PROVIDER_TRANSPORT_EXHAUSTED"
                    )

                    return stop_current_and_remaining(
                        angle_index,
                        reason=reason,
                        current_transport_failures=failures,
                    )

                retry_failures = _transport_failure_slice(
                    transport,
                    failure_start,
                )

                if transport_evidence.request_sha256 != rendered.request_sha256:
                    raise AssertionError("transport/request SHA-256 binding mismatch")

                metadata = AttemptMetadata(
                    attack_id=attack_id,
                    attack_family=str(angle["family"]),
                    property_id=str(falsifier["property_id"]),
                    falsifier_id=falsifier_id,
                    target_components=tuple(
                        str(x)
                        for x in angle.get(
                            "target_components",
                            [],
                        )
                    ),
                    subject_identity=dict(subject_identity),
                    round_number=round_number,
                    attempt_number=attempt_number,
                    adversary_config_digest=adversary_config_digest,
                    capture_order_index=(active_ledger.logical_adversarial_attempts + 1),
                )

                bundled_transport_evidence = {
                    "successful_response": (transport_evidence.to_dict()),
                    "retry_failures": retry_failures,
                }

                if transport_evidence.returned_model != NVIDIA_MODEL:
                    capture = recorder.capture(
                        metadata,
                        rendered=rendered,
                        raw_response=(transport_evidence.reconstructed_content),
                        transport_evidence=(bundled_transport_evidence),
                        ledger=active_ledger,
                    )

                    active_ledger.consume_logical_attempt()

                    evaluation = recorder.append_evaluation(
                        metadata,
                        capture=capture,
                        record=_unevaluable_record(
                            metadata=metadata,
                            category="OTHER",
                            internal_reason=("PROVIDER_MODEL_IDENTITY_MISMATCH"),
                            ledger=active_ledger,
                        ),
                    )

                    angle_history.append(evaluation.record)

                    attempt_records.append(
                        {
                            "attack_id": attack_id,
                            "round": round_number,
                            "attempt": attempt_number,
                            "disposition": "UNEVALUABLE",
                            "reason_category": "OTHER",
                            "capture_sha256": capture.sha256,
                            "evaluation_sha256": evaluation.sha256,
                        }
                    )

                    return stop_current_and_remaining(
                        angle_index,
                        reason="PROVIDER_MODEL_IDENTITY_MISMATCH",
                    )

                capture, evaluation = capture_and_evaluate_attempt(
                    metadata=metadata,
                    contract=contract,
                    rendered=rendered,
                    raw_response=(transport_evidence.reconstructed_content),
                    transport_evidence=bundled_transport_evidence,
                    ledger=active_ledger,
                    recorder=recorder,
                    invoke_fn=invoke_fn,
                    evaluate_fn=evaluate_fn,
                )

                angle_history.append(evaluation.record)

                summary_record: dict[str, Any] = {
                    "attack_id": attack_id,
                    "round": round_number,
                    "attempt": attempt_number,
                    "disposition": str(evaluation.record["disposition"]),
                    "capture_sha256": capture.sha256,
                    "evaluation_sha256": evaluation.sha256,
                }

                if "reason_category" in evaluation.record:
                    summary_record["reason_category"] = str(evaluation.record["reason_category"])

                attempt_records.append(summary_record)

                if evaluation.record["disposition"] == "COUNTEREXAMPLE_VALIDATED":
                    terminal = _write_angle_terminal(
                        recorder,
                        angle=angle,
                        disposition="COUNTEREXAMPLE_VALIDATED",
                        terminal_reason=("FIRST_COUNTEREXAMPLE_VALIDATED"),
                        ledger=active_ledger,
                        attempts_completed=attempts_for(attack_id),
                    )

                    terminal_records.append(
                        {
                            "attack_id": attack_id,
                            "disposition": ("COUNTEREXAMPLE_VALIDATED"),
                            "terminal_reason": ("FIRST_COUNTEREXAMPLE_VALIDATED"),
                            "receipt_sha256": terminal.sha256,
                            "receipt_path": terminal.path,
                            "not_executed_due_to_upstream_stop": False,
                        }
                    )

                    counterexample_found = True
                    break

            if counterexample_found:
                break

        if counterexample_found:
            continue

        terminal = _write_angle_terminal(
            recorder,
            angle=angle,
            disposition="COVERAGE_LIMITED",
            terminal_reason="PLANNED_ANGLE_DEPTH_EXHAUSTED",
            ledger=active_ledger,
            attempts_completed=attempts_for(attack_id),
        )

        terminal_records.append(
            {
                "attack_id": attack_id,
                "disposition": "COVERAGE_LIMITED",
                "terminal_reason": "PLANNED_ANGLE_DEPTH_EXHAUSTED",
                "receipt_sha256": terminal.sha256,
                "receipt_path": terminal.path,
                "not_executed_due_to_upstream_stop": False,
            }
        )

    return finalize(
        execution_stopped=False,
        stop_reason=None,
    )
