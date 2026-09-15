"""V1 — the deterministic OAT verifier.

V1 recomputes everything it reports. It does not trust the adversary's claimed
evaluation, the witness's self-description, or any narrative attached to a run.
No narrative interpretation may alter the computational result.
"""

from __future__ import annotations

from typing import Any

from oat import CLAIM_BEARING_USE, CLAIM_CEILING, RUN_MODE
from oat.canonical import CANONICAL_FORM
from oat.digest import digest_object
from oat.falsifiers import rb001 as rb001_falsifier
from oat.manifest import runtime_metadata, validate

VERIFIER_ID: str = "OAT-V1"
VERIFIER_VERSION: str = "0.1.0"

DISPOSITION_COUNTEREXAMPLE: str = "COUNTEREXAMPLE_CONFIRMED"
DISPOSITION_NO_COUNTEREXAMPLE: str = "NO_COUNTEREXAMPLE"
DISPOSITION_REJECTED: str = "REJECTED"

REJECT_SCHEMA_INVALID: str = "WITNESS_SCHEMA_INVALID"
REJECT_MANIFEST_BINDING: str = "MANIFEST_BINDING_MISMATCH"
REJECT_SCENARIO_IDENTITY: str = "SCENARIO_IDENTITY_MISMATCH"
REJECT_TAMPERED_BYTES: str = "CANONICAL_BYTES_TAMPERED"
REJECT_FALSIFIER_UNSUPPORTED: str = "FALSIFIER_VERSION_UNSUPPORTED"
REJECT_FALSIFIER_IDENTITY: str = "FALSIFIER_IDENTITY_MISMATCH"
REJECT_CLAIM_MISMATCH: str = "CLAIMED_EVALUATION_MISMATCH"
REJECT_UNEVALUABLE: str = "TRACE_NOT_EVALUABLE"


def identity() -> dict[str, str]:
    """Machine-readable verifier identity."""
    return {"id": VERIFIER_ID, "version": VERIFIER_VERSION}


def _result(
    disposition: str,
    witness: dict[str, Any],
    *,
    rejection_reason: str | None = None,
    detail: list[str] | None = None,
    predicate_trace: list[dict[str, Any]] | None = None,
    computational_result: bool | None = None,
) -> dict[str, Any]:
    evidence = {
        "canonical_form": CANONICAL_FORM,
        "run_mode": RUN_MODE,
        "claim_bearing_use": CLAIM_BEARING_USE,
        "claim_ceiling": CLAIM_CEILING,
        "scenario_id": str(witness.get("scenario_id", "")),
        "boundary_id": str(witness.get("boundary_id", "")),
        "manifest_digest": str(witness.get("manifest_digest", "")),
        "witness_digest": digest_object(witness),
        "falsifier": witness.get("falsifier", {}),
        "verifier": identity(),
        "disposition": disposition,
        "rejection_reason": rejection_reason,
        "predicate_trace": predicate_trace or [],
        "computational_result": computational_result,
    }
    return {
        "result_form": "oat-verifier-result/1",
        **evidence,
        "detail": detail or [],
        "evidence_digest": digest_object(evidence),
        "runtime": runtime_metadata(),
    }


def verify(
    witness: dict[str, Any],
    expected_manifest: dict[str, Any] | None = None,
    expected_scenario_id: str | None = None,
) -> dict[str, Any]:
    """Verify a candidate witness and return a verifier result.

    ``expected_manifest`` and ``expected_scenario_id`` are the frozen identities
    the witness claims to be bound to. When supplied, a mismatch is a rejection,
    not a warning.
    """
    schema_errors = validate(witness, "witness")
    if schema_errors:
        return _result(
            DISPOSITION_REJECTED,
            witness,
            rejection_reason=REJECT_SCHEMA_INVALID,
            detail=schema_errors,
        )

    falsifier_claim = dict(witness["falsifier"])
    if str(falsifier_claim.get("version", "")) not in rb001_falsifier.SUPPORTED_VERSIONS:
        return _result(
            DISPOSITION_REJECTED,
            witness,
            rejection_reason=REJECT_FALSIFIER_UNSUPPORTED,
            detail=[f"unsupported falsifier version: {falsifier_claim.get('version')!r}"],
        )

    local_falsifier = rb001_falsifier.identity()
    if falsifier_claim != local_falsifier:
        return _result(
            DISPOSITION_REJECTED,
            witness,
            rejection_reason=REJECT_FALSIFIER_IDENTITY,
            detail=[f"witness falsifier {falsifier_claim} != local {local_falsifier}"],
        )

    if expected_manifest is not None:
        expected_digest = digest_object(expected_manifest)
        if str(witness["manifest_digest"]) != expected_digest:
            return _result(
                DISPOSITION_REJECTED,
                witness,
                rejection_reason=REJECT_MANIFEST_BINDING,
                detail=[f"bound {witness['manifest_digest']} != manifest {expected_digest}"],
            )

    target = expected_scenario_id
    if target is None and expected_manifest is not None:
        target = str(expected_manifest["scenario"]["id"])
    if target is not None and str(witness["scenario_id"]) != target:
        return _result(
            DISPOSITION_REJECTED,
            witness,
            rejection_reason=REJECT_SCENARIO_IDENTITY,
            detail=[f"witness scenario {witness['scenario_id']!r} != target {target!r}"],
        )

    trace = witness["trace"]
    # Defense in depth: today the witness schema $refs the trace schema, so an
    # invalid trace is already rejected above. Kept so the verifier does not
    # depend on that composition holding in a future schema revision.
    trace_errors = validate(trace, "observable-trace")
    if trace_errors:  # pragma: no cover - unreachable while the $ref composition holds
        return _result(
            DISPOSITION_REJECTED,
            witness,
            rejection_reason=REJECT_SCHEMA_INVALID,
            detail=trace_errors,
        )
    if digest_object(trace) != str(witness["trace_digest"]):
        return _result(
            DISPOSITION_REJECTED,
            witness,
            rejection_reason=REJECT_TAMPERED_BYTES,
            detail=["recomputed trace digest does not match the witness-bound digest"],
        )
    if str(trace.get("scenario_id", "")) != str(witness["scenario_id"]):
        return _result(
            DISPOSITION_REJECTED,
            witness,
            rejection_reason=REJECT_SCENARIO_IDENTITY,
            detail=["trace scenario identity does not match witness scenario identity"],
        )

    try:
        evaluation = rb001_falsifier.evaluate(trace)
    except rb001_falsifier.FalsifierError as exc:
        return _result(
            DISPOSITION_REJECTED,
            witness,
            rejection_reason=REJECT_UNEVALUABLE,
            detail=[str(exc)],
        )

    claimed = witness.get("claimed_evaluation", {})
    if bool(claimed.get("counterexample")) != bool(evaluation["counterexample"]):
        return _result(
            DISPOSITION_REJECTED,
            witness,
            rejection_reason=REJECT_CLAIM_MISMATCH,
            detail=["adversary claim contradicts recomputed falsifier result"],
            predicate_trace=evaluation["predicate_trace"],
            computational_result=bool(evaluation["counterexample"]),
        )

    counterexample = bool(evaluation["counterexample"])
    return _result(
        DISPOSITION_COUNTEREXAMPLE if counterexample else DISPOSITION_NO_COUNTEREXAMPLE,
        witness,
        predicate_trace=evaluation["predicate_trace"],
        computational_result=counterexample,
    )
