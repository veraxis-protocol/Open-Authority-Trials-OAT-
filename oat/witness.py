"""Candidate witness construction.

A witness is the machine-readable state needed to evaluate the prohibited
consequence with no prose judgment. It carries the adversary's *claimed*
evaluation, which the verifier recomputes rather than trusts.
"""

from __future__ import annotations

from typing import Any

from oat import CLAIM_BEARING_USE, RUN_MODE
from oat.canonical import CANONICAL_FORM
from oat.digest import digest_object
from oat.reference_boundaries.rb001 import Variation


def build_witness(
    run_manifest: dict[str, Any],
    trace: dict[str, Any],
    claimed_evaluation: dict[str, Any],
    adversary_identity: dict[str, Any],
    transcript: list[dict[str, Any]],
    selected_candidate_index: int,
) -> dict[str, Any]:
    """Assemble a candidate witness bound to ``run_manifest``."""
    return {
        "witness_form": "oat-witness/1",
        "canonical_form": CANONICAL_FORM,
        "run_mode": RUN_MODE,
        "claim_bearing_use": CLAIM_BEARING_USE,
        "scenario_id": str(run_manifest["scenario"]["id"]),
        "boundary_id": str(run_manifest["boundary"]["id"]),
        "manifest_digest": digest_object(run_manifest),
        "falsifier": dict(run_manifest["falsifier"]),
        "adversary": dict(adversary_identity),
        "search": {
            "candidates_explored": len(transcript),
            "selected_candidate_index": selected_candidate_index,
            "transcript": list(transcript),
        },
        "trace": trace,
        "trace_digest": digest_object(trace),
        "claimed_evaluation": claimed_evaluation,
    }


def witness_digest(witness: dict[str, Any]) -> str:
    """Digest of a witness's canonical bytes."""
    return digest_object(witness)


def variation_of(witness: dict[str, Any]) -> Variation:
    """Recover the variation a witness was produced under."""
    data = witness["trace"]["variation"]
    return Variation(
        check_tick=int(data["check_tick"]),
        revocation_tick=int(data["revocation_tick"]),
        commit_tick=int(data["commit_tick"]),
        propagation_delay=int(data["propagation_delay"]),
        retry_index=int(data["retry_index"]),
        duplicate_request=bool(data["duplicate_request"]),
    )
