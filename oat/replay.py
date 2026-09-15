"""Deterministic replay.

Replay re-derives a run from its frozen package *without the adversary*: the
recorded variation is re-executed, the falsifier is re-evaluated, and V1 runs
again. Two consecutive replays of one frozen run must produce byte-identical
canonical result material and the same SHA-256 evidence digest.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oat import CLAIM_BEARING_USE, RUN_MODE
from oat.canonical import canonical_bytes
from oat.digest import digest_object
from oat.falsifiers import rb001 as rb001_falsifier
from oat.manifest import load_scenario_package, read_json, runtime_metadata, write_json
from oat.reference_boundaries import rb001
from oat.verifier import v1
from oat.witness import build_witness, variation_of


class ReplayError(ValueError):
    """Raised when a run package cannot be replayed."""


def _scenario_source(run_manifest: dict[str, Any], run_dir: Path) -> Path:
    source = run_manifest.get("runtime", {}).get("scenario_source")
    if source:
        candidate = Path(str(source))
        if candidate.is_file():
            return candidate
    name = str(run_manifest["scenario"]["name"])
    fallback = Path("scenarios") / "rb001" / name
    if fallback.is_file():
        return fallback
    raise ReplayError(f"cannot locate scenario source {name!r} for run {run_dir.as_posix()}")


def replay_run(run_dir: str | Path, write: bool = False) -> dict[str, Any]:
    """Replay a frozen run package and report whether it reproduces exactly."""
    directory = Path(run_dir)
    run_manifest = read_json(directory / "manifest.json")
    recorded_witness = read_json(directory / "witness.json")
    recorded_result = read_json(directory / "verifier-result.json")

    package = load_scenario_package(_scenario_source(run_manifest, directory))
    variation = variation_of(recorded_witness)

    trace = rb001.execute(package.scenario, variation)
    evaluation = rb001_falsifier.evaluate(trace)
    witness = build_witness(
        run_manifest,
        trace,
        evaluation,
        dict(recorded_witness["adversary"]),
        list(recorded_witness["search"]["transcript"]),
        int(recorded_witness["search"]["selected_candidate_index"]),
    )
    result = v1.verify(witness, expected_manifest=run_manifest)

    trace_match = digest_object(trace) == str(recorded_witness["trace_digest"])
    witness_match = digest_object(witness) == digest_object(recorded_witness)
    evidence_match = str(result["evidence_digest"]) == str(recorded_result["evidence_digest"])
    disposition_match = str(result["disposition"]) == str(recorded_result["disposition"])

    replay_result = {
        "replay_form": "oat-replay-result/1",
        "run_mode": RUN_MODE,
        "claim_bearing_use": CLAIM_BEARING_USE,
        "scenario_id": str(run_manifest["scenario"]["id"]),
        "adversary_used": False,
        "recorded_trace_digest": str(recorded_witness["trace_digest"]),
        "recomputed_trace_digest": digest_object(trace),
        "trace_match": trace_match,
        "witness_match": witness_match,
        "recorded_evidence_digest": str(recorded_result["evidence_digest"]),
        "recomputed_evidence_digest": str(result["evidence_digest"]),
        "evidence_digest_match": evidence_match,
        "recorded_disposition": str(recorded_result["disposition"]),
        "disposition": str(result["disposition"]),
        "disposition_match": disposition_match,
        "canonical_result_digest": digest_object(
            {
                "disposition": result["disposition"],
                "computational_result": result["computational_result"],
                "evidence_digest": result["evidence_digest"],
                "predicate_trace": result["predicate_trace"],
            }
        ),
        "replay_ok": trace_match and witness_match and evidence_match and disposition_match,
        "runtime": runtime_metadata(),
    }
    if write:
        write_json(directory / "replay-result.json", replay_result)
    return replay_result


def canonical_replay_bytes(replay_result: dict[str, Any]) -> bytes:
    """Canonical bytes of a replay result, runtime metadata excluded."""
    return canonical_bytes(replay_result)
