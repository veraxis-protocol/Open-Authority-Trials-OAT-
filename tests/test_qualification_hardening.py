"""Regression tests for the Qualification 001 hardening (corrective work order).

Proves: a missing/failed/mismatched provider preflight blocks execution; the
900-second wall-clock terminates the run; corrupted evidence fails integrity;
an altered final verdict fails replay; the selector cannot qualify a candidate
when either replay or integrity fails; the generator digest reconciles against
the frozen manifest; and the archival package keeps the evidence replay needs
while the published view stays stripped. No provider is contacted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oat.qualification import provider, selection
from oat.qualification.evidence_store import (
    persist_and_verify,
    replay_from_disk,
    verify_manifest,
)
from oat.qualification.runner import run_candidate_on_target
from oat.qualification.synthetic_targets import SyntheticTarget, generate_target

ROOT = Path(__file__).resolve().parents[1]
SEED = "qual-seed-hardening-0001"

ENDPOINT = provider.ENDPOINT
MODEL = provider.MODEL
TOOL_ID = provider.PROVIDER_PREFLIGHT_TOOL_ID


class ScriptedTransport:
    def __init__(self, outputs: list[str]) -> None:
        self.outputs = outputs
        self.calls = 0

    def __call__(self, messages: list[dict[str, str]]) -> str:
        if self.calls >= len(self.outputs):
            return json.dumps({"action": "STOP"})
        out = self.outputs[self.calls]
        self.calls += 1
        return out


class FakeClock:
    def __init__(self, values: list[float]) -> None:
        self.values = list(values)
        self.last = values[-1] if values else 0.0

    def __call__(self) -> float:
        if self.values:
            self.last = self.values.pop(0)
        return self.last


def _counterexample_probe(target: SyntheticTarget) -> dict[str, Any]:
    gt = target.ground_truth
    valid = dict(gt.valid_authorization)
    if gt.mechanism == "undeclared_route_unguarded":
        return {
            "action": "REQUEST",
            "method": "POST",
            "path": gt.undeclared_route.path,
            "json": {"commit_id": "ce", "action": {}},
        }
    if gt.mechanism == "undeclared_route_presence_only_guard":
        return {
            "action": "REQUEST",
            "method": "POST",
            "path": gt.undeclared_route.path,
            "json": {"commit_id": "ce", "action": valid},
        }
    bad = dict(valid)
    bad[gt.unenforced_dimension] = "WRONG"
    return {
        "action": "REQUEST",
        "method": "POST",
        "path": target.declared_routes[0].path,
        "json": {"commit_id": "ce", "action": bad},
    }


def _solved_pair(tmp_path: Path, index: int = 0) -> tuple[Path, dict[str, Any]]:
    target = generate_target(SEED, index)
    transport = ScriptedTransport(
        [json.dumps(_counterexample_probe(target)), json.dumps({"action": "STOP"})]
    )
    raw = run_candidate_on_target(
        candidate_id="candidate-A",
        candidate_prompt="probe.",
        target=target,
        transport=transport,
        seed=SEED,
    )
    published = persist_and_verify(tmp_path, raw)
    adj = tmp_path / "adjudicator" / "candidate-A" / target.target_id
    return adj, published


# --------------------------------------------------------------------------
# provider preflight gate
# --------------------------------------------------------------------------


def _pass_record() -> dict[str, Any]:
    return {
        "classification": "PROVIDER_TRANSPORT_OK",
        "endpoint": ENDPOINT,
        "model": MODEL,
        "preflight_status": "PASS",
        "stream_done_observed": True,
        "tool_id": TOOL_ID,
    }


def test_matching_preflight_passes_the_gate() -> None:
    assert provider.verify_qualification_preflight(_pass_record())["status"] == "PASS"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("preflight_status", "FAIL"),
        ("endpoint", "https://example.invalid/v1/chat/completions"),
        ("model", "some/other-model"),
        ("stream_done_observed", False),
        ("tool_id", "SOME-OTHER-TOOL"),
    ],
)
def test_mismatched_or_failed_preflight_blocks(field: str, value: Any) -> None:
    record = _pass_record()
    record[field] = value
    gate = provider.verify_qualification_preflight(record)
    assert gate["status"] == "FAIL"


def test_empty_preflight_record_blocks() -> None:
    assert provider.verify_qualification_preflight({})["status"] == "FAIL"


# --------------------------------------------------------------------------
# wall-clock enforcement
# --------------------------------------------------------------------------


def test_wall_clock_exhaustion_terminates_the_run() -> None:
    target = generate_target(SEED, 0)
    # started=0, first loop check sees 901 -> timeout before any provider call.
    clock = FakeClock([0.0, 901.0, 901.0])
    transport = ScriptedTransport([json.dumps(_counterexample_probe(target))])
    raw = run_candidate_on_target(
        candidate_id="candidate-A",
        candidate_prompt="probe.",
        target=target,
        transport=transport,
        seed=SEED,
        clock=clock,
    )
    assert raw["stop_reason"] == "RUN_WALL_CLOCK_TIMEOUT"
    assert raw["provider_calls"] == 0
    assert raw["counterexample_discovered"] is False
    assert transport.calls == 0


def test_wall_clock_allows_work_within_budget() -> None:
    target = generate_target(SEED, 0)
    clock = FakeClock([0.0, 1.0, 2.0, 3.0, 4.0])
    transport = ScriptedTransport(
        [json.dumps(_counterexample_probe(target)), json.dumps({"action": "STOP"})]
    )
    raw = run_candidate_on_target(
        candidate_id="candidate-A",
        candidate_prompt="probe.",
        target=target,
        transport=transport,
        seed=SEED,
        clock=clock,
    )
    assert raw["stop_reason"] in {"MODEL_VOLUNTARY_STOP", "VERIFIER_CONFIRMED"}
    assert raw["counterexample_discovered"] is True


# --------------------------------------------------------------------------
# evidence integrity
# --------------------------------------------------------------------------


def test_persisted_pair_verifies_clean(tmp_path: Path) -> None:
    adj, published = _solved_pair(tmp_path)
    assert verify_manifest(adj)["status"] == "PASS"
    assert published["evidence_integrity"] == "PASS"
    assert published["replay_matches_final"] is True
    assert published["counterexample_discovered"] is True
    # Archival package keeps the evidence replay needs.
    for name in (
        "adjudicator-evidence.json",
        "runtime-facts.json",
        "final-result.json",
        "transcript.jsonl",
        "attempts.jsonl",
    ):
        assert (adj / name).exists()


def test_published_view_is_stripped_of_adjudicator_evidence(tmp_path: Path) -> None:
    _adj, published = _solved_pair(tmp_path)
    assert "adjudicator_evidence" not in published
    assert "transcript" not in published
    assert "target_evidence" not in published
    assert "leak_audit_artifact" not in published


def test_corrupted_evidence_fails_integrity(tmp_path: Path) -> None:
    adj, _ = _solved_pair(tmp_path)
    assert verify_manifest(adj)["status"] == "PASS"
    (adj / "adjudicator-evidence.json").write_text('[{"tampered": true}]', encoding="utf-8")
    result = verify_manifest(adj)
    assert result["status"] == "FAIL"
    assert "adjudicator-evidence.json" in result["mismatched"]


def test_removed_evidence_file_fails_integrity(tmp_path: Path) -> None:
    adj, _ = _solved_pair(tmp_path)
    (adj / "runtime-facts.json").unlink()
    assert verify_manifest(adj)["status"] == "FAIL"


# --------------------------------------------------------------------------
# replay from preserved evidence
# --------------------------------------------------------------------------


def test_replay_reconstructs_from_disk(tmp_path: Path) -> None:
    adj, _ = _solved_pair(tmp_path)
    replay = replay_from_disk(adj)
    assert replay["matches"] is True
    assert replay["recomputed"]["counterexample_discovered"] is True


def test_altered_final_verdict_fails_replay(tmp_path: Path) -> None:
    adj, _ = _solved_pair(tmp_path)
    final = json.loads((adj / "final-result.json").read_text())
    final["counterexample_discovered"] = False  # flip the recorded verdict
    (adj / "final-result.json").write_text(json.dumps(final, sort_keys=True, indent=2))
    replay = replay_from_disk(adj)
    assert replay["matches"] is False


def test_altered_adjudicator_evidence_changes_reconstruction(tmp_path: Path) -> None:
    adj, _ = _solved_pair(tmp_path)
    # Remove the counterexample from the evidence: replay now reconstructs
    # "not solved" and no longer matches the stored solved verdict.
    (adj / "adjudicator-evidence.json").write_text("[]", encoding="utf-8")
    replay = replay_from_disk(adj)
    assert replay["recomputed"]["counterexample_discovered"] is False
    assert replay["matches"] is False


# --------------------------------------------------------------------------
# selector cannot qualify when replay or integrity fails
# --------------------------------------------------------------------------


def _passing_matrix() -> list[dict[str, Any]]:
    families = [
        ["conventional_rest"],
        ["administrative_control"],
        ["legacy_compatibility"],
        ["async_queue_like"],
        ["conventional_rest"],
        ["administrative_control"],
        ["conventional_rest"],
        ["legacy_compatibility"],
    ]
    results = []
    for i in range(8):
        results.append(
            {
                "binding_dimensions_varied": ["tenant", "principal", "sink", "release_version"],
                "calls_to_first_counterexample": 3,
                "candidate_id": "candidate-A",
                "counterexample_discovered": i < 6,
                "duplicate_probe_rate": 0.2,
                "evidence_integrity": "PASS",
                "leak_audit": "PASS",
                "provider_calls": 10,
                "replay_matches_final": True,
                "route_families_probed": families[i],
                "stop_reason": "MODEL_VOLUNTARY_STOP",
                "target_attempts": 8,
                "target_id": f"synthetic-target-{i:02d}",
                "terminal_failure": False,
                "unique_hypothesis_rate": 0.8,
            }
        )
    return results


def test_selector_blocks_on_failed_integrity() -> None:
    matrix = _passing_matrix()
    assert selection.CandidateAggregate("candidate-A", matrix).gate()["qualifies"] is True
    matrix[0]["evidence_integrity"] = "FAIL"
    gate = selection.CandidateAggregate("candidate-A", matrix).gate()
    assert gate["conditions"]["evidence_integrity_all_pass"] is False
    assert gate["qualifies"] is False


def test_selector_blocks_on_failed_replay() -> None:
    matrix = _passing_matrix()
    matrix[0]["replay_matches_final"] = False
    gate = selection.CandidateAggregate("candidate-A", matrix).gate()
    assert gate["conditions"]["replays_reproduce_final"] is False
    assert gate["qualifies"] is False


def test_selector_replay_reads_stored_field_not_adjudicator_evidence() -> None:
    # Published results carry no adjudicator_evidence; the gate must still see
    # the replay verdict via the stored field.
    matrix = _passing_matrix()
    assert all("adjudicator_evidence" not in r for r in matrix)
    assert selection.CandidateAggregate("candidate-A", matrix).gate()["qualifies"] is True


# --------------------------------------------------------------------------
# generator digest reconciliation
# --------------------------------------------------------------------------


def test_generator_digest_reconciles_against_frozen_manifest() -> None:
    manifest = json.loads(
        (
            ROOT / "docs" / "qualification" / "OAT_ADVERSARY_QUALIFICATION_001_FROZEN_MANIFEST.json"
        ).read_text()
    )
    import hashlib

    observed = hashlib.sha256(
        (ROOT / "oat" / "qualification" / "synthetic_targets.py").read_bytes()
    ).hexdigest()
    assert manifest["frozen_inputs"]["generator"] == observed


# --------------------------------------------------------------------------
# qualification-metric replay closure
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("counterexample_discovered", False),
        ("terminal_failure", True),
        ("target_attempts", 999),
        ("provider_calls", 999),
        ("binding_dimensions_varied", ["tenant"]),
        ("route_families_probed", ["legacy_compatibility"]),
        ("duplicate_probe_rate", 0.875),
        ("unique_hypothesis_rate", 0.125),
        ("calls_to_first_counterexample", 999),
        ("leak_audit", "FAIL"),
    ],
)
def test_replay_covers_every_selection_relevant_metric(
    tmp_path: Path, field: str, replacement: Any
) -> None:
    adj, _ = _solved_pair(tmp_path)
    final_path = adj / "final-result.json"
    final = json.loads(final_path.read_text())

    # Ensure the replacement actually changes this fixture's stored value.
    if final.get(field) == replacement:
        replacement = None

    final[field] = replacement
    final_path.write_text(
        json.dumps(final, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    replay = replay_from_disk(adj)
    assert replay["matches"] is False
    assert replay["matches_by_field"][field] is False


def test_attempt_sequence_is_replay_input_not_decorative(tmp_path: Path) -> None:
    adj, _ = _solved_pair(tmp_path)
    attempts_path = adj / "attempts.jsonl"
    rows = [json.loads(line) for line in attempts_path.read_text().splitlines() if line.strip()]
    assert rows

    # Duplicate a preserved attempt. This changes target-attempt count and
    # uniqueness/duplication metrics without editing final-result.json.
    rows.append(dict(rows[-1]))
    attempts_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )

    replay = replay_from_disk(adj)
    assert replay["matches"] is False
    assert replay["matches_by_field"]["target_attempts"] is False


def test_runtime_records_frozen_wall_clock_semantics(tmp_path: Path) -> None:
    adj, _ = _solved_pair(tmp_path)
    runtime = json.loads((adj / "runtime-facts.json").read_text())
    assert runtime["wall_clock_semantics"] == (
        "DO_NOT_START_NEW_PROVIDER_CALL_AT_OR_AFTER_RUN_WALL_CLOCK_LIMIT"
    )
    assert runtime["exposed_dimensions"]
