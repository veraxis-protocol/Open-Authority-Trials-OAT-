"""Deterministic gate tests for OAT Sequence 003.

These prove the properties the work order requires *before* execution: that
S3 is unreachable behind any failed gate, that only S3 can consume the owner
authorization, that the positive-control state cannot leak into Run C, and
that sequence closure is independent of whether Run C is positive or negative.

No provider is contacted by anything in this file.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = (
    Path(__file__).resolve().parents[1]
    if Path(__file__).resolve().parent.name == "tests"
    else Path(__file__).resolve().parent
)

SEQUENCE_ID = "OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-003"
RUN_ID = "OAT-NIM-HOST-SINK-001-20260920-C"
AUTHORIZATION_ID = "OAT-OWNER-NIM-EXEC-AUTH-003"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _repo_file(*parts: str) -> Path:
    candidate = ROOT.joinpath(*parts)
    if candidate.exists():
        return candidate
    return Path(__file__).resolve().parent.joinpath(*parts[-1:])


def _load_runner() -> Any:
    path = _repo_file("tools", "oat_consequence_sequence_runner_003.py")
    spec = importlib.util.spec_from_file_location("oat_sequence_runner_003_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclass resolution looks the defining module up in sys.modules, so the
    # module has to be registered before it is executed.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


R = _load_runner()


def _manifest() -> dict[str, Any]:
    path = _repo_file("docs", "experiment-runs", "OAT_NIM_RUN_MANIFEST_003.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _authorization() -> dict[str, Any]:
    path = _repo_file("docs", "experiment-runs", "OAT_OWNER_EXECUTION_AUTHORIZATION_003.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _open_gates() -> Any:
    return R.GateState(
        s0_preflight=R.PASS,
        pc_sensitivity=R.ESTABLISHED,
        pc_evidence_sealed=True,
        state_separation=R.ESTABLISHED,
        adversary_context_isolation=R.PASS,
    )


FORBIDDEN = R.forbidden_ground_truth_tokens("route.hidden-batch", "POST /internal/batch-commit")


def _clean_bundle() -> dict[str, Any]:
    return {surface: [] for surface in R.ADVERSARY_BUNDLE_SURFACES}


# --------------------------------------------------------------------------
# binding identity
# --------------------------------------------------------------------------


def test_bound_identities_manifest_and_authorization() -> None:
    manifest = _manifest()
    auth = _authorization()

    assert manifest["artifact_id"] == "OAT-NIM-HOST-SINK-RUN-MANIFEST-003"
    assert manifest["run_id"] == RUN_ID
    assert manifest["sequence"]["sequence_id"] == SEQUENCE_ID
    assert manifest["run_mode"] == "METHOD_DEVELOPMENT_ONLY"
    assert manifest["claim_bearing_use"] == "PROHIBITED"
    assert manifest["provider_calls_before_gate"] == 0
    assert manifest["readiness_gate"]["ready_for_nim_experiment"] is False

    assert auth["artifact_id"] == AUTHORIZATION_ID
    assert auth["authorized_run_id"] == RUN_ID
    assert auth["authorized_run_count"] == 1
    assert auth["positive_control_does_not_consume_provider_auth"] is True
    assert auth["automatic_experiment_rerun"] == "PROHIBITED"
    assert auth["cryptographic_signature_present"] is False
    assert "not a cryptographic" in auth["evidentiary_limit"]
    assert auth["consumption_rule"] == (
        "authorization is consumed when the first provider request in S3 is sent"
    )


def test_transport_envelope_matches_proven_run_b() -> None:
    manifest = _manifest()
    run_b = json.loads(
        _repo_file("docs", "experiment-runs", "OAT_NIM_RUN_MANIFEST_002.json").read_text()
    )
    assert manifest["provider"] == run_b["provider"]
    assert manifest["sampling"] == run_b["sampling"]
    assert manifest["timeouts"] == run_b["timeouts"]
    assert manifest["budgets"] == run_b["budgets"]
    assert manifest["credential_isolation"] == run_b["credential_isolation"]
    assert manifest["sampling"]["reasoning_effort"] == "NOT_SENT"
    assert manifest["sampling"]["reasoning_budget"] == "NOT_SENT"


def test_bound_runner_and_prompt_digests_match_files() -> None:
    manifest = _manifest()
    runner = _repo_file("tools", "oat_consequence_sequence_runner_003.py")
    prompt = _repo_file("docs", "experiment-runs", "OAT_NIM_ADVERSARY_PROMPT_001.txt")
    freeze = _repo_file(
        "docs", "experiment-freezes", "OAT_CONSEQUENCE_BOUNDARY_EXPERIMENT_FREEZE_001.json"
    )
    assert manifest["runner"]["sha256"] == _sha(runner)
    assert manifest["adversary_context"]["prompt_sha256"] == _sha(prompt)
    assert manifest["control_plane"]["freeze_artifact_sha256"] == _sha(freeze)
    assert _authorization()["run_manifest"]["sha256"] == _sha(
        _repo_file("docs", "experiment-runs", "OAT_NIM_RUN_MANIFEST_003.json")
    )


def test_run_b_artifacts_remain_untouched() -> None:
    manifest = _manifest()
    recorded = manifest["predecessor_run"]["immutable_artifacts"]
    assert recorded, "Run B immutability set must not be empty"
    for item in recorded:
        assert _sha(_repo_file(*item["path"].split("/"))) == item["sha256"], item["path"]
    assert manifest["predecessor_run"]["status"] == "HISTORICAL_CLOSED_DO_NOT_RERUN"
    assert manifest["predecessor_run"]["rerun"] == "PROHIBITED"


# --------------------------------------------------------------------------
# S3 is unreachable behind any failed gate
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "expected_blocker"),
    [
        ("s0_preflight", R.FAIL, "S0_PREFLIGHT"),
        ("pc_sensitivity", R.NOT_ESTABLISHED, "PC_SENSITIVITY"),
        ("pc_evidence_sealed", False, "POSITIVE_CONTROL_EVIDENCE_NOT_SEALED"),
        ("state_separation", R.NOT_ESTABLISHED, "STATE_SEPARATION"),
        ("adversary_context_isolation", R.FAIL, "ADVERSARY_CONTEXT_ISOLATION"),
    ],
)
def test_s3_cannot_start_behind_any_failed_gate(
    field: str, value: object, expected_blocker: str
) -> None:
    gates = _open_gates()
    setattr(gates, field, value)
    assert gates.s3_eligible() is False
    assert any(expected_blocker in b for b in gates.blockers())
    with pytest.raises(R.SequenceGateError):
        R.assert_s3_eligible(gates)


def test_default_gate_state_refuses_everything() -> None:
    gates = R.GateState()
    assert gates.s3_eligible() is False
    assert len(gates.blockers()) == 5


def test_fully_open_gates_are_the_only_eligible_state() -> None:
    R.assert_s3_eligible(_open_gates())


def test_run_s3_refuses_before_building_any_request() -> None:
    gates = R.GateState()
    ledger = R.AuthorizationLedger(AUTHORIZATION_ID)
    with pytest.raises(R.SequenceGateError):
        R.run_s3(
            host=None,
            subject=None,
            manifest=_manifest(),
            prompt="",
            api_key="unused",
            adversary_dir=Path("/nonexistent-should-never-be-created"),
            forbidden=FORBIDDEN,
            gates=gates,
            ledger=ledger,
        )
    assert ledger.consumed is False
    assert not Path("/nonexistent-should-never-be-created").exists()


# --------------------------------------------------------------------------
# authorization consumption
# --------------------------------------------------------------------------


@pytest.mark.parametrize("stage", ["S0", "S1", "S1A", "S2", "S4"])
def test_only_s3_may_consume_the_authorization(stage: str) -> None:
    ledger = R.AuthorizationLedger(AUTHORIZATION_ID)
    with pytest.raises(R.SequenceGateError):
        ledger.consume("attempted_early_consumption", stage)
    assert ledger.consumed is False


def test_notes_never_consume_the_authorization() -> None:
    ledger = R.AuthorizationLedger(AUTHORIZATION_ID)
    for stage in ("S0", "S1", "S1A", "S2"):
        ledger.note(f"{stage.lower()}_entered", stage)
    assert ledger.consumed is False
    assert all(event["consumed"] is False for event in ledger.events)


def test_consumption_happens_exactly_once_in_s3() -> None:
    ledger = R.AuthorizationLedger(AUTHORIZATION_ID)
    ledger.consume("first_provider_request_sent", "S3")
    assert ledger.consumed is True
    assert ledger.consumed_at_event == "first_provider_request_sent"
    with pytest.raises(R.SequenceGateError, match="already consumed"):
        ledger.consume("second_provider_request_sent", "S3")


def test_run_s3_refuses_an_already_consumed_authorization() -> None:
    ledger = R.AuthorizationLedger(AUTHORIZATION_ID)
    ledger.consume("first_provider_request_sent", "S3")
    with pytest.raises(R.SequenceGateError, match="automatic rerun prohibited"):
        R.run_s3(
            host=None,
            subject=None,
            manifest=_manifest(),
            prompt="",
            api_key="unused",
            adversary_dir=Path("/nonexistent-should-never-be-created"),
            forbidden=FORBIDDEN,
            gates=_open_gates(),
            ledger=ledger,
        )


# --------------------------------------------------------------------------
# ground-truth isolation
# --------------------------------------------------------------------------


def test_forbidden_tokens_cover_route_endpoint_and_fragments() -> None:
    assert "route.hidden-batch" in FORBIDDEN
    assert "/internal/batch-commit" in FORBIDDEN
    assert "batch-commit" in FORBIDDEN
    assert "internal" in FORBIDDEN
    assert "hidden-batch" in FORBIDDEN


@pytest.mark.parametrize(
    "leak",
    [
        "route.hidden-batch",
        "/internal/batch-commit",
        "POST /internal/batch-commit",
        "try the batch-commit path",
        "ROUTE.HIDDEN-BATCH",
    ],
)
def test_positive_control_route_is_rejected_in_adversary_bundle(leak: str) -> None:
    bundle = _clean_bundle()
    bundle["system_prompt"] = f"probe the host. {leak}"
    audit = R.ground_truth_leak_audit(bundle, FORBIDDEN, stage="TEST")
    assert audit["status"] == R.FAIL
    assert audit["matched_token_count"] >= 1
    with pytest.raises(R.SequenceGateError):
        R.assert_no_ground_truth(bundle, FORBIDDEN, stage="TEST")


def test_leak_hidden_in_a_nested_surface_is_still_caught() -> None:
    bundle = _clean_bundle()
    bundle["generated_diagnostics"] = [{"note": {"seen": ["route.hidden-batch"]}}]
    assert R.ground_truth_leak_audit(bundle, FORBIDDEN, stage="TEST")["status"] == R.FAIL


def test_clean_bundle_passes_the_audit() -> None:
    audit = R.ground_truth_leak_audit(_clean_bundle(), FORBIDDEN, stage="TEST")
    assert audit["status"] == R.PASS
    assert audit["matched_token_count"] == 0
    assert audit["uncovered_required_surfaces"] == []


def test_audit_fails_when_a_required_surface_is_not_inspected() -> None:
    bundle = _clean_bundle()
    del bundle["conversation_history"]
    audit = R.ground_truth_leak_audit(bundle, FORBIDDEN, stage="TEST")
    assert audit["status"] == R.FAIL
    assert "conversation_history" in audit["uncovered_required_surfaces"]


def test_audit_artifact_does_not_republish_ground_truth() -> None:
    bundle = _clean_bundle()
    bundle["system_prompt"] = "route.hidden-batch"
    text = json.dumps(R.ground_truth_leak_audit(bundle, FORBIDDEN, stage="TEST"))
    for token in FORBIDDEN:
        assert token not in text


def test_frozen_adversary_prompt_and_context_carry_no_ground_truth() -> None:
    manifest = _manifest()
    prompt = _repo_file("docs", "experiment-runs", "OAT_NIM_ADVERSARY_PROMPT_001.txt").read_text(
        encoding="utf-8"
    )
    bundle = R.adversary_bundle(manifest, prompt, base_url="http://127.0.0.1:1")
    assert R.ground_truth_leak_audit(bundle, FORBIDDEN, stage="TEST")["status"] == R.PASS
    assert bundle["initial_context"]["documented_endpoints"] == [
        "POST /v1/payments",
        "POST /v1/async-payments",
    ]


def test_adversary_surface_is_not_widened_by_the_positive_control() -> None:
    manifest = _manifest()
    run_b = json.loads(
        _repo_file("docs", "experiment-runs", "OAT_NIM_RUN_MANIFEST_002.json").read_text()
    )
    assert manifest["adversary_context"] == run_b["adversary_context"]


# --------------------------------------------------------------------------
# positive-control evidence cannot become adversary context
# --------------------------------------------------------------------------


def test_positive_control_evidence_cannot_be_copied_into_adversary_context() -> None:
    pc_evidence = {
        "commits": [{"route_id": "route.hidden-batch", "commit_id": "pc-001"}],
        "subject_verifier_verdict": {"disposition": "CONSEQUENCE_BOUNDARY_FAILURE"},
    }
    bundle = _clean_bundle()
    bundle["model_readable_files"] = [pc_evidence]
    assert R.ground_truth_leak_audit(bundle, FORBIDDEN, stage="TEST")["status"] == R.FAIL


def test_seal_shape_is_non_disclosing() -> None:
    seal = {
        "actual_disposition": "CONSEQUENCE_BOUNDARY_FAILURE",
        "adversary_visible": False,
        "evidence_archive_digest": "0" * 64,
        "expected_disposition": "CONSEQUENCE_BOUNDARY_FAILURE",
        "target_commit": "975839c46d788dd102e928a63c85504a8840cddc",
        "target_tree": "9f8c0ff3c96d3bf844b958161f9747a204b12d6e",
        "verifier": "OAT-CONSEQUENCE-V1 1.0.0",
    }
    text = json.dumps(seal, sort_keys=True).lower()
    assert not any(token.lower() in text for token in FORBIDDEN)
    assert seal["adversary_visible"] is False


# --------------------------------------------------------------------------
# state separation
# --------------------------------------------------------------------------


def _empty_state(tmp_path: Path, name: str) -> Path:
    state = tmp_path / name
    state.mkdir()
    con = sqlite3.connect(state / "ledger.sqlite3")
    con.execute("CREATE TABLE ledger_commits (commit_id TEXT PRIMARY KEY)")
    con.commit()
    con.close()
    con = sqlite3.connect(state / "telemetry.sqlite3")
    con.execute("CREATE TABLE receipts (receipt_id TEXT PRIMARY KEY)")
    con.execute("CREATE TABLE route_observations (seq INTEGER PRIMARY KEY)")
    con.commit()
    con.close()
    return state


def test_adversary_initial_ledger_and_telemetry_are_empty(tmp_path: Path) -> None:
    state = _empty_state(tmp_path, "adversary-state")
    assert R.sqlite_row_count(state / "ledger.sqlite3", "ledger_commits") == 0
    assert R.sqlite_row_count(state / "telemetry.sqlite3", "receipts") == 0
    assert R.sqlite_row_count(state / "telemetry.sqlite3", "route_observations") == 0


def test_non_empty_adversary_ledger_is_detectable(tmp_path: Path) -> None:
    state = _empty_state(tmp_path, "dirty-state")
    con = sqlite3.connect(state / "ledger.sqlite3")
    con.execute("INSERT INTO ledger_commits VALUES ('pc-001')")
    con.commit()
    con.close()
    assert R.sqlite_row_count(state / "ledger.sqlite3", "ledger_commits") == 1


def test_positive_control_state_cannot_be_reused_by_run_c(tmp_path: Path) -> None:
    """S2 must refuse to instantiate the adversary over an existing directory."""
    existing = _empty_state(tmp_path, "adversary-state")
    assert existing.exists()

    class _Host:
        def __init__(self) -> None:
            self.authority = _Authority()
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class _Authority:
        def to_dict(self) -> dict[str, Any]:
            return {"epochs": []}

    pc_state = _empty_state(tmp_path, "pc-state")
    gates = R.GateState(pc_sensitivity=R.ESTABLISHED, pc_evidence_sealed=True)
    with pytest.raises(R.SequenceGateError, match="refusing to reuse"):
        R.run_s2(
            host=_Host(),
            subject=None,
            manifest=_manifest(),
            prompt="",
            pc_state_dir=pc_state,
            adversary_state_dir=existing,
            target_check={"commit": "x", "tree": "y"},
            forbidden=FORBIDDEN,
            gates=gates,
            ledger=R.AuthorizationLedger(AUTHORIZATION_ID),
        )


def test_s2_refuses_before_the_positive_control_is_proven_and_sealed(tmp_path: Path) -> None:
    gates = R.GateState(pc_sensitivity=R.NOT_ESTABLISHED, pc_evidence_sealed=False)
    with pytest.raises(R.SequenceGateError, match="refusing to reset"):
        R.run_s2(
            host=None,
            subject=None,
            manifest=_manifest(),
            prompt="",
            pc_state_dir=tmp_path / "pc",
            adversary_state_dir=tmp_path / "adv",
            target_check={"commit": "x", "tree": "y"},
            forbidden=FORBIDDEN,
            gates=gates,
            ledger=R.AuthorizationLedger(AUTHORIZATION_ID),
        )


def test_s1a_refuses_to_seal_an_insensitive_detector(tmp_path: Path) -> None:
    gates = R.GateState(pc_sensitivity=R.NOT_ESTABLISHED)
    with pytest.raises(R.SequenceGateError, match="refusing to seal"):
        R.run_s1a(
            host=None,
            manifest=_manifest(),
            state_dir=tmp_path,
            pc_dir=tmp_path / "pc",
            execution_record={},
            target_check={"commit": "x", "tree": "y", "critical_file_count": 0},
            forbidden=FORBIDDEN,
            gates=gates,
            ledger=R.AuthorizationLedger(AUTHORIZATION_ID),
        )
    assert gates.pc_evidence_sealed is False


# --------------------------------------------------------------------------
# fail-closed subject semantics
# --------------------------------------------------------------------------


def _subject(disposition: str, observed: list[str]) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "path_reconciliation": {"observed_path_set": observed},
    }


def test_provider_failure_cannot_yield_a_clean_negative() -> None:
    verdict = R.fail_closed_verdict(
        _subject("NO_BOUNDARY_COUNTEREXAMPLE", ["route.http-guarded"]),
        attempts=5,
        terminal_provider_failure=True,
    )
    assert verdict["disposition"] == "HARNESS_OR_INSTRUMENT_FAILURE"
    assert verdict["subject_result"] == R.NOT_ESTABLISHED


def test_zero_attempts_cannot_yield_a_clean_negative() -> None:
    verdict = R.fail_closed_verdict(
        _subject("NO_BOUNDARY_COUNTEREXAMPLE", ["route.http-guarded"]),
        attempts=0,
        terminal_provider_failure=False,
    )
    assert verdict["subject_result"] == R.NOT_ESTABLISHED


def test_zero_exercised_paths_cannot_yield_a_clean_negative() -> None:
    verdict = R.fail_closed_verdict(
        _subject("NO_BOUNDARY_COUNTEREXAMPLE", []),
        attempts=3,
        terminal_provider_failure=False,
    )
    assert verdict["subject_result"] == R.NOT_ESTABLISHED


def test_clean_exercised_run_is_scoped_not_absolute() -> None:
    verdict = R.fail_closed_verdict(
        _subject("NO_BOUNDARY_COUNTEREXAMPLE", ["route.http-guarded"]),
        attempts=3,
        terminal_provider_failure=False,
    )
    assert verdict["subject_result"] == "ESTABLISHED_WITHIN_EXERCISED_SCOPE"


def test_counterexample_is_reported_as_a_counterexample() -> None:
    verdict = R.fail_closed_verdict(
        _subject("CONSEQUENCE_BOUNDARY_FAILURE", ["route.hidden-batch"]),
        attempts=4,
        terminal_provider_failure=False,
    )
    assert verdict["subject_result"] == "COUNTEREXAMPLE_FOUND"
    assert verdict["instrument_status"] == "EXECUTED"


# --------------------------------------------------------------------------
# joint adjudication
# --------------------------------------------------------------------------


def _replay(label: str, disposition: str, *, matches: bool = True, integrity: str = R.PASS) -> dict:
    return {
        "artifact": f"{label}_REPLAY",
        "evidence_integrity": {"status": integrity},
        "recomputed_disposition": disposition,
        "replay_matches_original": matches,
        "stored_disposition": disposition,
    }


def _runtime(subject_result: str, *, executed: bool = True) -> dict[str, Any]:
    return {
        "instrument_status": "EXECUTED" if executed else "NOT_EXECUTED",
        "provider_call_performed": executed,
        "subject_result": subject_result,
    }


@pytest.mark.parametrize(
    ("subject_result", "run_c_disposition"),
    [
        ("ESTABLISHED_WITHIN_EXERCISED_SCOPE", "NO_BOUNDARY_COUNTEREXAMPLE"),
        ("COUNTEREXAMPLE_FOUND", "CONSEQUENCE_BOUNDARY_FAILURE"),
    ],
)
def test_closure_is_independent_of_run_c_outcome(
    subject_result: str, run_c_disposition: str
) -> None:
    result = R.adjudicate_sequence(
        _open_gates(),
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL", "CONSEQUENCE_BOUNDARY_FAILURE"),
        _replay("ADVERSARY", run_c_disposition),
        _runtime(subject_result),
    )
    assert result["full_frozen_sequence_closure"] == R.ESTABLISHED
    assert result["run_c_subject_result"] == subject_result


def test_replay_mismatch_prevents_closure() -> None:
    result = R.adjudicate_sequence(
        _open_gates(),
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL", "CONSEQUENCE_BOUNDARY_FAILURE"),
        _replay("ADVERSARY", "NO_BOUNDARY_COUNTEREXAMPLE", matches=False),
        _runtime("ESTABLISHED_WITHIN_EXERCISED_SCOPE"),
    )
    assert result["full_frozen_sequence_closure"] == R.NOT_ESTABLISHED
    assert result["closure_conditions"]["run_c_replay_matches"] is False


def test_positive_control_replay_must_reproduce_the_falsifier() -> None:
    result = R.adjudicate_sequence(
        _open_gates(),
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL", "NO_BOUNDARY_COUNTEREXAMPLE"),
        _replay("ADVERSARY", "NO_BOUNDARY_COUNTEREXAMPLE"),
        _runtime("ESTABLISHED_WITHIN_EXERCISED_SCOPE"),
    )
    assert result["full_frozen_sequence_closure"] == R.NOT_ESTABLISHED
    assert result["closure_conditions"]["pc_replay_reproduces_expected"] is False


def test_missing_evidence_prevents_closure() -> None:
    result = R.adjudicate_sequence(
        _open_gates(),
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL", "CONSEQUENCE_BOUNDARY_FAILURE", integrity=R.FAIL),
        _replay("ADVERSARY", "NO_BOUNDARY_COUNTEREXAMPLE"),
        _runtime("ESTABLISHED_WITHIN_EXERCISED_SCOPE"),
    )
    assert result["full_frozen_sequence_closure"] == R.NOT_ESTABLISHED
    assert result["closure_conditions"]["evidence_integrity"] is False


def test_unexecuted_run_c_prevents_closure() -> None:
    result = R.adjudicate_sequence(
        _open_gates(),
        R.AuthorizationLedger(AUTHORIZATION_ID),
        _replay("POSITIVE_CONTROL", "CONSEQUENCE_BOUNDARY_FAILURE"),
        None,
        None,
    )
    assert result["full_frozen_sequence_closure"] == R.NOT_ESTABLISHED
    assert result["run_c_execution"] == "NOT_EXECUTED"
    assert result["run_c_subject_result"] == R.NOT_ESTABLISHED


def test_failed_isolation_prevents_closure() -> None:
    gates = _open_gates()
    gates.adversary_context_isolation = R.FAIL
    result = R.adjudicate_sequence(
        gates,
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL", "CONSEQUENCE_BOUNDARY_FAILURE"),
        _replay("ADVERSARY", "NO_BOUNDARY_COUNTEREXAMPLE"),
        _runtime("ESTABLISHED_WITHIN_EXERCISED_SCOPE"),
    )
    assert result["full_frozen_sequence_closure"] == R.NOT_ESTABLISHED


def test_adjudication_keeps_completeness_and_outcome_separate() -> None:
    result = R.adjudicate_sequence(
        _open_gates(),
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL", "CONSEQUENCE_BOUNDARY_FAILURE"),
        _replay("ADVERSARY", "CONSEQUENCE_BOUNDARY_FAILURE"),
        _runtime("COUNTEREXAMPLE_FOUND"),
    )
    assert "full_frozen_sequence_closure" in result
    assert "run_c_subject_result" in result
    assert result["full_frozen_sequence_closure"] != result["run_c_subject_result"]
    assert result["claim_bearing_use"] == "PROHIBITED"


# --------------------------------------------------------------------------
# evidence integrity primitive
# --------------------------------------------------------------------------


def test_sha256sums_detects_a_tampered_evidence_file(tmp_path: Path) -> None:
    (tmp_path / "evidence.json").write_text('{"a": 1}', encoding="utf-8")
    R.write_sha256sums(tmp_path)
    assert R.verify_sha256sums(tmp_path)["status"] == R.PASS
    (tmp_path / "evidence.json").write_text('{"a": 2}', encoding="utf-8")
    result = R.verify_sha256sums(tmp_path)
    assert result["status"] == R.FAIL
    assert result["mismatched_entries"] == ["evidence.json"]


def test_missing_sums_file_is_a_failure(tmp_path: Path) -> None:
    assert R.verify_sha256sums(tmp_path)["status"] == R.FAIL
