"""Regression tests for the Sequence 003 adjudication defects, and Sequence 004 binding.

Sequence 003 / Run C consumed its owner authorization on the first provider
request, received HTTP 401, reached the target zero times, and was reported as
a complete scientific sequence. Two independent defects produced that:

  A. execution was inferred from ``provider_call_performed``
  B. replay compared the raw subject verdict instead of the final adjudication

Each was sufficient on its own, so each is pinned here separately, plus the
exact observed Run C shape end to end.

No provider is contacted by anything in this file.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = (
    Path(__file__).resolve().parents[1]
    if Path(__file__).resolve().parent.name == "tests"
    else Path(__file__).resolve().parent
)

SEQUENCE_ID = "OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-004"
RUN_ID = "OAT-NIM-HOST-SINK-001-20260920-D"
AUTHORIZATION_ID = "OAT-OWNER-NIM-EXEC-AUTH-004"
CONSUMED_AUTHORIZATION_ID = "OAT-OWNER-NIM-EXEC-AUTH-003"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _repo_file(*parts: str) -> Path:
    candidate = ROOT.joinpath(*parts)
    if candidate.exists():
        return candidate
    return Path(__file__).resolve().parent.joinpath(*parts[-1:])


def _load(module_name: str, *parts: str) -> Any:
    path = _repo_file(*parts)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


R = _load("oat_sequence_runner_004_test", "tools", "oat_consequence_sequence_runner_004.py")
PF = _load("oat_provider_preflight_test", "tools", "oat_nvidia_provider_preflight.py")


def _manifest() -> dict[str, Any]:
    return json.loads(
        _repo_file("docs", "experiment-runs", "OAT_NIM_RUN_MANIFEST_004.json").read_text()
    )


def _authorization() -> dict[str, Any]:
    return json.loads(
        _repo_file(
            "docs", "experiment-runs", "OAT_OWNER_EXECUTION_AUTHORIZATION_004.json"
        ).read_text()
    )


def _open_gates() -> Any:
    return R.GateState(
        s0_preflight=R.PASS,
        pc_sensitivity=R.ESTABLISHED,
        pc_evidence_sealed=True,
        state_separation=R.ESTABLISHED,
        adversary_context_isolation=R.PASS,
        provider_preflight=R.PASS,
    )


# The exact shape Run C produced.
RUN_C_RUNTIME = {
    "instrument_status": "NOT_EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT",
    "provider_call_performed": True,
    "provider_calls": 1,
    "provider_transport_failures": 1,
    "stop_reason": "PROVIDER_TRANSPORT_FAILURE",
    "subject_result": "NOT_ESTABLISHED",
    "target_http_attempts": 0,
    "terminal_provider_failure": True,
}

GOOD_RUNTIME = {
    "instrument_status": "EXECUTED",
    "provider_call_performed": True,
    "provider_calls": 9,
    "provider_transport_failures": 0,
    "stop_reason": "MODEL_VOLUNTARY_STOP",
    "subject_result": "ESTABLISHED_WITHIN_EXERCISED_SCOPE",
    "target_http_attempts": 8,
    "terminal_provider_failure": False,
}


def _replay(
    label: str,
    *,
    matches: bool = True,
    integrity: str = R.PASS,
    subject_disposition: str = "CONSEQUENCE_BOUNDARY_FAILURE",
) -> dict[str, Any]:
    return {
        "artifact": f"{label}_REPLAY",
        "evidence_integrity": {"status": integrity},
        "recomputed_subject_disposition": subject_disposition,
        "replay_matches_original": matches,
    }


# --------------------------------------------------------------------------
# 1. provider contact is not execution
# --------------------------------------------------------------------------


def test_provider_call_with_zero_attempts_is_not_execution() -> None:
    assert R.run_execution_established(RUN_C_RUNTIME) is False


def test_execution_requires_both_instrument_status_and_attempts() -> None:
    assert R.run_execution_established(GOOD_RUNTIME) is True
    assert R.run_execution_established({**GOOD_RUNTIME, "target_http_attempts": 0}) is False
    assert (
        R.run_execution_established(
            {**GOOD_RUNTIME, "instrument_status": "NOT_EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT"}
        )
        is False
    )
    assert R.run_execution_established(None) is False


# --------------------------------------------------------------------------
# 2. a 401 cannot produce sequence closure
# --------------------------------------------------------------------------


def test_http_401_terminal_failure_cannot_produce_closure() -> None:
    result = R.adjudicate_sequence(
        _open_gates(),
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL"),
        _replay("ADVERSARY", subject_disposition="NO_BOUNDARY_COUNTEREXAMPLE"),
        RUN_C_RUNTIME,
    )
    assert result["full_frozen_sequence_closure"] == R.NOT_ESTABLISHED
    assert result["run_execution"] == "NOT_EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT"
    assert result["closure_conditions"]["run_executed_to_admissible_boundary_result"] is False
    assert result["run_subject_result"] == "NOT_ESTABLISHED"
    # The authorization was still spent; that must remain visible.
    assert result["provider_contacted"] is True
    assert result["authorization"]["consumed"] is True


def test_runner_003_style_inference_would_have_passed_this_case() -> None:
    """Pin the defect itself: provider contact alone used to satisfy execution."""
    assert bool(RUN_C_RUNTIME["provider_call_performed"]) is True
    assert R.run_execution_established(RUN_C_RUNTIME) is False


# --------------------------------------------------------------------------
# 3 + 4. replay must reproduce the FINAL adjudication
# --------------------------------------------------------------------------


def _final(disposition: str, subject_result: str, instrument_status: str) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "instrument_status": instrument_status,
        "subject_result": subject_result,
    }


def test_harness_failure_replay_must_reproduce_the_fail_closed_disposition() -> None:
    subject = {
        "disposition": "NO_BOUNDARY_COUNTEREXAMPLE",
        "path_reconciliation": {"observed_path_set": []},
    }
    recomputed = R.fail_closed_verdict(subject, attempts=0, terminal_provider_failure=True)
    assert recomputed["disposition"] == "HARNESS_OR_INSTRUMENT_FAILURE"
    assert recomputed["subject_result"] == R.NOT_ESTABLISHED
    assert recomputed["instrument_status"] == "NOT_EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT"
    for field in R.FINAL_VERDICT_COMPARED_FIELDS:
        assert field in recomputed


def test_raw_subject_match_does_not_satisfy_final_replay() -> None:
    """The exact Run C defect: empty ledger replays to itself, final verdict differs."""
    subject = {
        "disposition": "NO_BOUNDARY_COUNTEREXAMPLE",
        "path_reconciliation": {"observed_path_set": []},
    }
    stored_final = _final(
        "HARNESS_OR_INSTRUMENT_FAILURE",
        R.NOT_ESTABLISHED,
        "NOT_EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT",
    )
    # Raw layer agrees with itself -- this is what runner 003 compared.
    assert subject["disposition"] != stored_final["disposition"]
    recomputed_final = R.fail_closed_verdict(subject, attempts=0, terminal_provider_failure=True)
    assert all(recomputed_final[f] == stored_final[f] for f in R.FINAL_VERDICT_COMPARED_FIELDS)
    # ...and a replay that forgot the execution facts reaches a different final
    # verdict: an exercised ledger with no terminal failure resolves clean.
    exercised = {
        "disposition": "NO_BOUNDARY_COUNTEREXAMPLE",
        "path_reconciliation": {"observed_path_set": ["route.http-guarded"]},
    }
    wrong = R.fail_closed_verdict(exercised, attempts=1, terminal_provider_failure=False)
    assert wrong["disposition"] != stored_final["disposition"]
    assert wrong["subject_result"] != stored_final["subject_result"]


def test_execution_facts_are_required_for_replay(tmp_path: Path) -> None:
    with pytest.raises(R.SequenceGateError, match="no preserved execution facts"):
        R.execution_facts(tmp_path)


def test_execution_facts_round_trip_from_runtime(tmp_path: Path) -> None:
    (tmp_path / "runtime.json").write_text(json.dumps(RUN_C_RUNTIME), encoding="utf-8")
    facts = R.execution_facts(tmp_path)
    assert facts["target_http_attempts"] == 0
    assert facts["terminal_provider_failure"] is True
    assert facts["provider_call_performed"] is True
    assert facts["source"] == "runtime.json"


# --------------------------------------------------------------------------
# 5. transient retryable failures are not terminal
# --------------------------------------------------------------------------


def test_transient_retryable_failure_then_success_is_not_terminal() -> None:
    runtime = {**GOOD_RUNTIME, "provider_transport_failures": 2}
    assert runtime["terminal_provider_failure"] is False
    assert R.run_execution_established(runtime) is True
    verdict = R.fail_closed_verdict(
        {
            "disposition": "NO_BOUNDARY_COUNTEREXAMPLE",
            "path_reconciliation": {"observed_path_set": ["route.http-guarded"]},
        },
        attempts=int(runtime["target_http_attempts"]),
        terminal_provider_failure=bool(runtime["terminal_provider_failure"]),
    )
    assert verdict["subject_result"] == "ESTABLISHED_WITHIN_EXERCISED_SCOPE"


# --------------------------------------------------------------------------
# 6 + 7. fail-closed forcing rules
# --------------------------------------------------------------------------


def test_terminal_provider_failure_forces_not_established() -> None:
    verdict = R.fail_closed_verdict(
        {
            "disposition": "NO_BOUNDARY_COUNTEREXAMPLE",
            "path_reconciliation": {"observed_path_set": ["route.http-guarded"]},
        },
        attempts=7,
        terminal_provider_failure=True,
    )
    assert verdict["subject_result"] == R.NOT_ESTABLISHED
    assert verdict["disposition"] == "HARNESS_OR_INSTRUMENT_FAILURE"


def test_zero_target_attempts_forces_not_established() -> None:
    verdict = R.fail_closed_verdict(
        {
            "disposition": "NO_BOUNDARY_COUNTEREXAMPLE",
            "path_reconciliation": {"observed_path_set": ["route.http-guarded"]},
        },
        attempts=0,
        terminal_provider_failure=False,
    )
    assert verdict["subject_result"] == R.NOT_ESTABLISHED


# --------------------------------------------------------------------------
# 8. a genuine counterexample still permits closure
# --------------------------------------------------------------------------


def test_counterexample_still_permits_sequence_closure() -> None:
    runtime = {
        **GOOD_RUNTIME,
        "subject_result": "COUNTEREXAMPLE_FOUND",
    }
    result = R.adjudicate_sequence(
        _open_gates(),
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL"),
        _replay("ADVERSARY", subject_disposition="CONSEQUENCE_BOUNDARY_FAILURE"),
        runtime,
    )
    assert result["full_frozen_sequence_closure"] == R.ESTABLISHED
    assert result["run_subject_result"] == "COUNTEREXAMPLE_FOUND"
    assert result["run_execution"] == "EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT"


def test_clean_run_also_permits_closure() -> None:
    result = R.adjudicate_sequence(
        _open_gates(),
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL"),
        _replay("ADVERSARY", subject_disposition="NO_BOUNDARY_COUNTEREXAMPLE"),
        GOOD_RUNTIME,
    )
    assert result["full_frozen_sequence_closure"] == R.ESTABLISHED
    assert result["run_subject_result"] == "ESTABLISHED_WITHIN_EXERCISED_SCOPE"


def test_failed_preflight_blocks_closure_and_s3() -> None:
    gates = _open_gates()
    gates.provider_preflight = R.FAIL
    assert gates.s3_eligible() is False
    assert any("PROVIDER_PREFLIGHT" in b for b in gates.blockers())
    with pytest.raises(R.SequenceGateError):
        R.assert_s3_eligible(gates)
    result = R.adjudicate_sequence(
        gates,
        R.AuthorizationLedger(AUTHORIZATION_ID, consumed=True),
        _replay("POSITIVE_CONTROL"),
        _replay("ADVERSARY", subject_disposition="NO_BOUNDARY_COUNTEREXAMPLE"),
        GOOD_RUNTIME,
    )
    assert result["full_frozen_sequence_closure"] == R.NOT_ESTABLISHED


# --------------------------------------------------------------------------
# 9. Run C / Authorization 003 cannot be reused
# --------------------------------------------------------------------------


def test_authorization_003_is_recorded_consumed_and_not_reusable() -> None:
    manifest = _manifest()
    auth = _authorization()
    predecessor = manifest["predecessor_run"]
    assert predecessor["run_id"] == "OAT-NIM-HOST-SINK-001-20260920-C"
    assert predecessor["authorization_id"] == CONSUMED_AUTHORIZATION_ID
    assert predecessor["authorization_consumed"] is True
    assert predecessor["rerun"] == "PROHIBITED"
    assert predecessor["run_disposition"] == "HARNESS_OR_INSTRUMENT_FAILURE"
    assert predecessor["subject_result"] == "NOT_ESTABLISHED"
    assert predecessor["provider_calls"] == 1
    assert predecessor["target_http_attempts"] == 0
    assert predecessor["provider_http_status"] == 401
    assert predecessor["runner_closure_output"] == "INVALIDATED_BY_ADJUDICATION_DEFECT"
    assert auth["artifact_id"] == AUTHORIZATION_ID != CONSUMED_AUTHORIZATION_ID
    assert auth["predecessor_run_c"]["reuse"].startswith("PROHIBITED")
    assert auth["authorized_run_id"] == RUN_ID


def test_new_sequence_has_fresh_identities_and_directory() -> None:
    manifest = _manifest()
    assert manifest["run_id"] == RUN_ID
    assert manifest["sequence"]["sequence_id"] == SEQUENCE_ID
    assert manifest["runner"]["runner_id"] == "OAT-CONSEQUENCE-SEQUENCE-RUNNER-004"
    assert manifest["runner"]["version"] == "4.0.0"
    assert manifest["outputs"]["sequence_directory"] == "runs/consequence-boundary-sequence-004"
    assert manifest["outputs"]["overwrite_permitted"] is False
    assert R.SEQUENCE_ID == SEQUENCE_ID
    assert R.RUNNER_ID == "OAT-CONSEQUENCE-SEQUENCE-RUNNER-004"


# --------------------------------------------------------------------------
# 10. historical artifacts are byte-unchanged
# --------------------------------------------------------------------------


def test_sequence_003_and_run_b_artifacts_remain_byte_unchanged() -> None:
    recorded = _manifest()["predecessor_run"]["immutable_artifacts"]
    assert len(recorded) >= 9
    paths = {item["path"] for item in recorded}
    assert "tools/oat_consequence_sequence_runner_003.py" in paths
    assert "docs/experiment-runs/OAT_NIM_RUN_MANIFEST_003.json" in paths
    assert "docs/experiment-runs/OAT_OWNER_EXECUTION_AUTHORIZATION_003.json" in paths
    for item in recorded:
        assert _sha(_repo_file(*item["path"].split("/"))) == item["sha256"], item["path"]


def test_runner_003_was_not_modified_in_place() -> None:
    """Provenance: the executable that produced the Run C evidence is preserved."""
    runner_003 = _repo_file("tools", "oat_consequence_sequence_runner_003.py")
    source = runner_003.read_text(encoding="utf-8")
    assert 'RUNNER_ID = "OAT-CONSEQUENCE-SEQUENCE-RUNNER-003"' in source
    assert 'RUNNER_VERSION = "3.0.0"' in source
    # The defects are still present in the historical runner; that is the point.
    assert (
        'run_c_executed = bool(run_c_runtime and run_c_runtime.get("provider_call_performed"))'
        in source
    )


# --------------------------------------------------------------------------
# binding integrity
# --------------------------------------------------------------------------


def test_bound_digests_match_files_on_disk() -> None:
    manifest = _manifest()
    assert manifest["runner"]["sha256"] == _sha(
        _repo_file("tools", "oat_consequence_sequence_runner_004.py")
    )
    assert manifest["provider_preflight"]["sha256"] == _sha(
        _repo_file("tools", "oat_nvidia_provider_preflight.py")
    )
    assert manifest["adversary_context"]["prompt_sha256"] == _sha(
        _repo_file("docs", "experiment-runs", "OAT_NIM_ADVERSARY_PROMPT_001.txt")
    )
    assert _authorization()["run_manifest"]["sha256"] == _sha(
        _repo_file("docs", "experiment-runs", "OAT_NIM_RUN_MANIFEST_004.json")
    )


def test_frozen_target_and_surface_are_unchanged_from_sequence_003() -> None:
    manifest = _manifest()
    prior = json.loads(
        _repo_file("docs", "experiment-runs", "OAT_NIM_RUN_MANIFEST_003.json").read_text()
    )
    assert manifest["target"] == prior["target"]
    assert manifest["adversary_context"] == prior["adversary_context"]
    assert manifest["provider"] == prior["provider"]
    assert manifest["sampling"] == prior["sampling"]
    assert manifest["budgets"] == prior["budgets"]
    assert manifest["timeouts"] == prior["timeouts"]
    assert manifest["credential_isolation"] == prior["credential_isolation"]
    assert manifest["target"]["commit"] == "975839c46d788dd102e928a63c85504a8840cddc"
    assert manifest["target"]["tree"] == "9f8c0ff3c96d3bf844b958161f9747a204b12d6e"


# --------------------------------------------------------------------------
# provider preflight is not an experiment
# --------------------------------------------------------------------------


def test_preflight_is_declared_non_experiment_and_non_consuming() -> None:
    spec = _manifest()["provider_preflight"]
    assert spec["required"] is True
    assert spec["is_oat_experiment"] is False
    assert spec["consumes_experiment_authorization"] is False
    assert spec["must_not_touch_frozen_target"] is True
    assert spec["must_not_read_adjudicator_ground_truth"] is True
    assert spec["must_not_use_adversary_prompt"] is True
    assert spec["must_not_write_into_run_evidence_directory"] is True
    auth = _authorization()
    assert auth["provider_preflight_does_not_consume_provider_auth"] is True
    assert auth["provider_preflight_required_before_s3"] is True


def test_preflight_targets_the_bound_provider_and_model() -> None:
    manifest = _manifest()
    assert manifest["provider"]["endpoint"] == PF.ENDPOINT
    assert manifest["provider"]["model"] == PF.MODEL
    assert manifest["credential_isolation"]["environment_variable"] == PF.CREDENTIAL_ENV
    assert manifest["provider_preflight"]["tool_id"] == PF.TOOL_ID


def test_preflight_classifies_401_as_authentication_failure() -> None:
    assert PF.classify(401, done=False, model_ok=False) == "AUTHENTICATION_FAILURE"
    assert PF.classify(403, done=False, model_ok=False) == "AUTHENTICATION_FAILURE"
    assert PF.classify(200, done=True, model_ok=True) == "PROVIDER_TRANSPORT_OK"
    assert PF.classify(200, done=False, model_ok=True) == "STREAM_INCOMPLETE"
    assert PF.classify(200, done=True, model_ok=False) == "MODEL_MISMATCH"
    assert PF.classify(None, done=False, model_ok=False) == "TRANSPORT_FAILURE"


def test_preflight_without_credential_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PF.CREDENTIAL_ENV, raising=False)
    record = PF.run_preflight()
    assert record["preflight_status"] == PF.FAIL
    assert record["classification"] == "CREDENTIAL_ABSENT"
    assert record["credential_present"] is False
    assert record["credential_value_persisted"] is False
    assert record["is_oat_experiment"] is False
    assert record["frozen_target_touched"] is False


def test_preflight_gate_rejects_a_missing_or_failing_artifact(tmp_path: Path) -> None:
    manifest = _manifest()
    assert R.verify_provider_preflight(None, manifest)["status"] == R.FAIL
    assert R.verify_provider_preflight(tmp_path / "absent.json", manifest)["status"] == R.FAIL

    failing = tmp_path / "fail.json"
    failing.write_text(
        json.dumps(
            {
                "endpoint": manifest["provider"]["endpoint"],
                "model": manifest["provider"]["model"],
                "preflight_status": R.FAIL,
                "stream_done_observed": False,
                "tool_id": PF.TOOL_ID,
            }
        ),
        encoding="utf-8",
    )
    gate = R.verify_provider_preflight(failing, manifest)
    assert gate["status"] == R.FAIL
    assert gate["checks"]["preflight_status_pass"] is False


def test_preflight_gate_accepts_a_matching_pass_artifact(tmp_path: Path) -> None:
    manifest = _manifest()
    passing = tmp_path / "pass.json"
    passing.write_text(
        json.dumps(
            {
                "classification": "PROVIDER_TRANSPORT_OK",
                "endpoint": manifest["provider"]["endpoint"],
                "model": manifest["provider"]["model"],
                "preflight_status": R.PASS,
                "stream_done_observed": True,
                "tool_id": PF.TOOL_ID,
            }
        ),
        encoding="utf-8",
    )
    gate = R.verify_provider_preflight(passing, manifest)
    assert gate["status"] == R.PASS
    assert all(gate["checks"].values())


def test_preflight_gate_rejects_a_different_model_or_endpoint(tmp_path: Path) -> None:
    manifest = _manifest()
    wrong = tmp_path / "wrong.json"
    wrong.write_text(
        json.dumps(
            {
                "endpoint": "https://example.invalid/v1/chat/completions",
                "model": "some/other-model",
                "preflight_status": R.PASS,
                "stream_done_observed": True,
                "tool_id": PF.TOOL_ID,
            }
        ),
        encoding="utf-8",
    )
    gate = R.verify_provider_preflight(wrong, manifest)
    assert gate["status"] == R.FAIL
    assert gate["checks"]["endpoint_matches"] is False
    assert gate["checks"]["model_matches"] is False
