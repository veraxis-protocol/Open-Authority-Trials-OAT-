"""The instrument must reject invalid bindings and tampered evidence.

Each test seeds a specific defect and asserts the exact rejection reason: a
verifier that rejects everything for the wrong reason is not evidence either.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from oat.digest import digest_object
from oat.manifest import write_json
from oat.pipeline import run_scenario, verify_sha256sums
from oat.verifier import v1
from tests.conftest import scenario_path


@pytest.fixture
def run(tmp_path: Path) -> dict[str, Any]:
    return run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "run")


def _verify(run: dict[str, Any], witness: dict[str, Any]) -> dict[str, Any]:
    return v1.verify(witness, expected_manifest=run["manifest"])


def test_clean_witness_is_accepted(run: dict[str, Any]) -> None:
    assert _verify(run, run["witness"])["disposition"] == v1.DISPOSITION_COUNTEREXAMPLE


def test_schema_invalid_witness_is_rejected(run: dict[str, Any]) -> None:
    witness = copy.deepcopy(run["witness"])
    del witness["trace_digest"]
    result = _verify(run, witness)
    assert result["disposition"] == v1.DISPOSITION_REJECTED
    assert result["rejection_reason"] == v1.REJECT_SCHEMA_INVALID
    assert result["detail"]


def test_wrong_manifest_binding_is_rejected(run: dict[str, Any]) -> None:
    witness = copy.deepcopy(run["witness"])
    witness["manifest_digest"] = "sha256:" + "0" * 64
    result = _verify(run, witness)
    assert result["rejection_reason"] == v1.REJECT_MANIFEST_BINDING


def test_mutating_the_manifest_breaks_the_binding(run: dict[str, Any]) -> None:
    manifest = copy.deepcopy(run["manifest"])
    manifest["scenario"]["digest"] = "sha256:" + "1" * 64
    result = v1.verify(run["witness"], expected_manifest=manifest)
    assert result["rejection_reason"] == v1.REJECT_MANIFEST_BINDING


def test_wrong_scenario_target_is_rejected(run: dict[str, Any]) -> None:
    result = v1.verify(run["witness"], expected_scenario_id="RB-001-CONTROL")
    assert result["rejection_reason"] == v1.REJECT_SCENARIO_IDENTITY


def test_trace_scenario_identity_must_match_the_witness(run: dict[str, Any]) -> None:
    witness = copy.deepcopy(run["witness"])
    witness["trace"]["scenario_id"] = "RB-001-CONTROL"
    witness["trace_digest"] = digest_object(witness["trace"])
    result = _verify(run, witness)
    assert result["rejection_reason"] == v1.REJECT_SCENARIO_IDENTITY


def test_tampered_canonical_bytes_are_detected(run: dict[str, Any]) -> None:
    """Flip the committed flag without refreshing the bound digest."""
    witness = copy.deepcopy(run["witness"])
    for event in witness["trace"]["events"]:
        if event["event"] == "consequence_committed":
            event["committed"] = False
    result = _verify(run, witness)
    assert result["rejection_reason"] == v1.REJECT_TAMPERED_BYTES


def test_adversary_cannot_assert_a_verdict_the_trace_does_not_support(
    run: dict[str, Any],
) -> None:
    """Re-digest a doctored trace so only recomputation can catch the lie."""
    witness = copy.deepcopy(run["witness"])
    for event in witness["trace"]["events"]:
        if event["event"] == "consequence_committed":
            event["committed"] = False
    witness["trace_digest"] = digest_object(witness["trace"])
    result = _verify(run, witness)
    assert result["rejection_reason"] == v1.REJECT_CLAIM_MISMATCH
    assert result["computational_result"] is False


def test_changed_falsifier_identity_is_detected(run: dict[str, Any]) -> None:
    witness = copy.deepcopy(run["witness"])
    witness["falsifier"]["digest"] = "sha256:" + "2" * 64
    result = _verify(run, witness)
    assert result["rejection_reason"] == v1.REJECT_FALSIFIER_IDENTITY


def test_unsupported_falsifier_version_is_detected(run: dict[str, Any]) -> None:
    witness = copy.deepcopy(run["witness"])
    witness["falsifier"]["version"] = "9.9.9"
    result = _verify(run, witness)
    assert result["rejection_reason"] == v1.REJECT_FALSIFIER_UNSUPPORTED


def test_unevaluable_trace_is_rejected_not_guessed(run: dict[str, Any]) -> None:
    witness = copy.deepcopy(run["witness"])
    witness["trace"]["events"] = [
        e for e in witness["trace"]["events"] if e["event"] != "consequence_committed"
    ]
    witness["trace_digest"] = digest_object(witness["trace"])
    result = _verify(run, witness)
    assert result["rejection_reason"] == v1.REJECT_UNEVALUABLE


def test_rejections_still_carry_quarantine_labels(run: dict[str, Any]) -> None:
    witness = copy.deepcopy(run["witness"])
    witness["falsifier"]["version"] = "9.9.9"
    result = _verify(run, witness)
    assert result["run_mode"] == "METHOD_DEVELOPMENT_ONLY"
    assert result["claim_bearing_use"] == "PROHIBITED"


def test_sha256sums_detects_a_modified_run_file(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    assert verify_sha256sums(run_dir)["ok"] is True

    doc = {"tampered": True}
    write_json(run_dir / "verifier-result.json", doc)
    report = verify_sha256sums(run_dir)
    assert report["ok"] is False
    assert any("verifier-result.json" in line for line in report["detail"])


def test_sha256sums_detects_a_deleted_run_file(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    (run_dir / "witness.json").unlink()
    report = verify_sha256sums(run_dir)
    assert report["ok"] is False
    assert any("missing" in line for line in report["detail"])


def test_missing_sha256sums_is_not_silently_ok(tmp_path: Path) -> None:
    report = verify_sha256sums(tmp_path)
    assert report["ok"] is False
    assert report["checked"] == 0


def test_schema_invalid_trace_inside_a_valid_witness_is_rejected(run: dict[str, Any]) -> None:
    """The witness envelope can be well formed while the trace it carries is not."""
    witness = copy.deepcopy(run["witness"])
    witness["trace"]["enforcement_path"] = "NOT_A_PATH"
    witness["trace_digest"] = digest_object(witness["trace"])
    result = _verify(run, witness)
    assert result["rejection_reason"] == v1.REJECT_SCHEMA_INVALID
    assert any("enforcement_path" in line for line in result["detail"])


def test_witness_digest_helper_matches_canonical_digest(run: dict[str, Any]) -> None:
    from oat.witness import witness_digest

    assert witness_digest(run["witness"]) == digest_object(run["witness"])
    assert run["verifier_result"]["witness_digest"] == witness_digest(run["witness"])
