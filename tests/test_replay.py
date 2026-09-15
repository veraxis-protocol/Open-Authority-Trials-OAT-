"""Deterministic replay without the adversary."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from oat.pipeline import run_scenario
from oat.replay import ReplayError, canonical_replay_bytes, replay_run
from oat.verifier import v1
from tests.conftest import scenario_path


@pytest.mark.parametrize("name", ["VULN-A", "VULN-B", "CONTROL"])
def test_two_replays_are_byte_identical(name: str, tmp_path: Path) -> None:
    run_dir = tmp_path / name
    run_scenario(scenario_path(name), out_dir=run_dir)

    first = replay_run(run_dir)
    second = replay_run(run_dir)

    assert canonical_replay_bytes(first) == canonical_replay_bytes(second)
    assert first["recomputed_evidence_digest"] == second["recomputed_evidence_digest"]
    assert first["canonical_result_digest"] == second["canonical_result_digest"]
    assert first["replay_ok"] and second["replay_ok"]


def test_replay_reproduces_the_recorded_disposition_and_digest(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run = run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    replay = replay_run(run_dir)

    assert replay["trace_match"] is True
    assert replay["witness_match"] is True
    assert replay["evidence_digest_match"] is True
    assert replay["disposition_match"] is True
    assert replay["recomputed_evidence_digest"] == run["verifier_result"]["evidence_digest"]
    assert replay["disposition"] == v1.DISPOSITION_COUNTEREXAMPLE


def test_replay_does_not_use_the_adversary(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("CONTROL"), out_dir=run_dir)
    replay = replay_run(run_dir)
    assert replay["adversary_used"] is False
    assert replay["disposition"] == v1.DISPOSITION_NO_COUNTEREXAMPLE


def test_replay_can_write_its_result(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    replay_run(run_dir, write=True)
    assert (run_dir / "replay-result.json").is_file()


def test_replay_falls_back_to_the_conventional_scenario_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, repo_root: Path
) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)

    workspace = tmp_path / "workspace"
    shutil.copytree(repo_root / "scenarios", workspace / "scenarios")
    monkeypatch.chdir(workspace)

    from oat.manifest import read_json, write_json

    manifest = read_json(run_dir / "manifest.json")
    del manifest["runtime"]["scenario_source"]
    write_json(run_dir / "manifest.json", manifest)

    assert replay_run(run_dir)["replay_ok"] is True


def test_replay_refuses_when_the_scenario_source_is_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)

    from oat.manifest import read_json, write_json

    manifest = read_json(run_dir / "manifest.json")
    manifest["runtime"]["scenario_source"] = "nowhere/VULN-A.json"
    manifest["scenario"]["name"] = "ABSENT.json"
    write_json(run_dir / "manifest.json", manifest)

    monkeypatch.chdir(tmp_path)
    with pytest.raises(ReplayError, match="cannot locate scenario source"):
        replay_run(run_dir)


def test_checked_in_reference_run_replays_cleanly(at_repo_root: Path) -> None:
    replay = replay_run(at_repo_root / "examples" / "rb001" / "reference-run")
    assert replay["replay_ok"] is True


def test_checked_in_reference_run_is_interpreter_independent(at_repo_root: Path) -> None:
    """Checked-in evidence must be byte-identical whichever supported interpreter wrote it."""
    import json
    import sys

    run_dir = at_repo_root / "examples" / "rb001" / "reference-run"
    version = ".".join(str(part) for part in sys.version_info[:2])
    for path in sorted(run_dir.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert "runtime" not in document, f"{path.name} carries runtime metadata"
        assert version not in path.read_text(encoding="utf-8")


def test_stripping_runtime_preserves_every_digest(tmp_path: Path) -> None:
    from oat.pipeline import strip_runtime_from_run_dir, verify_sha256sums

    run_dir = tmp_path / "run"
    run = run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    replay_run(run_dir, write=True)

    rewritten = strip_runtime_from_run_dir(run_dir)
    assert rewritten
    assert verify_sha256sums(run_dir)["ok"] is True
    after = replay_run(run_dir)
    assert after["replay_ok"] is True
    assert after["recomputed_evidence_digest"] == run["verifier_result"]["evidence_digest"]
