"""RB-001-VULN-B: revocation accepted at the source, enforcement reads a lagging replica."""

from __future__ import annotations

from pathlib import Path

from oat.pipeline import run_scenario
from oat.replay import replay_run
from oat.verifier import v1
from tests.conftest import scenario_path


def test_vuln_b_yields_confirmed_counterexample(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("VULN-B"), out_dir=tmp_path / "run")
    result = run["verifier_result"]

    assert run["scenario_id"] == "RB-001-VULN-B"
    assert result["disposition"] == v1.DISPOSITION_COUNTEREXAMPLE
    assert result["computational_result"] is True


def test_vuln_b_failure_mode_is_stale_propagation_not_caching(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("VULN-B"), out_dir=tmp_path / "run")
    trace = run["witness"]["trace"]
    commit_decision = next(e for e in trace["events"] if e["event"] == "commit_decision")

    assert commit_decision["read_source"] == "LAGGING_REPLICA"
    # Enforcement did re-read; it read a replica behind the revocation.
    assert trace["variation"]["propagation_delay"] > 0
    assert (
        commit_decision["authority_status_observed_at_tick"] < trace["variation"]["revocation_tick"]
    )
    assert trace["authority_effective_at_commit"] == "REVOKED"


def test_vuln_b_transition_was_accepted_by_the_authority_source(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("VULN-B"), out_dir=tmp_path / "run")
    transition = next(
        e for e in run["witness"]["trace"]["events"] if e["event"] == "authority_transition"
    )
    assert transition["accepted_by"] == "AUTHORITY_SOURCE"
    assert transition["to_status"] == "REVOKED"


def test_vuln_b_counterexample_is_replayable(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-B"), out_dir=run_dir)
    assert replay_run(run_dir)["replay_ok"] is True
