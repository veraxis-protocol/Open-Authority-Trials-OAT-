"""RB-001-VULN-A: authorization checked once and cached; commit uses the stale decision."""

from __future__ import annotations

from pathlib import Path

from oat.pipeline import run_scenario
from oat.replay import replay_run
from oat.verifier import v1
from tests.conftest import scenario_path


def test_vuln_a_yields_confirmed_counterexample(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "run")
    result = run["verifier_result"]

    assert run["scenario_id"] == "RB-001-VULN-A"
    assert result["disposition"] == v1.DISPOSITION_COUNTEREXAMPLE
    assert result["computational_result"] is True
    assert result["rejection_reason"] is None


def test_vuln_a_counterexample_is_a_genuine_toctou(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "run")
    trace = run["witness"]["trace"]
    commit_decision = next(e for e in trace["events"] if e["event"] == "commit_decision")
    committed = next(e for e in trace["events"] if e["event"] == "consequence_committed")

    # The consequence was committed while authority was, in ground truth, revoked.
    assert committed["committed"] is True
    assert trace["authority_effective_at_commit"] == "REVOKED"
    # ...because enforcement reused a decision taken before the revocation.
    assert commit_decision["read_source"] == "CACHED_DECISION"
    assert commit_decision["authority_status_used"] == "ACTIVE"
    assert trace["variation"]["check_tick"] < trace["variation"]["revocation_tick"]
    assert trace["commit_tick"] >= trace["variation"]["revocation_tick"]


def test_vuln_a_counterexample_is_replayable(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    replay = replay_run(run_dir)

    assert replay["replay_ok"] is True
    assert replay["disposition"] == v1.DISPOSITION_COUNTEREXAMPLE
    assert replay["adversary_used"] is False


def test_vuln_a_predicate_trace_is_explicit(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "run")
    predicates = {e["predicate"]: e["result"] for e in run["verifier_result"]["predicate_trace"]}
    assert predicates == {
        "committed": True,
        "authority_effective_at_commit_is_revoked": True,
    }
