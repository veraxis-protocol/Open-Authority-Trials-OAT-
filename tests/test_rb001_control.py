"""RB-001-CONTROL: authority re-evaluated at the commit boundary.

The control is as important as the vulnerable variants: a false counterexample
here means the instrument itself is broken.
"""

from __future__ import annotations

from pathlib import Path

from oat.adversaries.deterministic import DeterministicAdversary
from oat.falsifiers import rb001 as rb001_falsifier
from oat.manifest import load_scenario_package
from oat.pipeline import run_scenario
from oat.reference_boundaries import rb001
from oat.verifier import v1
from tests.conftest import scenario_path


def test_control_produces_no_counterexample(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("CONTROL"), out_dir=tmp_path / "run")
    result = run["verifier_result"]

    assert result["disposition"] == v1.DISPOSITION_NO_COUNTEREXAMPLE
    assert result["computational_result"] is False
    assert result["rejection_reason"] is None


def test_control_search_space_is_exhausted_not_truncated(tmp_path: Path) -> None:
    """A control that passes because the search gave up early proves nothing."""
    package = load_scenario_package(scenario_path("CONTROL"))
    adversary = DeterministicAdversary()
    total = sum(1 for _ in adversary.propose(package.scenario))
    run = run_scenario(scenario_path("CONTROL"), out_dir=tmp_path / "run")

    assert total > 1
    assert run["witness"]["search"]["candidates_explored"] == total


def test_control_never_commits_after_effective_revocation() -> None:
    package = load_scenario_package(scenario_path("CONTROL"))
    for variation in DeterministicAdversary().propose(package.scenario):
        trace = rb001.execute(package.scenario, variation)
        evaluation = rb001_falsifier.evaluate(trace)
        assert evaluation["counterexample"] is False
        if trace["authority_effective_at_commit"] == "REVOKED":
            committed = next(e for e in trace["events"] if e["event"] == "consequence_committed")
            assert committed["committed"] is False


def test_control_still_commits_when_authority_is_live() -> None:
    """The control must not pass trivially by refusing everything."""
    package = load_scenario_package(scenario_path("CONTROL"))
    variation = rb001.Variation(check_tick=5, revocation_tick=100, commit_tick=10)
    trace = rb001.execute(package.scenario, variation)
    committed = next(e for e in trace["events"] if e["event"] == "consequence_committed")

    assert trace["authority_effective_at_commit"] == "ACTIVE"
    assert committed["committed"] is True
    assert rb001_falsifier.evaluate(trace)["counterexample"] is False


def test_falsifier_refuses_a_trace_without_events() -> None:
    """An unevaluable trace must raise, never default to 'no counterexample'."""
    import pytest

    with pytest.raises(rb001_falsifier.FalsifierError, match="no events list"):
        rb001_falsifier.evaluate({"authority_effective_at_commit": "REVOKED"})

    with pytest.raises(rb001_falsifier.FalsifierError, match="exactly one"):
        rb001_falsifier.evaluate({"events": [], "authority_effective_at_commit": "REVOKED"})
