"""Adversary determinism and the limits of what an adversary may do."""

from __future__ import annotations

from pathlib import Path

import pytest

from oat.adversaries.base import ProviderAdversary
from oat.adversaries.deterministic import DeterministicAdversary
from oat.manifest import load_scenario_package
from tests.conftest import scenario_path


def test_candidate_order_is_deterministic() -> None:
    package = load_scenario_package(scenario_path("VULN-B"))
    first = [v.to_dict() for v in DeterministicAdversary().propose(package.scenario)]
    second = [v.to_dict() for v in DeterministicAdversary().propose(package.scenario)]
    assert first == second
    assert len(first) == len({repr(v) for v in first})


def test_search_covers_the_declared_dimensions() -> None:
    package = load_scenario_package(scenario_path("VULN-B"))
    variations = list(DeterministicAdversary().propose(package.scenario))
    assert {v.retry_index for v in variations} == {0, 1}
    assert {v.duplicate_request for v in variations} == {False, True}
    assert {v.propagation_delay for v in variations} == {0, 4, 12, 25}
    # Race ordering in both directions: commit before and after the revocation.
    assert any(v.commit_tick < v.revocation_tick for v in variations)
    assert any(v.commit_tick > v.revocation_tick for v in variations)


def test_candidate_budget_is_honoured() -> None:
    package = load_scenario_package(scenario_path("CONTROL"))
    assert len(list(DeterministicAdversary(max_candidates=3).propose(package.scenario))) == 3


def test_malformed_search_space_is_refused() -> None:
    package = load_scenario_package(scenario_path("VULN-A"))
    object.__setattr__(package.scenario, "search_space", {"retry_index": []})
    with pytest.raises(ValueError, match="non-empty list"):
        list(DeterministicAdversary().propose(package.scenario))


def test_adversary_identity_is_recorded() -> None:
    identity = DeterministicAdversary().identity()
    assert identity["id"] == "OAT-ADVERSARY-DETERMINISTIC"
    assert identity["kind"] == "local-deterministic"
    assert identity["strategy"] == "ordered-grid-search"


def test_provider_adversary_is_an_interface_not_a_run() -> None:
    """A provider run that did not happen must never look like one that did."""
    provider = ProviderAdversary()
    package = load_scenario_package(scenario_path("VULN-A"))
    assert provider.kind == "provider"
    assert "interface-only" in provider.version
    with pytest.raises(NotImplementedError, match="No provider adversary is configured"):
        list(provider.propose(package.scenario))


def test_every_candidate_is_captured_in_the_transcript(tmp_path: Path) -> None:
    """The runbook requires all candidate witnesses to be captured, not just the winner."""
    from oat.pipeline import run_scenario

    run = run_scenario(scenario_path("CONTROL"), out_dir=tmp_path / "run")
    search = run["witness"]["search"]
    transcript = search["transcript"]

    assert len(transcript) == search["candidates_explored"]
    assert [entry["index"] for entry in transcript] == list(range(len(transcript)))
    assert all(entry["counterexample"] is False for entry in transcript)
    assert all(entry["trace_digest"].startswith("sha256:") for entry in transcript)


def test_transcript_stops_at_the_first_counterexample(tmp_path: Path) -> None:
    from oat.pipeline import run_scenario

    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "run")
    search = run["witness"]["search"]
    transcript = search["transcript"]

    assert transcript[-1]["index"] == search["selected_candidate_index"]
    assert transcript[-1]["counterexample"] is True
    assert all(entry["counterexample"] is False for entry in transcript[:-1])


def test_a_silent_adversary_is_an_error_not_an_acquittal() -> None:
    """Zero candidates must raise, never read as 'nothing found'."""
    from collections.abc import Iterator

    from oat.adversaries.base import Adversary
    from oat.pipeline import search
    from oat.reference_boundaries.rb001 import Scenario, Variation

    class SilentAdversary(Adversary):
        id = "OAT-ADVERSARY-SILENT"
        version = "0.0.0"

        def propose(self, scenario: Scenario) -> Iterator[Variation]:
            return iter(())

    package = load_scenario_package(scenario_path("VULN-A"))
    with pytest.raises(ValueError, match="proposed no candidates"):
        search(package, SilentAdversary())
