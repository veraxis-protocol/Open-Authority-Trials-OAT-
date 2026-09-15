"""Provider seam: a run that did not happen must never look like one that did."""

from __future__ import annotations

from pathlib import Path

import pytest

from oat.adversaries.provider import (
    NOT_EXPOSED,
    ProviderAdversary,
    ScriptedTransport,
    TransportError,
    UnconfiguredTransport,
)
from oat.dryrun import run_dry_run
from oat.manifest import load_scenario_package
from oat.pipeline import run_scenario
from tests.conftest import scenario_path


def test_default_transport_refuses_and_explains() -> None:
    adversary = ProviderAdversary()
    package = load_scenario_package(scenario_path("VULN-A"))

    assert adversary.provider_run_occurred is False
    with pytest.raises(TransportError, match="No provider transport is configured"):
        list(adversary.propose(package.scenario))


def test_unconfigured_transport_is_never_live() -> None:
    assert UnconfiguredTransport().is_live is False


def test_scripted_transport_is_never_reported_as_live() -> None:
    adversary = ProviderAdversary(transport=ScriptedTransport(["10,20,21\n"]))
    assert adversary.transport.is_live is False
    assert adversary.provider_run_occurred is False
    assert adversary.identity()["provider_run_occurred"] is False
    assert adversary.identity()["transport"] == "scripted-offline"


def test_unpinnable_config_fields_read_as_not_exposed() -> None:
    identity = ProviderAdversary().identity()
    assert identity["model"] == NOT_EXPOSED
    assert identity["endpoint"] == NOT_EXPOSED
    assert identity["config_digest"].startswith("sha256:")


def test_scripted_transport_exhausts_rather_than_inventing() -> None:
    transport = ScriptedTransport(["one"])
    assert transport.complete("p") == "one"
    with pytest.raises(TransportError, match="exhausted"):
        transport.complete("p")


def test_candidate_parsing_discards_unparseable_lines() -> None:
    adversary = ProviderAdversary(
        transport=ScriptedTransport(["10,20,21\nrubbish\n5,20,17,4,1,true\n"])
    )
    package = load_scenario_package(scenario_path("VULN-A"))
    variations = list(adversary.propose(package.scenario))

    assert len(variations) == 2
    assert variations[0].check_tick == 10
    assert variations[1].propagation_delay == 4
    assert variations[1].duplicate_request is True


def test_provider_candidates_flow_through_the_real_pipeline(tmp_path: Path) -> None:
    adversary = ProviderAdversary(transport=ScriptedTransport(["10,20,21\n"]))
    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "r", adversary=adversary)

    assert run["verifier_result"]["disposition"] == "COUNTEREXAMPLE_CONFIRMED"
    assert run["witness"]["adversary"]["kind"] == "provider"
    assert run["witness"]["adversary"]["provider_run_occurred"] is False


def test_assertions_are_labelled_as_claims_not_verdicts() -> None:
    adversary = ProviderAdversary(transport=ScriptedTransport([""]))
    assertion = adversary.assert_finding("ATK-9", "P-1", True, "why")

    assert assertion.claimed_violation is True
    assert assertion.adversary_identity["provider_run_occurred"] is False
    assert "disposition" not in assertion.to_dict()


def test_dry_run_passes_every_check_without_touching_a_subject(tmp_path: Path) -> None:
    report = run_dry_run(
        scenario_path("VULN-A"), scenario_path("CONTROL"), out_dir=tmp_path / "dry"
    )

    assert report["dryrun_ok"] is True
    assert report["veip_subject_exposed"] is False
    assert report["provider_run_occurred"] is False
    assert report["pipeline"]["replay_ok"] is True
    assert {c["check"] for c in report["checks"]} == {
        "validated_counterexample",
        "false_assertion_refused",
        "out_of_scope_refused",
        "verifier_conflict_surfaced",
        "coverage_limited_when_budget_exhausted",
        "no_provider_run_claimed",
    }
    assert (tmp_path / "dry" / "dryrun-report.json").is_file()


def test_dry_run_works_without_writing_anything() -> None:
    report = run_dry_run(scenario_path("VULN-A"), scenario_path("CONTROL"))
    assert report["dryrun_ok"] is True
    assert report["pipeline"]["replay_ok"] is None
