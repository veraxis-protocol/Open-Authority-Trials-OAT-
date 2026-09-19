"""Deterministic controls for the consequence-boundary instrument (work order §24).

Each test names the control it establishes. The controls exist to keep the
instrument honest in both directions: it must catch the crossing it is meant
to catch, and it must refuse to call anything else a crossing.
"""

from __future__ import annotations

import pytest

from oat.consequence.scenarios import SCENARIOS
from oat.consequence.sink import ADMITTED, REFUSED
from oat.evidence.replay import replay_scenario, run_scenario
from oat.verifier.consequence import ConsequenceDisposition as D


def _scenario(name: str):
    return SCENARIOS[name]()


def _last_interlock(scenario):
    assert scenario.sink.interlock_log, "expected the interlock to have been exercised"
    return scenario.sink.interlock_log[-1]


# --- KNOWN_VULNERABLE_BYPASS_DETECTED ---------------------------------


def test_known_vulnerable_bypass_detected():
    package = run_scenario("hidden-route-bypass")
    assert package["verdict"]["disposition"] == D.CONSEQUENCE_BOUNDARY_FAILURE.value
    finding = package["verdict"]["findings"][0]
    assert finding["disposition"] == D.CONSEQUENCE_BOUNDARY_FAILURE.value
    # It is a crossing because a protected consequence durably committed.
    assert package["sink"]["state"]["commits"], "the bypass must actually commit something"


# --- SAFE_GUARDED_ROUTE_NOT_FALSE_POSITIVE ----------------------------


def test_safe_guarded_route_not_false_positive():
    scenario = _scenario("guarded-valid")
    assert _last_interlock(scenario).outcome == ADMITTED
    # The commit must genuinely land; a refusal here would make this control
    # pass for the wrong reason.
    assert len(scenario.sink.state.commits) == 1
    package = run_scenario("guarded-valid")
    assert package["verdict"]["disposition"] == D.NO_BOUNDARY_COUNTEREXAMPLE.value


# --- HIDDEN_ROUTE_DISCOVERED ------------------------------------------


def test_hidden_route_discovered():
    package = run_scenario("hidden-route-bypass")
    reconciliation = package["verdict"]["path_reconciliation"]
    assert "route.batch-replay" in reconciliation["unknown_observed_paths"]
    assert "route.batch-replay" not in reconciliation["declared_path_set"]


def test_hidden_route_alone_is_not_a_boundary_counterexample():
    """Discovering an undeclared route is an integration finding, not a crossing."""
    package = run_scenario("hidden-route-authorized")
    reconciliation = package["verdict"]["path_reconciliation"]
    assert "route.batch-replay" in reconciliation["unknown_observed_paths"]
    assert package["verdict"]["disposition"] == D.INTEGRATION_FAILURE.value


# --- authority state controls -----------------------------------------


def test_stale_authority_blocked_or_detected():
    scenario = _scenario("stale-authority")
    decision = _last_interlock(scenario)
    assert decision.outcome == REFUSED
    assert "authority_state_at_commit" in decision.dimensions["failed_dimensions"]
    assert not scenario.sink.state.commits


def test_revoked_authority_blocked_or_detected():
    scenario = _scenario("revoked-authority")
    decision = _last_interlock(scenario)
    assert decision.outcome == REFUSED
    assert "revocation_state" in decision.dimensions["failed_dimensions"]


# --- replay / idempotency ---------------------------------------------


def test_replay_blocked_or_detected():
    scenario = _scenario("replay")
    assert len(scenario.sink.state.commits) == 1, "the second presentation must not commit"
    assert scenario.sink.interlock_log[-1].outcome == REFUSED
    assert scenario.sink.interlock_log[-1].reason == "IDEMPOTENCY_REPLAY"


def test_race_duplicate_consequence_blocked_or_detected():
    scenario = _scenario("race-duplicate")
    commit_ids = [c.commit_id for c in scenario.sink.state.commits]
    assert len(commit_ids) == len(set(commit_ids)) == 1


# --- exact binding controls -------------------------------------------


@pytest.mark.parametrize(
    ("scenario_name", "dimension"),
    [
        ("wrong-principal", "principal"),
        ("wrong-release", "release_identity"),
        ("wrong-tenant", "tenant"),
        ("wrong-sink", "protected_sink"),
        ("exact-action-mutation", "exact_action_digest"),
    ],
)
def test_exact_binding_mismatch_blocked_or_detected(scenario_name: str, dimension: str):
    scenario = _scenario(scenario_name)
    decision = _last_interlock(scenario)
    assert decision.outcome == REFUSED
    assert dimension in decision.dimensions["failed_dimensions"]
    assert not scenario.sink.state.commits


def test_invalid_delegation_blocked_or_detected():
    scenario = _scenario("invalid-delegation")
    decision = _last_interlock(scenario)
    assert decision.outcome == REFUSED
    failed = decision.dimensions["failed_dimensions"]
    assert "delegation_chain" in failed or "non_amplification" in failed


# --- taxonomy separation ----------------------------------------------


def test_local_internal_defect_with_no_commit_is_not_boundary_ce():
    package = run_scenario("internal-defect-no-commit")
    assert package["verdict"]["disposition"] == D.VEIP_INTERNAL_PROPERTY_FAILURE.value
    assert not package["sink"]["state"]["commits"]


def test_incomplete_evidence_returns_unknown():
    package = run_scenario("incomplete-evidence")
    assert package["verdict"]["disposition"] == D.UNKNOWN_OR_UNESTABLISHED.value


def test_instrument_failure_quarantines_the_result():
    package = run_scenario("instrument-failure")
    assert package["verdict"]["disposition"] == D.HARNESS_OR_INSTRUMENT_FAILURE.value
    assert not package["verdict"]["findings"], "a broken instrument reports no subject findings"


# --- adversary has no authority ---------------------------------------


def test_adversary_assertion_alone_establishes_nothing():
    """No adversary input reaches the verifier at all.

    The strongest available form of this control: the verifier's evidence
    object has no field an adversary could populate.
    """
    from oat.verifier.consequence import ConsequenceEvidence

    fields = set(ConsequenceEvidence.__dataclass_fields__)
    assert not {"adversary", "assertion", "claimed_violation", "model_output"} & fields
    package = run_scenario("guarded-valid")
    assert package["provider_run_occurred"] is False


# --- determinism ------------------------------------------------------


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_scenario_replays_identically(name: str):
    first = run_scenario(name)
    ok, detail = replay_scenario(name, first)
    assert ok, detail
