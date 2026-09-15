"""Trial adjudication: the six frozen dispositions, and who is allowed to decide."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oat.pipeline import run_scenario
from oat.trial import (
    AdversaryAssertion,
    BudgetState,
    Disposition,
    TrialScope,
    adjudicate,
    supported_dispositions,
)
from oat.verifier import v1
from tests.conftest import scenario_path

SCOPE = TrialScope(
    in_scope_property_ids=frozenset({"P-1", "P-2"}),
    declared_attack_families=frozenset({"F-01", "F-02"}),
)


@pytest.fixture
def positive(tmp_path: Path) -> dict[str, Any]:
    return run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "a")["verifier_result"]


@pytest.fixture
def negative(tmp_path: Path) -> dict[str, Any]:
    return run_scenario(scenario_path("CONTROL"), out_dir=tmp_path / "c")["verifier_result"]


def claim(violation: bool = True, property_id: str = "P-1") -> AdversaryAssertion:
    return AdversaryAssertion("ATK-1", property_id, violation, "hypothesis")


def test_the_disposition_vocabulary_is_exactly_the_frozen_six() -> None:
    assert supported_dispositions() == [
        "COUNTEREXAMPLE_VALIDATED",
        "NOT_A_COUNTEREXAMPLE",
        "UNEVALUABLE",
        "OUTSIDE_SCOPE",
        "VERIFIER_CONFLICT",
        "COVERAGE_LIMITED",
    ]


def test_verified_counterexample_is_validated(positive: dict[str, Any]) -> None:
    result = adjudicate(claim(), [positive], SCOPE)
    assert result["disposition"] == Disposition.COUNTEREXAMPLE_VALIDATED.value


def test_an_assertion_alone_never_validates_anything(negative: dict[str, Any]) -> None:
    """The whole point: confidence is not evidence."""
    result = adjudicate(claim(violation=True), [negative], SCOPE)

    assert result["disposition"] == Disposition.NOT_A_COUNTEREXAMPLE.value
    assert result["adversary_assertion"]["claimed_violation"] is True
    assert any("not credited" in line for line in result["reasoning"])


def test_undeclared_property_is_out_of_scope(positive: dict[str, Any]) -> None:
    result = adjudicate(claim(property_id="P-UNDECLARED"), [positive], SCOPE)
    assert result["disposition"] == Disposition.OUTSIDE_SCOPE.value


def test_scope_is_checked_before_the_verdict(positive: dict[str, Any]) -> None:
    """An out-of-scope hit must not be smuggled in as a validated counterexample."""
    result = adjudicate(claim(property_id="P-UNDECLARED"), [positive], SCOPE)
    assert result["disposition"] != Disposition.COUNTEREXAMPLE_VALIDATED.value


def test_disagreeing_verifiers_surface_as_conflict(
    positive: dict[str, Any], negative: dict[str, Any]
) -> None:
    result = adjudicate(claim(), [positive, negative], SCOPE)
    assert result["disposition"] == Disposition.VERIFIER_CONFLICT.value
    assert any("disagree" in line for line in result["reasoning"])


def test_agreeing_verifiers_do_not_conflict(positive: dict[str, Any]) -> None:
    result = adjudicate(claim(), [positive, positive], SCOPE)
    assert result["disposition"] == Disposition.COUNTEREXAMPLE_VALIDATED.value


def test_rejected_evidence_is_unevaluable_not_a_clean_pass(
    positive: dict[str, Any], tmp_path: Path
) -> None:
    import copy

    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "t")
    witness = copy.deepcopy(run["witness"])
    witness["falsifier"]["version"] = "9.9.9"
    rejected = v1.verify(witness, expected_manifest=run["manifest"])

    result = adjudicate(claim(), [rejected], SCOPE)
    assert result["disposition"] == Disposition.UNEVALUABLE.value


def test_exhausted_budget_downgrades_a_negative_result(negative: dict[str, Any]) -> None:
    budget = BudgetState(20, 20, frozenset({"F-01", "F-02"}))
    result = adjudicate(claim(violation=False), [negative], SCOPE, budget=budget)

    assert result["disposition"] == Disposition.COVERAGE_LIMITED.value
    assert any("budget exhausted" in line for line in result["reasoning"])


def test_untested_families_downgrade_a_negative_result(negative: dict[str, Any]) -> None:
    budget = BudgetState(1, 20, frozenset({"F-01"}))
    result = adjudicate(claim(violation=False), [negative], SCOPE, budget=budget)

    assert result["disposition"] == Disposition.COVERAGE_LIMITED.value
    assert any("never attempted" in line for line in result["reasoning"])


def test_full_coverage_leaves_a_negative_result_intact(negative: dict[str, Any]) -> None:
    budget = BudgetState(5, 20, frozenset({"F-01", "F-02"}))
    result = adjudicate(claim(violation=False), [negative], SCOPE, budget=budget)
    assert result["disposition"] == Disposition.NOT_A_COUNTEREXAMPLE.value


def test_coverage_never_downgrades_a_validated_counterexample(positive: dict[str, Any]) -> None:
    """Exhausting the budget says nothing about a counterexample already proved."""
    budget = BudgetState(20, 20, frozenset())
    result = adjudicate(claim(), [positive], SCOPE, budget=budget)
    assert result["disposition"] == Disposition.COUNTEREXAMPLE_VALIDATED.value


def test_adjudication_records_quarantine_and_is_digest_bound(positive: dict[str, Any]) -> None:
    result = adjudicate(claim(), [positive], SCOPE)
    assert result["run_mode"] == "METHOD_DEVELOPMENT_ONLY"
    assert result["claim_bearing_use"] == "PROHIBITED"
    assert result["adjudication_digest"].startswith("sha256:")


def test_adjudication_requires_a_verifier_result() -> None:
    with pytest.raises(ValueError, match="at least one verifier result"):
        adjudicate(claim(), [], SCOPE)
