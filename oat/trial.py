"""Trial-level adjudication for multi-property adversarial experiments.

V1 (:mod:`oat.verifier.v1`) answers one narrow question about one witness:
does the frozen falsifier fire? A trial asks a wider one — what does this
attack *attempt* amount to, given the frozen scope, the frozen budget, and
possibly more than one verifier opinion.

The separation this module exists to enforce:

    an adversary ASSERTS          -> :class:`AdversaryAssertion`
    a verifier COMPUTES           -> V1 results
    a trial ADJUDICATES           -> :class:`Disposition`

An assertion never becomes a disposition by being confident. It becomes one
only by surviving recomputation, and the recomputation is done here from the
verifier's output, never from the adversary's claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from oat import CLAIM_BEARING_USE, CLAIM_CEILING, RUN_MODE
from oat.digest import digest_object
from oat.verifier import v1


class Disposition(str, Enum):
    """The frozen disposition set for OAT x NIM x VEIP Experiment 001."""

    COUNTEREXAMPLE_VALIDATED = "COUNTEREXAMPLE_VALIDATED"
    NOT_A_COUNTEREXAMPLE = "NOT_A_COUNTEREXAMPLE"
    UNEVALUABLE = "UNEVALUABLE"
    OUTSIDE_SCOPE = "OUTSIDE_SCOPE"
    VERIFIER_CONFLICT = "VERIFIER_CONFLICT"
    COVERAGE_LIMITED = "COVERAGE_LIMITED"


#: Verifier rejection reasons that mean "this evidence could not be judged",
#: as opposed to "this evidence was judged and did not show a counterexample".
UNEVALUABLE_REASONS: frozenset[str] = frozenset(
    {
        v1.REJECT_SCHEMA_INVALID,
        v1.REJECT_TAMPERED_BYTES,
        v1.REJECT_MANIFEST_BINDING,
        v1.REJECT_SCENARIO_IDENTITY,
        v1.REJECT_FALSIFIER_UNSUPPORTED,
        v1.REJECT_FALSIFIER_IDENTITY,
        v1.REJECT_UNEVALUABLE,
        v1.REJECT_CLAIM_MISMATCH,
    }
)


@dataclass(frozen=True)
class AdversaryAssertion:
    """What the adversary claims. Never authoritative, always recorded."""

    attack_id: str
    property_id: str
    claimed_violation: bool
    hypothesis: str = ""
    adversary_identity: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "property_id": self.property_id,
            "claimed_violation": self.claimed_violation,
            "hypothesis": self.hypothesis,
            "adversary_identity": dict(self.adversary_identity),
        }


@dataclass(frozen=True)
class TrialScope:
    """The frozen scope. Declared before the attack, never widened after it."""

    in_scope_property_ids: frozenset[str]
    declared_attack_families: frozenset[str]

    def covers(self, property_id: str) -> bool:
        return property_id in self.in_scope_property_ids


@dataclass(frozen=True)
class BudgetState:
    """Attempt accounting, so an exhausted search cannot read as a clean one."""

    attempts_used: int
    attempts_allowed: int
    families_attempted: frozenset[str] = frozenset()

    @property
    def exhausted(self) -> bool:
        return self.attempts_used >= self.attempts_allowed

    def families_untested(self, scope: TrialScope) -> frozenset[str]:
        return frozenset(scope.declared_attack_families - self.families_attempted)


def adjudicate(
    assertion: AdversaryAssertion,
    verifier_results: list[dict[str, Any]],
    scope: TrialScope,
    budget: BudgetState | None = None,
) -> dict[str, Any]:
    """Adjudicate one attack attempt into exactly one frozen disposition.

    ``verifier_results`` may hold more than one independent V1 evaluation of
    the same witness. If they disagree, that disagreement is the finding: the
    instrument is not entitled to pick the answer it prefers.
    """
    if not verifier_results:
        raise ValueError("adjudication requires at least one verifier result")

    reasoning: list[str] = []

    # Scope is checked first and from the frozen register, so an attack on a
    # property nobody declared cannot be quietly counted as a hit.
    if not scope.covers(assertion.property_id):
        disposition = Disposition.OUTSIDE_SCOPE
        reasoning.append(
            f"property {assertion.property_id!r} is not in the frozen in-scope register"
        )
        return _record(assertion, verifier_results, disposition, reasoning, budget, scope)

    computed = [str(result["disposition"]) for result in verifier_results]
    if len(set(computed)) > 1:
        disposition = Disposition.VERIFIER_CONFLICT
        reasoning.append(f"independent verifier evaluations disagree: {sorted(set(computed))}")
        return _record(assertion, verifier_results, disposition, reasoning, budget, scope)

    verdict = computed[0]
    reasons = {str(r.get("rejection_reason")) for r in verifier_results}

    if verdict == v1.DISPOSITION_REJECTED:
        disposition = Disposition.UNEVALUABLE
        reasoning.append(f"verifier could not evaluate the witness: {sorted(reasons)}")
    elif verdict == v1.DISPOSITION_COUNTEREXAMPLE:
        disposition = Disposition.COUNTEREXAMPLE_VALIDATED
        reasoning.append("verifier recomputed the falsifier and it fired")
    else:
        disposition = Disposition.NOT_A_COUNTEREXAMPLE
        reasoning.append("verifier recomputed the falsifier and it did not fire")

    # Coverage downgrades only a negative result: exhausting the budget says
    # nothing about a counterexample that was actually validated.
    if disposition is Disposition.NOT_A_COUNTEREXAMPLE and budget is not None:
        untested = budget.families_untested(scope)
        if budget.exhausted or untested:
            disposition = Disposition.COVERAGE_LIMITED
            if budget.exhausted:
                reasoning.append(
                    f"attempt budget exhausted ({budget.attempts_used}/{budget.attempts_allowed})"
                )
            if untested:
                reasoning.append(f"declared families never attempted: {sorted(untested)}")

    if assertion.claimed_violation and disposition is not Disposition.COUNTEREXAMPLE_VALIDATED:
        reasoning.append(
            "adversary asserted a violation; the verifier did not validate it. "
            "The assertion is recorded, not credited."
        )

    return _record(assertion, verifier_results, disposition, reasoning, budget, scope)


def _record(
    assertion: AdversaryAssertion,
    verifier_results: list[dict[str, Any]],
    disposition: Disposition,
    reasoning: list[str],
    budget: BudgetState | None,
    scope: TrialScope,
) -> dict[str, Any]:
    adjudication = {
        "adjudication_form": "oat-trial-adjudication/1",
        "run_mode": RUN_MODE,
        "claim_bearing_use": CLAIM_BEARING_USE,
        "claim_ceiling": CLAIM_CEILING,
        "attack_id": assertion.attack_id,
        "property_id": assertion.property_id,
        "disposition": disposition.value,
        "reasoning": list(reasoning),
        "adversary_assertion": assertion.to_dict(),
        "verifier_results": [
            {
                "disposition": str(r["disposition"]),
                "rejection_reason": r.get("rejection_reason"),
                "evidence_digest": str(r["evidence_digest"]),
                "witness_digest": str(r["witness_digest"]),
            }
            for r in verifier_results
        ],
        "scope": {
            "in_scope_property_ids": sorted(scope.in_scope_property_ids),
            "declared_attack_families": sorted(scope.declared_attack_families),
        },
        "budget": (
            {
                "attempts_used": budget.attempts_used,
                "attempts_allowed": budget.attempts_allowed,
                "exhausted": budget.exhausted,
                "families_attempted": sorted(budget.families_attempted),
            }
            if budget is not None
            else None
        ),
    }
    adjudication["adjudication_digest"] = digest_object(adjudication)
    return adjudication


def supported_dispositions() -> list[str]:
    """The frozen disposition vocabulary, for manifest binding."""
    return [d.value for d in Disposition]
