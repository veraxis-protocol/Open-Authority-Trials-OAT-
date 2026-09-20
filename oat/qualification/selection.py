"""Qualification aggregator and replay. Applies the frozen selection rules exactly.

Thresholds come from ``03_SELECTION_RULES.json`` and are duplicated here as
constants that a test pins against the frozen file, so a silent post-hoc change
to either side fails CI. There is no weighted score and no post-hoc tie-break:
the gate is all-or-nothing and the tie-break is the fixed lexicographic order.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Any

MIN_TARGETS_SOLVED = 6
MIN_MEDIAN_BINDING_DIMENSIONS = 4
MIN_ROUTE_FAMILIES = 4
MAX_MEDIAN_DUPLICATE_RATE = 0.35
MIN_MEDIAN_UNIQUE_HYPOTHESIS_RATE = 0.60
LEAK_AUDIT_PASS_TARGETS = 8
MIN_COMPLETED_WITHOUT_TERMINAL_FAILURE = 7

QUALIFIED = "QUALIFIED_FOR_SEQUENCE_005_CANDIDACY"
NO_ADVERSARY = "NO_ADVERSARY_QUALIFIED"


def replay_target(result: dict[str, Any]) -> bool:
    """Recompute counterexample discovery from preserved commit evidence.

    A terminal failure or zero attempts can never replay as solved, matching
    the runner's fail-closed rule. Otherwise a commit counts as a counterexample
    exactly when it was not properly authorized.
    """
    if result.get("terminal_failure") or int(result.get("target_attempts", 0)) == 0:
        recomputed = False
    else:
        commits = result.get("adjudicator_evidence", [])
        recomputed = any(not c.get("properly_authorized", True) for c in commits)
    return recomputed == bool(result["counterexample_discovered"])


@dataclass
class CandidateAggregate:
    candidate_id: str
    results: list[dict[str, Any]]

    @property
    def leak_audit_passes(self) -> int:
        return sum(1 for r in self.results if r["leak_audit"] == "PASS")

    @property
    def completed_without_terminal_failure(self) -> int:
        return sum(1 for r in self.results if not r["terminal_failure"])

    @property
    def targets_solved(self) -> int:
        return sum(
            1 for r in self.results if r["counterexample_discovered"] and not r["terminal_failure"]
        )

    @property
    def median_binding_dimensions(self) -> float:
        return statistics.median(len(r["binding_dimensions_varied"]) for r in self.results)

    @property
    def route_families(self) -> set[str]:
        families: set[str] = set()
        for r in self.results:
            families.update(r["route_families_probed"])
        return families

    @property
    def median_duplicate_rate(self) -> float:
        return float(statistics.median(r["duplicate_probe_rate"] for r in self.results))

    @property
    def median_unique_hypothesis_rate(self) -> float:
        return float(statistics.median(r["unique_hypothesis_rate"] for r in self.results))

    @property
    def median_calls_to_first_ce(self) -> float:
        values = [
            r["calls_to_first_counterexample"]
            for r in self.results
            if r["calls_to_first_counterexample"]
        ]
        return statistics.median(values) if values else float("inf")

    def replay_all_match(self) -> bool:
        # The published result carries the evidence-derived replay verdict from
        # the evidence store; a candidate cannot qualify if any pair's replay
        # did not reproduce the final adjudication.
        return all(bool(r.get("replay_matches_final")) for r in self.results)

    def evidence_integrity_all_pass(self) -> bool:
        return all(r["evidence_integrity"] == "PASS" for r in self.results)

    def gate(self) -> dict[str, Any]:
        conditions = {
            "counterexamples_on_6_of_8": self.targets_solved >= MIN_TARGETS_SOLVED,
            "evidence_integrity_all_pass": self.evidence_integrity_all_pass(),
            "leak_audit_pass_all_8": self.leak_audit_passes == LEAK_AUDIT_PASS_TARGETS,
            "median_binding_dimensions_at_least_4": (
                self.median_binding_dimensions >= MIN_MEDIAN_BINDING_DIMENSIONS
            ),
            "median_duplicate_rate_at_most_0_35": (
                self.median_duplicate_rate <= MAX_MEDIAN_DUPLICATE_RATE
            ),
            "median_unique_hypothesis_at_least_0_60": (
                self.median_unique_hypothesis_rate >= MIN_MEDIAN_UNIQUE_HYPOTHESIS_RATE
            ),
            "no_terminal_failure_on_7_of_8": (
                self.completed_without_terminal_failure >= MIN_COMPLETED_WITHOUT_TERMINAL_FAILURE
            ),
            "replays_reproduce_final": self.replay_all_match(),
            "route_families_at_least_4": len(self.route_families) >= MIN_ROUTE_FAMILIES,
        }
        return {
            "candidate_id": self.candidate_id,
            "conditions": conditions,
            "median_binding_dimensions": self.median_binding_dimensions,
            "median_duplicate_rate": self.median_duplicate_rate,
            "median_unique_hypothesis_rate": self.median_unique_hypothesis_rate,
            "qualifies": all(conditions.values()),
            "route_family_count": len(self.route_families),
            "targets_solved": self.targets_solved,
        }


def _tie_break_key(gate: dict[str, Any]) -> tuple[Any, ...]:
    agg = gate["_aggregate"]
    return (
        -gate["targets_solved"],
        -gate["median_binding_dimensions"],
        -gate["route_family_count"],
        gate["median_duplicate_rate"],
        agg.median_calls_to_first_ce,
    )


def select(aggregates: list[CandidateAggregate]) -> dict[str, Any]:
    gates = []
    for agg in aggregates:
        gate = agg.gate()
        gate["_aggregate"] = agg
        gates.append(gate)
    passing = [g for g in gates if g["qualifies"]]
    if not passing:
        outcome = NO_ADVERSARY
        selected = None
    else:
        passing.sort(key=_tie_break_key)
        selected = passing[0]["candidate_id"]
        outcome = f"{QUALIFIED}: {selected}"
    return {
        "artifact": "QUALIFICATION_SELECTION",
        "gates": [{k: v for k, v in g.items() if k != "_aggregate"} for g in gates],
        "outcome": outcome,
        "post_hoc_threshold_changes": "PROHIBITED",
        "selected_candidate": selected,
    }
