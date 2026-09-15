"""Synthetic plumbing dry run.

Proves the whole chain moves, against a synthetic target only:

    provider adapter -> candidate capture -> canonical evidence
    -> OAT verification -> replay -> disposition

and proves the property the chain exists for: **a model-generated assertion
is not accepted without verifier evidence.** The dry run deliberately feeds
in a false assertion and shows the trial layer refusing to credit it.

No frozen subject is exposed here, and no provider is contacted: the
transport is offline and scripted, and every report states so.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oat import CLAIM_BEARING_USE, RUN_MODE
from oat.adversaries.provider import ProviderAdversary, ScriptedTransport
from oat.manifest import write_json
from oat.pipeline import run_scenario
from oat.replay import replay_run
from oat.trial import BudgetState, Disposition, TrialScope, adjudicate

#: In-scope properties for the dry run. Synthetic; not VEIP properties.
DRYRUN_SCOPE = TrialScope(
    in_scope_property_ids=frozenset({"RB001-P1"}),
    declared_attack_families=frozenset({"ATTACK-FAMILY-01"}),
)

#: Scripted "model output": candidate variations as csv lines. The first
#: reaches a genuine RB-001 counterexample; the rest are noise.
SCRIPTED_CANDIDATES: str = "10,20,21\n5,20,17\nnot,a,variation\n"


def _scripted_adversary() -> ProviderAdversary:
    return ProviderAdversary(
        transport=ScriptedTransport([SCRIPTED_CANDIDATES]),
        config={
            "model": "NOT_EXPOSED_BY_PROVIDER",
            "endpoint": "NOT_EXPOSED_BY_PROVIDER",
            "note": "offline scripted transport; no provider contacted",
        },
    )


def run_dry_run(
    vuln_scenario: str | Path,
    control_scenario: str | Path,
    out_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Execute the synthetic plumbing dry run and return its report."""
    adversary = _scripted_adversary()

    # 1-3. adapter -> candidate capture -> canonical evidence -> V1
    run = run_scenario(vuln_scenario, out_dir=out_dir, adversary=adversary)
    verifier_result = run["verifier_result"]

    # 4. replay without the adversary
    replay = replay_run(run["run_dir"]) if out_dir is not None else None

    checks: list[dict[str, Any]] = []

    # 5a. an honest assertion that the verifier confirms
    honest = adversary.assert_finding(
        "DRYRUN-A", "RB001-P1", True, "cached decision survives revocation"
    )
    honest_adj = adjudicate(honest, [verifier_result], DRYRUN_SCOPE)
    checks.append(
        {
            "check": "validated_counterexample",
            "expected": Disposition.COUNTEREXAMPLE_VALIDATED.value,
            "observed": honest_adj["disposition"],
            "passed": honest_adj["disposition"] == Disposition.COUNTEREXAMPLE_VALIDATED.value,
        }
    )

    # 5b. THE point of the dry run: a confident false assertion on a control
    control = run_scenario(control_scenario, adversary=_scripted_adversary())
    false_claim = adversary.assert_finding(
        "DRYRUN-B", "RB001-P1", True, "asserting a violation the trace does not support"
    )
    false_adj = adjudicate(false_claim, [control["verifier_result"]], DRYRUN_SCOPE)
    checks.append(
        {
            "check": "false_assertion_refused",
            "expected": Disposition.NOT_A_COUNTEREXAMPLE.value,
            "observed": false_adj["disposition"],
            "passed": false_adj["disposition"] == Disposition.NOT_A_COUNTEREXAMPLE.value
            and false_adj["adversary_assertion"]["claimed_violation"] is True,
        }
    )

    # 5c. an attack on a property nobody declared
    off_scope = adversary.assert_finding("DRYRUN-C", "NOT-DECLARED", True, "undeclared property")
    off_adj = adjudicate(off_scope, [verifier_result], DRYRUN_SCOPE)
    checks.append(
        {
            "check": "out_of_scope_refused",
            "expected": Disposition.OUTSIDE_SCOPE.value,
            "observed": off_adj["disposition"],
            "passed": off_adj["disposition"] == Disposition.OUTSIDE_SCOPE.value,
        }
    )

    # 5d. two verifiers disagreeing must not be silently resolved
    conflict_adj = adjudicate(honest, [verifier_result, control["verifier_result"]], DRYRUN_SCOPE)
    checks.append(
        {
            "check": "verifier_conflict_surfaced",
            "expected": Disposition.VERIFIER_CONFLICT.value,
            "observed": conflict_adj["disposition"],
            "passed": conflict_adj["disposition"] == Disposition.VERIFIER_CONFLICT.value,
        }
    )

    # 5e. an exhausted search must not read as a clean bill of health
    budget = BudgetState(attempts_used=10, attempts_allowed=10, families_attempted=frozenset())
    coverage_adj = adjudicate(
        adversary.assert_finding("DRYRUN-E", "RB001-P1", False, "no finding"),
        [control["verifier_result"]],
        DRYRUN_SCOPE,
        budget=budget,
    )
    checks.append(
        {
            "check": "coverage_limited_when_budget_exhausted",
            "expected": Disposition.COVERAGE_LIMITED.value,
            "observed": coverage_adj["disposition"],
            "passed": coverage_adj["disposition"] == Disposition.COVERAGE_LIMITED.value,
        }
    )

    # 5f. no provider was contacted, and the adapter says so itself
    checks.append(
        {
            "check": "no_provider_run_claimed",
            "expected": False,
            "observed": adversary.provider_run_occurred,
            "passed": adversary.provider_run_occurred is False,
        }
    )

    report = {
        "dryrun_form": "oat-dryrun-report/1",
        "run_mode": RUN_MODE,
        "claim_bearing_use": CLAIM_BEARING_USE,
        "target": "synthetic RB-001 reference boundary",
        "veip_subject_exposed": False,
        "provider_run_occurred": adversary.provider_run_occurred,
        "transport": adversary.transport.name,
        "adversary_identity": adversary.identity(),
        "pipeline": {
            "candidates_captured": run["witness"]["search"]["candidates_explored"],
            "verifier_disposition": verifier_result["disposition"],
            "evidence_digest": verifier_result["evidence_digest"],
            "replay_ok": replay["replay_ok"] if replay else None,
        },
        "checks": checks,
        "dryrun_ok": all(entry["passed"] for entry in checks),
    }
    if out_dir is not None:
        write_json(Path(out_dir) / "dryrun-report.json", report)
    return report
