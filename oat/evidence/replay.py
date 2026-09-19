"""Deterministic consequence-boundary runs and their replay.

A run is a pure function of frozen inputs. No provider, no network, no clock.
Replay recomputes the disposition from the recorded evidence alone: model
output is search provenance, never a truth input.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oat.consequence.scenarios import SCENARIOS, ScenarioResult
from oat.digest import digest_object
from oat.evidence.graph import audit, build_graph
from oat.paths.discovery import reconcile
from oat.paths.observations import observations_from_sink
from oat.verifier.consequence import (
    ConsequenceEvidence,
    ConsequenceVerdict,
    adjudicate,
)

RUN_FORM: str = "oat-consequence-run/1"


def evidence_from_scenario(scenario: ScenarioResult) -> ConsequenceEvidence:
    """Assemble verifier input from a built scenario."""
    from oat.consequence.scenarios import DECLARED_PATHS

    observations = observations_from_sink(scenario.sink)
    return ConsequenceEvidence(
        protected_sink=scenario.sink.sink,
        commits=list(scenario.sink.state.commits),
        receipts=list(scenario.sink.state.receipts),
        authorizations=dict(scenario.authorizations),
        authority=scenario.authority,
        issuer=scenario.issuer,
        correlated_token_digests=dict(scenario.correlated_token_digests),
        use_counts=dict(scenario.use_counts),
        reconciliation=reconcile(DECLARED_PATHS, observations),
        internal_property_failures=list(scenario.internal_property_failures),
        instrument_failures=list(scenario.instrument_failures),
    )


def _graphs(scenario: ScenarioResult, verdict: ConsequenceVerdict) -> list[dict[str, Any]]:
    graphs: list[dict[str, Any]] = []
    by_commit = {f.commit_id: f for f in verdict.findings}
    for commit in scenario.sink.state.commits:
        authorization = (
            scenario.authorizations.get(commit.authorization_ref)
            if commit.authorization_ref
            else None
        )
        receipt = next(
            (r for r in scenario.sink.state.receipts if r.commit_id == commit.commit_id), None
        )
        at_commit = scenario.authority.at(commit.committed_at)
        finding = by_commit.get(commit.commit_id)
        graph = build_graph(
            agent_id=commit.agent_id,
            principal_id=commit.principal_id,
            route_id=commit.route_id,
            action_digest=commit.action_digest,
            authorization=authorization.to_dict() if authorization else None,
            authority_at_issue=at_commit.to_dict() if authorization and at_commit else None,
            authority_at_commit=at_commit.to_dict() if at_commit else None,
            sink_decision=(
                scenario.sink.interlock_log[-1].to_dict() if scenario.sink.interlock_log else None
            ),
            commit=commit.to_dict(),
            receipt=receipt.to_dict() if receipt else None,
            verifier_trace=finding.to_dict() if finding else None,
            disposition=finding.disposition.value if finding else None,
        )
        graphs.append(
            {
                "commit_id": commit.commit_id,
                "graph": graph.to_dict(),
                "audit": audit(graph).to_dict(),
                "graph_digest": graph.digest,
            }
        )
    return graphs


def run_scenario(name: str) -> dict[str, Any]:
    """Execute one deterministic scenario and return its evidence package."""
    if name not in SCENARIOS:
        raise KeyError(f"unknown scenario {name!r}; known: {', '.join(sorted(SCENARIOS))}")
    scenario = SCENARIOS[name]()
    evidence = evidence_from_scenario(scenario)
    verdict = adjudicate(evidence)
    package = {
        "run_form": RUN_FORM,
        "scenario": name,
        "notes": scenario.notes,
        "status": "METHOD_DEVELOPMENT_ONLY",
        "claim_bearing_use": "PROHIBITED",
        "provider_run_occurred": False,
        "sink": scenario.sink.to_dict(),
        "authority": scenario.authority.to_dict(),
        "authorizations": {k: v.to_dict() for k, v in sorted(scenario.authorizations.items())},
        "verdict": verdict.to_dict(),
        "evidence_graphs": _graphs(scenario, verdict),
    }
    package["evidence_digest"] = digest_object(package)
    return package


def verify_package(package: dict[str, Any]) -> tuple[bool, str]:
    """Recompute the evidence digest of a stored package."""
    stored = package.get("evidence_digest")
    body = {k: v for k, v in package.items() if k != "evidence_digest"}
    recomputed = digest_object(body)
    if stored != recomputed:
        return False, f"evidence digest mismatch: stored {stored}, recomputed {recomputed}"
    return True, "evidence digest matches"


def replay_scenario(name: str, package: dict[str, Any]) -> tuple[bool, str]:
    """Re-execute a scenario and require an identical disposition and digest."""
    fresh = run_scenario(name)
    if fresh["verdict"]["disposition"] != package["verdict"]["disposition"]:
        return (
            False,
            f"disposition changed: {package['verdict']['disposition']} -> "
            f"{fresh['verdict']['disposition']}",
        )
    if fresh["evidence_digest"] != package["evidence_digest"]:
        return False, "evidence digest is not reproducible"
    return True, "replay reproduced the disposition and digest exactly"


def write_package(package: dict[str, Any], out_dir: str | Path) -> Path:
    """Write a run package deterministically."""
    path = Path(out_dir)
    path.mkdir(parents=True, exist_ok=True)
    target = path / "consequence-run.json"
    target.write_text(
        json.dumps(package, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return target


def read_package(run_dir: str | Path) -> dict[str, Any]:
    """Read a run package from ``run_dir``."""
    target = Path(run_dir) / "consequence-run.json"
    data: dict[str, Any] = json.loads(target.read_text(encoding="utf-8"))
    return data
