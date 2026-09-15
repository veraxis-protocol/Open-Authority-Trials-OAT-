"""RB-001 — revocation-before-commit / TOCTOU authorization failure.

RB-001 is a *synthetic* reference boundary. It exists so the OAT instrument can
be exercised end to end against a failure class whose ground truth is known by
construction. Nothing here models a real product.

Time is expressed in integer logical ticks, never wall-clock time: the evidence
digest domain must be deterministic, and a wall-clock timestamp would make two
replays of the same frozen run diverge. See FORMATION-0001 for the ambiguity
this resolves in the RB-001 source description.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

BOUNDARY_ID: str = "RB-001"
BOUNDARY_VERSION: str = "0.1.0"

STATUS_ACTIVE: str = "ACTIVE"
STATUS_REVOKED: str = "REVOKED"

#: Enforcement paths under test. The first two are defective by construction,
#: the third is the correct one.
ENFORCEMENT_CHECK_ONCE_CACHED: str = "CHECK_ONCE_CACHED"
ENFORCEMENT_STALE_PROPAGATION: str = "STALE_PROPAGATION"
ENFORCEMENT_RECHECK_AT_COMMIT: str = "RECHECK_AT_COMMIT"

ENFORCEMENT_PATHS: frozenset[str] = frozenset(
    {
        ENFORCEMENT_CHECK_ONCE_CACHED,
        ENFORCEMENT_STALE_PROPAGATION,
        ENFORCEMENT_RECHECK_AT_COMMIT,
    }
)


class ScenarioError(ValueError):
    """Raised when a scenario definition is not executable as written."""


@dataclass(frozen=True)
class AuthorityInput:
    """Frozen authority grant. ``valid_from``/``valid_until`` are logical ticks."""

    subject: str
    resource_or_beneficiary: str
    max_quantity: int
    unit: str
    valid_from: int
    valid_until: int
    status: str = STATUS_ACTIVE

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AuthorityInput:
        try:
            return AuthorityInput(
                subject=str(data["subject"]),
                resource_or_beneficiary=str(data["resource_or_beneficiary"]),
                max_quantity=int(data["max_quantity"]),
                unit=str(data["unit"]),
                valid_from=int(data["valid_from"]),
                valid_until=int(data["valid_until"]),
                status=str(data.get("status", STATUS_ACTIVE)),
            )
        except KeyError as exc:  # pragma: no cover - guarded by schema validation
            raise ScenarioError(f"authority input missing field: {exc}") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "resource_or_beneficiary": self.resource_or_beneficiary,
            "max_quantity": self.max_quantity,
            "unit": self.unit,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "status": self.status,
        }


@dataclass(frozen=True)
class Variation:
    """One point in the adversary's allowed search space.

    Every field is a *scenario dimension the adversary is permitted to vary*.
    None of them mutate frozen authority facts or the falsifier.
    """

    check_tick: int
    revocation_tick: int
    commit_tick: int
    propagation_delay: int = 0
    retry_index: int = 0
    duplicate_request: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_tick": self.check_tick,
            "commit_tick": self.commit_tick,
            "duplicate_request": self.duplicate_request,
            "propagation_delay": self.propagation_delay,
            "retry_index": self.retry_index,
            "revocation_tick": self.revocation_tick,
        }


@dataclass(frozen=True)
class Scenario:
    """A frozen RB-001 scenario instance."""

    scenario_id: str
    enforcement_path: str
    authority: AuthorityInput
    action_quantity: int
    execution_identity: str
    baseline: Variation
    search_space: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(data: dict[str, Any], authority: AuthorityInput) -> Scenario:
        enforcement_path = str(data["enforcement_path"])
        if enforcement_path not in ENFORCEMENT_PATHS:
            raise ScenarioError(f"unknown enforcement_path: {enforcement_path}")
        baseline_data = data["baseline"]
        return Scenario(
            scenario_id=str(data["scenario_id"]),
            enforcement_path=enforcement_path,
            authority=authority,
            action_quantity=int(data["action_quantity"]),
            execution_identity=str(data["execution_identity"]),
            baseline=Variation(
                check_tick=int(baseline_data["check_tick"]),
                revocation_tick=int(baseline_data["revocation_tick"]),
                commit_tick=int(baseline_data["commit_tick"]),
                propagation_delay=int(baseline_data.get("propagation_delay", 0)),
            ),
            search_space=dict(data.get("search_space", {})),
        )


def authority_effective_status(
    authority: AuthorityInput, revocation_tick: int, at_tick: int
) -> str:
    """Ground-truth effective authority status at ``at_tick``.

    This is the authoritative source of truth, independent of what any
    enforcement path happened to observe. The falsifier reads this, never the
    enforcement path's cached view.
    """
    if at_tick >= revocation_tick:
        return STATUS_REVOKED
    if at_tick < authority.valid_from or at_tick > authority.valid_until:
        return STATUS_REVOKED
    return authority.status


def _observed_status(
    scenario: Scenario, variation: Variation, commit_tick: int
) -> tuple[str, int, str]:
    """Return (observed_status, observed_at_tick, read_source) for the commit check."""
    path = scenario.enforcement_path
    if path == ENFORCEMENT_CHECK_ONCE_CACHED:
        # Defect: the decision taken at check time is reused verbatim at commit.
        return (
            authority_effective_status(
                scenario.authority, variation.revocation_tick, variation.check_tick
            ),
            variation.check_tick,
            "CACHED_DECISION",
        )
    if path == ENFORCEMENT_STALE_PROPAGATION:
        # Defect: enforcement re-reads, but from a replica that lags the source.
        replica_tick = commit_tick - variation.propagation_delay
        return (
            authority_effective_status(scenario.authority, variation.revocation_tick, replica_tick),
            replica_tick,
            "LAGGING_REPLICA",
        )
    # Correct path: authoritative re-evaluation at the consequence boundary.
    return (
        authority_effective_status(scenario.authority, variation.revocation_tick, commit_tick),
        commit_tick,
        "AUTHORITATIVE_SOURCE",
    )


def execute(scenario: Scenario, variation: Variation) -> dict[str, Any]:
    """Run the scenario under one variation and return a canonical observable trace.

    The returned object contains only observables: what was proposed, what was
    checked, what the authority source did, and what consequence was committed.
    """
    commit_tick = variation.commit_tick + variation.retry_index
    events: list[dict[str, Any]] = []

    def emit(tick: int, event: str, **payload: Any) -> None:
        events.append({"seq": len(events), "tick": tick, "event": event, **payload})

    emit(
        variation.check_tick,
        "action_proposed",
        subject=scenario.authority.subject,
        beneficiary=scenario.authority.resource_or_beneficiary,
        quantity=scenario.action_quantity,
        unit=scenario.authority.unit,
    )

    check_status = authority_effective_status(
        scenario.authority, variation.revocation_tick, variation.check_tick
    )
    within_limit = scenario.action_quantity <= scenario.authority.max_quantity
    check_decision = "ALLOW" if (check_status == STATUS_ACTIVE and within_limit) else "DENY"
    emit(
        variation.check_tick,
        "authorization_checked",
        authority_status_observed=check_status,
        within_quantity_limit=within_limit,
        decision=check_decision,
        read_source="AUTHORITATIVE_SOURCE",
    )

    emit(
        variation.revocation_tick,
        "authority_transition",
        from_status=STATUS_ACTIVE,
        to_status=STATUS_REVOKED,
        effective_tick=variation.revocation_tick,
        accepted_by="AUTHORITY_SOURCE",
    )

    if variation.duplicate_request:
        emit(commit_tick, "commit_requested", retry_index=variation.retry_index, duplicate=True)
    emit(commit_tick, "commit_requested", retry_index=variation.retry_index, duplicate=False)

    observed_status, observed_at, read_source = _observed_status(scenario, variation, commit_tick)
    allowed = observed_status == STATUS_ACTIVE and within_limit and check_decision == "ALLOW"
    emit(
        commit_tick,
        "commit_decision",
        enforcement_path=scenario.enforcement_path,
        authority_status_used=observed_status,
        authority_status_observed_at_tick=observed_at,
        read_source=read_source,
        allowed=allowed,
    )

    emit(
        commit_tick,
        "consequence_committed",
        committed=allowed,
        quantity=scenario.action_quantity if allowed else 0,
        unit=scenario.authority.unit,
        beneficiary=scenario.authority.resource_or_beneficiary,
    )

    return {
        "trace_form": "oat-observable-trace/1",
        "boundary_id": BOUNDARY_ID,
        "boundary_version": BOUNDARY_VERSION,
        "scenario_id": scenario.scenario_id,
        "execution_identity": scenario.execution_identity,
        "enforcement_path": scenario.enforcement_path,
        "authority_input": scenario.authority.to_dict(),
        "variation": variation.to_dict(),
        "commit_tick": commit_tick,
        "authority_effective_at_commit": authority_effective_status(
            scenario.authority, variation.revocation_tick, commit_tick
        ),
        "events": events,
    }
