"""Data model for protected consequences and the actions that cause them."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from oat.consequence.canonical import exact_action_digest, normalize_action

#: Explicit marker for a binding dimension that does not apply to a profile.
#: OAT has no wildcard semantics: a dimension is bound, or it is declared
#: inapplicable in the open. It is never silently skipped.
NON_APPLICABLE: str = "NOT_APPLICABLE"


@dataclass(frozen=True)
class ProtectedSink:
    """A sink whose committed state OAT treats as a protected consequence."""

    sink_id: str
    description: str

    def protects(self, commit: CommitEvent) -> bool:
        return commit.sink_id == self.sink_id


@dataclass(frozen=True)
class NormalizedAction:
    """An action in exact-action form, carrying its own digest."""

    action_type: str
    target: str
    parameters: dict[str, Any]
    quantity: Any
    unit: str
    principal_id: str
    sink_id: str
    tenant_id: str
    release_id: str

    def to_dict(self) -> dict[str, Any]:
        return normalize_action(
            {
                "action_type": self.action_type,
                "target": self.target,
                "parameters": self.parameters,
                "quantity": self.quantity,
                "unit": self.unit,
                "principal_id": self.principal_id,
                "sink_id": self.sink_id,
                "tenant_id": self.tenant_id,
                "release_id": self.release_id,
            }
        )

    @property
    def digest(self) -> str:
        return exact_action_digest(self.to_dict())


@dataclass(frozen=True)
class CommitEvent:
    """A durable commit in a protected sink.

    ``committed_at`` is an integer logical tick, never wall-clock time, so a
    reference run replays byte-identically on any host.
    """

    commit_id: str
    sink_id: str
    route_id: str
    tenant_id: str
    principal_id: str
    agent_id: str
    release_id: str
    action_digest: str
    normalized_action: dict[str, Any]
    committed_at: int
    authorization_ref: str | None
    authority_state_ref: str | None
    idempotency_key: str
    trace_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit_id": self.commit_id,
            "sink_id": self.sink_id,
            "route_id": self.route_id,
            "tenant_id": self.tenant_id,
            "principal_id": self.principal_id,
            "agent_id": self.agent_id,
            "release_id": self.release_id,
            "action_digest": self.action_digest,
            "normalized_action": self.normalized_action,
            "committed_at": self.committed_at,
            "authorization_ref": self.authorization_ref,
            "authority_state_ref": self.authority_state_ref,
            "idempotency_key": self.idempotency_key,
            "trace_ref": self.trace_ref,
        }


@dataclass(frozen=True)
class ConsequenceReceipt:
    """Independent evidence that a commit occurred.

    Emitted by the sink's observation surface, not by the authorization engine
    and not by the adversary. If this is absent for a commit the verifier must
    not conclude that nothing happened -- see
    :func:`oat.verifier.consequence.adjudicate`.
    """

    receipt_id: str
    commit_id: str
    sink_id: str
    route_id: str
    observed_at: int
    action_digest: str
    observer: str = "sink-independent-observer"

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "commit_id": self.commit_id,
            "sink_id": self.sink_id,
            "route_id": self.route_id,
            "observed_at": self.observed_at,
            "action_digest": self.action_digest,
            "observer": self.observer,
        }


@dataclass
class SinkState:
    """Committed ledger state plus the independent observation log."""

    commits: list[CommitEvent] = field(default_factory=list)
    receipts: list[ConsequenceReceipt] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "commits": [c.to_dict() for c in self.commits],
            "receipts": [r.to_dict() for r in self.receipts],
        }
