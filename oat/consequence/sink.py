"""The protected sink, its interlock, and its independent observer.

Three roles are deliberately separated here:

* the **interlock** decides whether to admit an action (preventive control);
* the **ledger** records what actually committed (commit truth);
* the **observer** independently witnesses commits (occurrence evidence).

An unguarded route reaches the ledger without passing the interlock. That is
the whole point: OAT must be able to study a sink that commits things nobody
authorized, which is impossible if the only way in is through the guard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from oat.authority.authorization import (
    Authorization,
    AuthorizationIssuer,
    token_digest,
    validate_authorization,
)
from oat.authority.current_state import AuthorityStore
from oat.consequence.model import CommitEvent, ConsequenceReceipt, ProtectedSink, SinkState

#: Interlock outcomes.
ADMITTED: str = "ADMITTED"
REFUSED: str = "REFUSED"


@dataclass(frozen=True)
class InterlockDecision:
    """Why the interlock admitted or refused an action."""

    outcome: str
    reason: str
    dimensions: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"outcome": self.outcome, "reason": self.reason, "dimensions": self.dimensions}


@dataclass(frozen=True)
class RouteObservation:
    """Sink-side telemetry for one arrival, guarded or not."""

    route_id: str
    observed_at: int
    admitted: bool
    committed: bool
    commit_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_id": self.route_id,
            "observed_at": self.observed_at,
            "admitted": self.admitted,
            "committed": self.committed,
            "commit_id": self.commit_id,
        }


@dataclass
class PaymentLedgerSink:
    """Deterministic reference sink: a payment ledger.

    Representative primitive, not production infrastructure. Commits are
    in-memory records keyed by logical tick so a run replays identically.
    """

    sink: ProtectedSink
    authority: AuthorityStore
    issuer: AuthorizationIssuer
    state: SinkState = field(default_factory=SinkState)
    route_log: list[RouteObservation] = field(default_factory=list)
    interlock_log: list[InterlockDecision] = field(default_factory=list)
    _seen_idempotency: set[str] = field(default_factory=set)

    # -- guarded path -----------------------------------------------------

    def submit(
        self,
        *,
        commit: CommitEvent,
        authorization: Authorization | None,
        presented_token_digest: str | None = None,
    ) -> InterlockDecision:
        """Guarded entry. Fails closed on every unsatisfied binding."""
        authority_at_commit = self.authority.at(commit.committed_at)
        prior_uses = (
            self.issuer.use_count(authorization.authorization_id) if authorization else None
        )
        report = validate_authorization(
            authorization,
            commit,
            authority_at_commit=authority_at_commit,
            issuer=self.issuer,
            prior_use_count=(prior_uses + 1) if prior_uses is not None else None,
            correlated_token_digest=presented_token_digest,
        )

        if commit.idempotency_key in self._seen_idempotency:
            decision = InterlockDecision(
                REFUSED, "IDEMPOTENCY_REPLAY", {"idempotency_key": commit.idempotency_key}
            )
            self.interlock_log.append(decision)
            self.route_log.append(
                RouteObservation(commit.route_id, commit.committed_at, False, False, None)
            )
            return decision

        if not report.valid:
            failed = [r.dimension for r in report.mismatches] or [
                r.dimension for r in report.undetermined
            ]
            decision = InterlockDecision(
                REFUSED, "BINDING_NOT_SATISFIED", {"failed_dimensions": failed}
            )
            self.interlock_log.append(decision)
            self.route_log.append(
                RouteObservation(commit.route_id, commit.committed_at, False, False, None)
            )
            return decision

        assert authorization is not None  # narrowed by report.valid
        self.issuer.record_use(authorization.authorization_id)
        self._seen_idempotency.add(commit.idempotency_key)
        decision = InterlockDecision(ADMITTED, "ALL_BINDINGS_SATISFIED")
        self.interlock_log.append(decision)
        self._commit(commit)
        return decision

    # -- unguarded path ---------------------------------------------------

    def commit_unguarded(self, commit: CommitEvent) -> None:
        """Commit without passing the interlock.

        This models a route the designers did not know existed. It is how a
        consequence-boundary counterexample becomes physically possible.
        """
        self._seen_idempotency.add(commit.idempotency_key)
        self._commit(commit)

    # -- shared -----------------------------------------------------------

    def _commit(self, commit: CommitEvent) -> None:
        self.state.commits.append(commit)
        receipt = ConsequenceReceipt(
            receipt_id=f"receipt-{len(self.state.receipts) + 1:04d}",
            commit_id=commit.commit_id,
            sink_id=commit.sink_id,
            route_id=commit.route_id,
            observed_at=commit.committed_at,
            action_digest=commit.action_digest,
        )
        self.state.receipts.append(receipt)
        self.route_log.append(
            RouteObservation(commit.route_id, commit.committed_at, True, True, commit.commit_id)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink_id": self.sink.sink_id,
            "state": self.state.to_dict(),
            "route_observations": [r.to_dict() for r in self.route_log],
            "interlock_decisions": [d.to_dict() for d in self.interlock_log],
        }


def presented_digest(authorization: Authorization) -> str:
    """Convenience re-export so callers need not import the authority layer."""
    return token_digest(authorization)
