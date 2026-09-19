"""Authorization artifacts and the ValidAuthorization relation.

This module implements the second half of the primary falsifier. The first
half -- "a protected consequence committed" -- is a fact about the sink. This
half is the question of whether any authorization actually covered it.

Every dimension is evaluated and reported individually. The relation is a
conjunction, but the *report* is not a boolean: a caller needs to know which
dimension failed, and needs to be able to tell "this dimension was checked and
failed" from "this dimension could not be checked at all".
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from hashlib import sha256
from typing import TYPE_CHECKING, Any

from oat.authority.current_state import AuthorityState
from oat.authority.delegation import DelegationChain, validate_delegation
from oat.consequence.model import NON_APPLICABLE
from oat.digest import digest_object

if TYPE_CHECKING:  # pragma: no cover - typing only
    from oat.consequence.model import CommitEvent

#: Outcome of a single binding dimension.
BOUND: str = "BOUND"
MISMATCH: str = "MISMATCH"
UNDETERMINED: str = "UNDETERMINED"
DECLARED_NON_APPLICABLE: str = "DECLARED_NON_APPLICABLE"


@dataclass(frozen=True)
class DimensionResult:
    """Result for one binding dimension of ValidAuthorization."""

    dimension: str
    outcome: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"dimension": self.dimension, "outcome": self.outcome, "detail": self.detail}


@dataclass(frozen=True)
class ValidationReport:
    """Per-dimension outcome of evaluating ValidAuthorization(a, c)."""

    results: tuple[DimensionResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"dimensions": [r.to_dict() for r in self.results]}

    @property
    def mismatches(self) -> tuple[DimensionResult, ...]:
        return tuple(r for r in self.results if r.outcome == MISMATCH)

    @property
    def undetermined(self) -> tuple[DimensionResult, ...]:
        return tuple(r for r in self.results if r.outcome == UNDETERMINED)

    @property
    def valid(self) -> bool:
        """True only when every dimension is BOUND or explicitly inapplicable.

        An UNDETERMINED dimension never yields True. Missing evidence is not
        permission.
        """
        return not self.mismatches and not self.undetermined


@dataclass(frozen=True)
class Authorization:
    """A deterministic authorization artifact.

    The HMAC is a representative integrity primitive for the reference
    profile, not production infrastructure -- see docs/CONSEQUENCE-BOUNDARY.md.
    """

    authorization_id: str
    grant_id: str
    decision: str
    tenant_id: str
    principal_id: str
    agent_id: str
    release_id: str
    action_digest: str
    sink_id: str
    scope: str
    authority_state_digest: str
    not_before: int
    not_after: int
    idempotency_key: str
    max_uses: int
    delegation: DelegationChain | None = None
    integrity: str = ""

    def payload(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "grant_id": self.grant_id,
            "decision": self.decision,
            "tenant_id": self.tenant_id,
            "principal_id": self.principal_id,
            "agent_id": self.agent_id,
            "release_id": self.release_id,
            "action_digest": self.action_digest,
            "sink_id": self.sink_id,
            "scope": self.scope,
            "authority_state_digest": self.authority_state_digest,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "idempotency_key": self.idempotency_key,
            "max_uses": self.max_uses,
            "delegation": self.delegation.to_dict() if self.delegation else NON_APPLICABLE,
        }

    def to_dict(self) -> dict[str, Any]:
        record = self.payload()
        record["integrity"] = self.integrity
        return record

    @property
    def digest(self) -> str:
        return digest_object(self.to_dict())


@dataclass
class AuthorizationIssuer:
    """Issues integrity-protected authorizations for the reference profile."""

    secret: bytes
    _uses: dict[str, int] = field(default_factory=dict)

    def sign(self, authorization: Authorization) -> Authorization:
        from dataclasses import replace

        mac = hmac.new(
            self.secret, digest_object(authorization.payload()).encode("utf-8"), sha256
        ).hexdigest()
        return replace(authorization, integrity=f"hmac-sha256:{mac}")

    def verify_integrity(self, authorization: Authorization) -> bool:
        expected = hmac.new(
            self.secret, digest_object(authorization.payload()).encode("utf-8"), sha256
        ).hexdigest()
        return hmac.compare_digest(f"hmac-sha256:{expected}", authorization.integrity)

    def record_use(self, authorization_id: str) -> int:
        self._uses[authorization_id] = self._uses.get(authorization_id, 0) + 1
        return self._uses[authorization_id]

    def use_count(self, authorization_id: str) -> int:
        return self._uses.get(authorization_id, 0)


def _cmp(dimension: str, expected: Any, actual: Any) -> DimensionResult:
    if expected == NON_APPLICABLE:
        return DimensionResult(dimension, DECLARED_NON_APPLICABLE, "declared inapplicable")
    if expected is None or actual is None:
        return DimensionResult(dimension, UNDETERMINED, "value missing from evidence")
    if expected == actual:
        return DimensionResult(dimension, BOUND)
    return DimensionResult(dimension, MISMATCH, f"expected {expected!r}, observed {actual!r}")


def validate_authorization(
    authorization: Authorization | None,
    commit: CommitEvent,
    *,
    authority_at_commit: AuthorityState | None,
    issuer: AuthorizationIssuer | None = None,
    prior_use_count: int | None = None,
    correlated_token_digest: str | None = None,
) -> ValidationReport:
    """Evaluate ValidAuthorization(a, c) dimension by dimension.

    ``authority_at_commit`` is the state in force when the commit landed, not
    when the authorization was issued. Passing ``None`` means the evidence is
    missing, which yields UNDETERMINED dimensions rather than failures.
    """
    results: list[DimensionResult] = []
    add = results.append

    if authorization is None:
        return ValidationReport(
            (DimensionResult("authorization_present", MISMATCH, "no authorization artifact"),)
        )

    add(
        DimensionResult("positive_decision", BOUND)
        if authorization.decision == "ALLOW"
        else DimensionResult(
            "positive_decision", MISMATCH, f"decision is {authorization.decision!r}"
        )
    )
    add(_cmp("tenant", authorization.tenant_id, commit.tenant_id))
    add(_cmp("principal", authorization.principal_id, commit.principal_id))
    add(_cmp("agent_identity", authorization.agent_id, commit.agent_id))
    add(_cmp("release_identity", authorization.release_id, commit.release_id))
    add(_cmp("exact_action_digest", authorization.action_digest, commit.action_digest))
    add(_cmp("protected_sink", authorization.sink_id, commit.sink_id))
    add(_cmp("idempotency_binding", authorization.idempotency_key, commit.idempotency_key))

    # Scope is bound by construction in this profile: the reference scope is
    # the sink's action class. Recorded explicitly rather than assumed.
    add(
        DimensionResult("normalized_action_scope", BOUND)
        if authorization.scope
        else DimensionResult("normalized_action_scope", UNDETERMINED, "no scope recorded")
    )

    # Integrity.
    if issuer is None:
        add(DimensionResult("authorization_integrity", UNDETERMINED, "no issuer to verify with"))
    elif issuer.verify_integrity(authorization):
        add(DimensionResult("authorization_integrity", BOUND))
    else:
        add(DimensionResult("authorization_integrity", MISMATCH, "integrity check failed"))

    # Validity interval, in logical ticks.
    if commit.committed_at < authorization.not_before:
        add(DimensionResult("validity_interval", MISMATCH, "commit before not_before"))
    elif commit.committed_at > authorization.not_after:
        add(DimensionResult("validity_interval", MISMATCH, "commit after not_after"))
    else:
        add(DimensionResult("validity_interval", BOUND))

    # Authority state at commit -- the load-bearing one.
    if authority_at_commit is None:
        add(
            DimensionResult(
                "authority_state_at_commit", UNDETERMINED, "no authority state for commit tick"
            )
        )
        add(DimensionResult("revocation_state", UNDETERMINED, "authority state unavailable"))
    else:
        add(
            _cmp(
                "authority_state_at_commit",
                authorization.authority_state_digest,
                authority_at_commit.digest,
            )
        )
        status = authority_at_commit.status_of(authorization.grant_id)
        add(
            DimensionResult("revocation_state", BOUND)
            if status == "ACTIVE"
            else DimensionResult("revocation_state", MISMATCH, f"grant is {status}")
        )

    # Delegation.
    if authorization.delegation is None:
        add(DimensionResult("delegation_chain", DECLARED_NON_APPLICABLE, "no delegation in force"))
        add(DimensionResult("non_amplification", DECLARED_NON_APPLICABLE, "no delegation in force"))
    else:
        ok, reason = validate_delegation(
            authorization.delegation,
            acting_principal=commit.principal_id,
            required_scope=authorization.scope,
        )
        add(
            DimensionResult("delegation_chain", BOUND)
            if ok
            else DimensionResult("delegation_chain", MISMATCH, reason)
        )
        add(
            DimensionResult("non_amplification", MISMATCH, reason)
            if reason.startswith("DELEGATION_AMPLIFIED")
            else DimensionResult("non_amplification", BOUND)
        )

    # Authorization use constraints (replay).
    if prior_use_count is None:
        add(DimensionResult("authorization_use_count", UNDETERMINED, "use count not recorded"))
    elif prior_use_count > authorization.max_uses:
        add(
            DimensionResult(
                "authorization_use_count",
                MISMATCH,
                f"used {prior_use_count} times, max {authorization.max_uses}",
            )
        )
    else:
        add(DimensionResult("authorization_use_count", BOUND))

    # Commit-to-authorization correlation: the sink must have recorded the
    # same token it was actually presented.
    if correlated_token_digest is None:
        add(
            DimensionResult(
                "commit_authorization_correlation", UNDETERMINED, "no correlation telemetry"
            )
        )
    else:
        add(_cmp("commit_authorization_correlation", authorization.digest, correlated_token_digest))

    return ValidationReport(tuple(results))


def token_digest(authorization: Authorization) -> str:
    """Digest the sink records for the token it was actually presented.

    This is the authorization's own digest, not a hash of it: the correlation
    dimension compares the two directly, and an extra round of hashing here
    would make every correlation fail closed for the wrong reason.
    """
    return authorization.digest
