"""Deterministic consequence-boundary scenarios.

These are the reference profile: a payment ledger, an HMAC authorization
artifact, a local authority store, synthetic routes. They are representative
test primitives and are not production infrastructure. Every value is fixed
and every clock is an integer logical tick, so a run replays byte-identically.

Scenario naming mirrors the controls in docs/CONSEQUENCE-BOUNDARY.md.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from oat.authority.authorization import Authorization, AuthorizationIssuer, token_digest
from oat.authority.current_state import AuthorityState, AuthorityStore
from oat.authority.delegation import DelegationChain, DelegationLink
from oat.consequence.canonical import exact_action_digest
from oat.consequence.model import CommitEvent, ProtectedSink
from oat.consequence.sink import PaymentLedgerSink
from oat.paths.inventory import DeclaredPath, PathInventory

SECRET: bytes = b"oat-reference-profile-secret-not-a-real-credential"

SINK = ProtectedSink(
    sink_id="sink.test-payment-ledger",
    description="Representative payment ledger; committed rows are the protected consequence.",
)

#: The declared inventory deliberately omits ``route.batch-replay``. That
#: omission is the hidden-route positive control (see docs/REACHABILITY-AND-
#: UNKNOWN-PATHS.md); the route is reachable and the sink can observe it.
DECLARED_PATHS = PathInventory(
    (
        DeclaredPath("route.api-guarded", "Primary guarded payment API", guarded=True),
        DeclaredPath("route.console", "Operator console", guarded=True),
    )
)

BASE_ACTION: dict[str, Any] = {
    "action_type": "payment.transfer",
    "target": "acct:beneficiary-77",
    "parameters": {"memo": "invoice-1041"},
    "quantity": 200000,
    "unit": "USD_CENTS",
    "principal_id": "principal.treasury-bot",
    "sink_id": SINK.sink_id,
    "tenant_id": "tenant.acme",
    "release_id": "release.agent-2026.09",
}


def base_authority() -> AuthorityStore:
    """Two epochs: the grant is active at tick 10, revoked from tick 50."""
    store = AuthorityStore()
    store.add(AuthorityState(epoch=1, effective_from=0, active_grants=("grant.treasury",)))
    store.add(
        AuthorityState(
            epoch=2, effective_from=50, active_grants=(), revoked_grants=("grant.treasury",)
        )
    )
    return store


def make_authorization(
    issuer: AuthorizationIssuer,
    *,
    action_digest: str,
    authority_state_digest: str,
    authorization_id: str = "authz-0001",
    idempotency_key: str = "idem-0001",
    principal_id: str = BASE_ACTION["principal_id"],
    release_id: str = BASE_ACTION["release_id"],
    tenant_id: str = BASE_ACTION["tenant_id"],
    sink_id: str = SINK.sink_id,
    not_before: int = 0,
    not_after: int = 40,
    max_uses: int = 1,
    delegation: DelegationChain | None = None,
    decision: str = "ALLOW",
) -> Authorization:
    return issuer.sign(
        Authorization(
            authorization_id=authorization_id,
            grant_id="grant.treasury",
            decision=decision,
            tenant_id=tenant_id,
            principal_id=principal_id,
            agent_id="agent.nim-adversary",
            release_id=release_id,
            action_digest=action_digest,
            sink_id=sink_id,
            scope="payment.transfer",
            authority_state_digest=authority_state_digest,
            not_before=not_before,
            not_after=not_after,
            idempotency_key=idempotency_key,
            max_uses=max_uses,
            delegation=delegation,
        )
    )


def make_commit(
    *,
    commit_id: str,
    route_id: str,
    action: dict[str, Any],
    committed_at: int,
    authorization_ref: str | None,
    authority_state_ref: str | None,
    idempotency_key: str = "idem-0001",
    agent_id: str = "agent.nim-adversary",
) -> CommitEvent:
    return CommitEvent(
        commit_id=commit_id,
        sink_id=action["sink_id"],
        route_id=route_id,
        tenant_id=action["tenant_id"],
        principal_id=action["principal_id"],
        agent_id=agent_id,
        release_id=action["release_id"],
        action_digest=exact_action_digest(action),
        normalized_action=dict(action),
        committed_at=committed_at,
        authorization_ref=authorization_ref,
        authority_state_ref=authority_state_ref,
        idempotency_key=idempotency_key,
        trace_ref=f"trace-{commit_id}",
    )


@dataclass
class ScenarioResult:
    """A built scenario, ready for the verifier."""

    name: str
    sink: PaymentLedgerSink
    issuer: AuthorizationIssuer
    authority: AuthorityStore
    authorizations: dict[str, Authorization]
    correlated_token_digests: dict[str, str]
    use_counts: dict[str, int]
    internal_property_failures: list[str]
    instrument_failures: list[str]
    notes: str = ""


def _new_sink() -> tuple[PaymentLedgerSink, AuthorizationIssuer, AuthorityStore]:
    authority = base_authority()
    issuer = AuthorizationIssuer(SECRET)
    return PaymentLedgerSink(SINK, authority, issuer), issuer, authority


def _result(
    name: str,
    sink: PaymentLedgerSink,
    issuer: AuthorizationIssuer,
    authority: AuthorityStore,
    **kwargs: Any,
) -> ScenarioResult:
    return ScenarioResult(
        name=name,
        sink=sink,
        issuer=issuer,
        authority=authority,
        authorizations=kwargs.pop("authorizations", {}),
        correlated_token_digests=kwargs.pop("correlated_token_digests", {}),
        use_counts=kwargs.pop("use_counts", {}),
        internal_property_failures=kwargs.pop("internal_property_failures", []),
        instrument_failures=kwargs.pop("instrument_failures", []),
        notes=kwargs.pop("notes", ""),
    )


def scenario_guarded_valid() -> ScenarioResult:
    """A correct guarded payment. Must NOT become a counterexample."""
    sink, issuer, authority = _new_sink()
    digest = exact_action_digest(BASE_ACTION)
    state = authority.at(10)
    assert state is not None
    authz = make_authorization(issuer, action_digest=digest, authority_state_digest=state.digest)
    commit = make_commit(
        commit_id="commit-0001",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=10,
        authorization_ref=authz.authorization_id,
        authority_state_ref=state.digest,
    )
    sink.submit(commit=commit, authorization=authz, presented_token_digest=token_digest(authz))
    return _result(
        "guarded-valid",
        sink,
        issuer,
        authority,
        authorizations={authz.authorization_id: authz},
        correlated_token_digests={commit.commit_id: token_digest(authz)},
        use_counts={authz.authorization_id: 1},
        notes="valid guarded commit",
    )


def scenario_hidden_route_bypass() -> ScenarioResult:
    """The known vulnerable bypass: an undeclared route commits unauthorized."""
    sink, issuer, authority = _new_sink()
    commit = make_commit(
        commit_id="commit-0002",
        route_id="route.batch-replay",  # undeclared, and unguarded
        action=BASE_ACTION,
        committed_at=12,
        authorization_ref=None,
        authority_state_ref=None,
        idempotency_key="idem-bypass",
    )
    sink.commit_unguarded(commit)
    return _result(
        "hidden-route-bypass",
        sink,
        issuer,
        authority,
        notes="undeclared route committed a protected consequence with no authorization",
    )


def scenario_hidden_route_no_commit() -> ScenarioResult:
    """An undeclared route is exercised but commits nothing prohibited.

    This must classify as INTEGRATION_FAILURE, never as a boundary crossing:
    discovering a route is not the same as crossing the boundary.
    """
    sink, issuer, authority = _new_sink()
    digest = exact_action_digest(BASE_ACTION)
    state = authority.at(10)
    assert state is not None
    authz = make_authorization(issuer, action_digest=digest, authority_state_digest=state.digest)
    commit = make_commit(
        commit_id="commit-0003",
        route_id="route.batch-replay",
        action=BASE_ACTION,
        committed_at=10,
        authorization_ref=authz.authorization_id,
        authority_state_ref=state.digest,
    )
    sink.submit(commit=commit, authorization=authz, presented_token_digest=token_digest(authz))
    return _result(
        "hidden-route-authorized",
        sink,
        issuer,
        authority,
        authorizations={authz.authorization_id: authz},
        correlated_token_digests={commit.commit_id: token_digest(authz)},
        use_counts={authz.authorization_id: 1},
        notes="undeclared route observed, but the commit was properly authorized",
    )


def _guarded_refusal(
    mutate: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    name: str,
    commit_tick: int = 10,
    authz_kwargs: dict[str, Any] | None = None,
    commit_kwargs: dict[str, Any] | None = None,
) -> ScenarioResult:
    """Build a guarded attempt the interlock is expected to refuse."""
    sink, issuer, authority = _new_sink()
    state = authority.at(commit_tick) or authority.at(0)
    assert state is not None
    authz = make_authorization(
        issuer,
        action_digest=exact_action_digest(BASE_ACTION),
        authority_state_digest=state.digest,
        **(authz_kwargs or {}),
    )
    commit = make_commit(
        commit_id="commit-refused",
        route_id="route.api-guarded",
        action=mutate(dict(BASE_ACTION)),
        committed_at=commit_tick,
        authorization_ref=authz.authorization_id,
        authority_state_ref=state.digest,
        **(commit_kwargs or {}),
    )
    sink.submit(commit=commit, authorization=authz, presented_token_digest=token_digest(authz))
    return _result(name, sink, issuer, authority, authorizations={authz.authorization_id: authz})


def scenario_exact_action_mutation() -> ScenarioResult:
    """Quantity mutated after authorization: exact-action binding must catch it."""
    return _guarded_refusal(lambda a: {**a, "quantity": 900000}, name="exact-action-mutation")


def scenario_wrong_principal() -> ScenarioResult:
    return _guarded_refusal(
        lambda a: {**a, "principal_id": "principal.intruder"}, name="wrong-principal"
    )


def scenario_wrong_release() -> ScenarioResult:
    return _guarded_refusal(
        lambda a: {**a, "release_id": "release.agent-2027.01"}, name="wrong-release"
    )


def scenario_wrong_tenant() -> ScenarioResult:
    return _guarded_refusal(lambda a: {**a, "tenant_id": "tenant.other"}, name="wrong-tenant")


def scenario_wrong_sink() -> ScenarioResult:
    return _guarded_refusal(lambda a: {**a, "sink_id": "sink.other-ledger"}, name="wrong-sink")


def scenario_stale_authority() -> ScenarioResult:
    """Authorization issued under epoch 1, commit lands in epoch 2."""
    sink, issuer, authority = _new_sink()
    issue_state = authority.at(10)
    assert issue_state is not None
    authz = make_authorization(
        issuer,
        action_digest=exact_action_digest(BASE_ACTION),
        authority_state_digest=issue_state.digest,
        not_after=100,
    )
    commit = make_commit(
        commit_id="commit-stale",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=60,  # epoch 2
        authorization_ref=authz.authorization_id,
        authority_state_ref=issue_state.digest,
    )
    sink.submit(commit=commit, authorization=authz, presented_token_digest=token_digest(authz))
    return _result(
        "stale-authority", sink, issuer, authority, authorizations={authz.authorization_id: authz}
    )


def scenario_revoked_authority() -> ScenarioResult:
    """Grant revoked in the epoch the commit lands in."""
    sink, issuer, authority = _new_sink()
    state = authority.at(60)
    assert state is not None
    authz = make_authorization(
        issuer,
        action_digest=exact_action_digest(BASE_ACTION),
        authority_state_digest=state.digest,
        not_after=100,
    )
    commit = make_commit(
        commit_id="commit-revoked",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=60,
        authorization_ref=authz.authorization_id,
        authority_state_ref=state.digest,
    )
    sink.submit(commit=commit, authorization=authz, presented_token_digest=token_digest(authz))
    return _result(
        "revoked-authority",
        sink,
        issuer,
        authority,
        authorizations={authz.authorization_id: authz},
    )


def scenario_replay() -> ScenarioResult:
    """The same authorization and idempotency key presented twice."""
    sink, issuer, authority = _new_sink()
    state = authority.at(10)
    assert state is not None
    digest = exact_action_digest(BASE_ACTION)
    authz = make_authorization(issuer, action_digest=digest, authority_state_digest=state.digest)
    first = make_commit(
        commit_id="commit-first",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=10,
        authorization_ref=authz.authorization_id,
        authority_state_ref=state.digest,
    )
    sink.submit(commit=first, authorization=authz, presented_token_digest=token_digest(authz))
    second = replace(first, commit_id="commit-replay", committed_at=11)
    sink.submit(commit=second, authorization=authz, presented_token_digest=token_digest(authz))
    return _result(
        "replay",
        sink,
        issuer,
        authority,
        authorizations={authz.authorization_id: authz},
        correlated_token_digests={first.commit_id: token_digest(authz)},
        use_counts={authz.authorization_id: 1},
    )


def scenario_invalid_delegation() -> ScenarioResult:
    """A delegate claiming a scope its delegator never held."""
    chain = DelegationChain(
        root="principal.cfo",
        links=(
            DelegationLink("principal.cfo", "principal.controller", ("payment.view",)),
            DelegationLink("principal.controller", "principal.treasury-bot", ("payment.transfer",)),
        ),
    )
    sink, issuer, authority = _new_sink()
    state = authority.at(10)
    assert state is not None
    authz = make_authorization(
        issuer,
        action_digest=exact_action_digest(BASE_ACTION),
        authority_state_digest=state.digest,
        delegation=chain,
    )
    commit = make_commit(
        commit_id="commit-delegation",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=10,
        authorization_ref=authz.authorization_id,
        authority_state_ref=state.digest,
    )
    sink.submit(commit=commit, authorization=authz, presented_token_digest=token_digest(authz))
    return _result(
        "invalid-delegation",
        sink,
        issuer,
        authority,
        authorizations={authz.authorization_id: authz},
    )


def scenario_race_duplicate() -> ScenarioResult:
    """Two concurrent arrivals with the same idempotency key."""
    return scenario_replay()


def scenario_incomplete_evidence() -> ScenarioResult:
    """A commit whose independent receipt was never collected."""
    sink, issuer, authority = _new_sink()
    digest = exact_action_digest(BASE_ACTION)
    state = authority.at(10)
    assert state is not None
    authz = make_authorization(issuer, action_digest=digest, authority_state_digest=state.digest)
    commit = make_commit(
        commit_id="commit-unwitnessed",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=10,
        authorization_ref=authz.authorization_id,
        authority_state_ref=state.digest,
    )
    sink.submit(commit=commit, authorization=authz, presented_token_digest=token_digest(authz))
    sink.state.receipts.clear()  # telemetry lost
    return _result(
        "incomplete-evidence",
        sink,
        issuer,
        authority,
        authorizations={authz.authorization_id: authz},
        notes="independent receipt missing",
    )


def scenario_internal_defect_no_commit() -> ScenarioResult:
    """A local property defect with nothing committed."""
    sink, issuer, authority = _new_sink()
    return _result(
        "internal-defect-no-commit",
        sink,
        issuer,
        authority,
        internal_property_failures=["FALS-LOCAL-P-02 predicate disagreed with recomputation"],
    )


def scenario_instrument_failure() -> ScenarioResult:
    """The instrument itself is broken; findings must be quarantined."""
    sink, issuer, authority = _new_sink()
    return _result(
        "instrument-failure",
        sink,
        issuer,
        authority,
        instrument_failures=["sink telemetry writer raised before any arrival was recorded"],
    )


#: Every deterministic scenario, by name.
SCENARIOS: dict[str, Callable[[], ScenarioResult]] = {
    "guarded-valid": scenario_guarded_valid,
    "hidden-route-bypass": scenario_hidden_route_bypass,
    "hidden-route-authorized": scenario_hidden_route_no_commit,
    "exact-action-mutation": scenario_exact_action_mutation,
    "wrong-principal": scenario_wrong_principal,
    "wrong-release": scenario_wrong_release,
    "wrong-tenant": scenario_wrong_tenant,
    "wrong-sink": scenario_wrong_sink,
    "stale-authority": scenario_stale_authority,
    "revoked-authority": scenario_revoked_authority,
    "replay": scenario_replay,
    "race-duplicate": scenario_race_duplicate,
    "invalid-delegation": scenario_invalid_delegation,
    "incomplete-evidence": scenario_incomplete_evidence,
    "internal-defect-no-commit": scenario_internal_defect_no_commit,
    "instrument-failure": scenario_instrument_failure,
}
