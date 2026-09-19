"""Negative epistemic tests (work order §25).

These are method tests, not feature tests. Each one names an inference the
instrument must refuse to make. They are the reason OAT can say "unknown"
at all, and they are what stops a quiet run from being read as a safe one.
"""

from __future__ import annotations

from dataclasses import replace

from oat.authority.authorization import (
    UNDETERMINED,
    Authorization,
    AuthorizationIssuer,
    validate_authorization,
)
from oat.authority.current_state import AuthorityState, AuthorityStore
from oat.consequence.canonical import exact_action_digest
from oat.consequence.model import ConsequenceReceipt
from oat.consequence.scenarios import (
    BASE_ACTION,
    SECRET,
    SINK,
    make_authorization,
    make_commit,
)
from oat.evidence.replay import run_scenario
from oat.verifier.consequence import (
    ConsequenceDisposition as D,
)
from oat.verifier.consequence import (
    ConsequenceEvidence,
    adjudicate,
)


def _issuer() -> AuthorizationIssuer:
    return AuthorizationIssuer(SECRET)


def _authority() -> AuthorityStore:
    store = AuthorityStore()
    store.add(AuthorityState(epoch=1, effective_from=0, active_grants=("grant.treasury",)))
    return store


def test_credentials_present_does_not_imply_authorization_valid():
    """A syntactically perfect, integrity-valid token is not authorization.

    The token here is genuine and unmodified. It simply does not cover the
    action that committed.
    """
    issuer, authority = _issuer(), _authority()
    state = authority.at(0)
    assert state is not None
    authz = make_authorization(
        issuer, action_digest="sha256:" + "0" * 64, authority_state_digest=state.digest
    )
    assert issuer.verify_integrity(authz) is True  # credential is real
    commit = make_commit(
        commit_id="c1",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=1,
        authorization_ref=authz.authorization_id,
        authority_state_ref=state.digest,
    )
    report = validate_authorization(
        authz,
        commit,
        authority_at_commit=state,
        issuer=issuer,
        prior_use_count=1,
        correlated_token_digest=authz.digest,
    )
    assert report.valid is False
    assert "exact_action_digest" in {r.dimension for r in report.mismatches}


def test_authentication_succeeded_does_not_imply_authority_valid():
    """Integrity passes; the authority backing the grant is gone."""
    issuer = _issuer()
    store = AuthorityStore()
    store.add(AuthorityState(epoch=1, effective_from=0, active_grants=("grant.treasury",)))
    store.add(
        AuthorityState(
            epoch=2, effective_from=10, active_grants=(), revoked_grants=("grant.treasury",)
        )
    )
    issue_state = store.at(0)
    assert issue_state is not None
    authz = make_authorization(
        issuer,
        action_digest=exact_action_digest(BASE_ACTION),
        authority_state_digest=issue_state.digest,
        not_after=100,
    )
    commit = make_commit(
        commit_id="c2",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=20,
        authorization_ref=authz.authorization_id,
        authority_state_ref=issue_state.digest,
    )
    assert issuer.verify_integrity(authz) is True  # authentication fine
    report = validate_authorization(
        authz,
        commit,
        authority_at_commit=store.at(20),
        issuer=issuer,
        prior_use_count=1,
        correlated_token_digest=authz.digest,
    )
    assert report.valid is False
    assert "revocation_state" in {r.dimension for r in report.mismatches}


def test_no_harm_observed_does_not_imply_boundary_preserved():
    """Zero commits on the exercised routes says nothing about unexercised ones."""
    package = run_scenario("guarded-valid")
    verdict = package["verdict"]
    assert verdict["disposition"] == D.NO_BOUNDARY_COUNTEREXAMPLE.value
    # The negative is explicitly scoped, in the machine-readable reason.
    assert "routes actually exercised" in verdict["reason"]
    # And the instrument still reports what it never touched.
    assert verdict["path_reconciliation"]["unexercised_declared_paths"]


def test_no_counterexample_on_declared_paths_does_not_imply_all_paths_safe():
    """The bypass commits on a route the declaration never mentioned."""
    package = run_scenario("hidden-route-bypass")
    reconciliation = package["verdict"]["path_reconciliation"]
    assert reconciliation["declared_path_set"] == ["route.api-guarded", "route.console"]
    assert reconciliation["unknown_observed_paths"] == ["route.batch-replay"]
    assert package["verdict"]["disposition"] == D.CONSEQUENCE_BOUNDARY_FAILURE.value


def test_adversary_says_violation_does_not_imply_counterexample():
    """There is no channel by which an assertion can become a disposition."""
    evidence = ConsequenceEvidence(
        protected_sink=SINK, commits=[], receipts=[], authority=_authority()
    )
    # Whatever an adversary might claim, with no committed consequence the
    # verdict cannot be a boundary failure.
    verdict = adjudicate(evidence)
    assert verdict.disposition is not D.CONSEQUENCE_BOUNDARY_FAILURE


def test_missing_sink_evidence_does_not_imply_no_consequence():
    """A commit with no independent receipt is unknown, not absent."""
    package = run_scenario("incomplete-evidence")
    assert package["verdict"]["disposition"] == D.UNKNOWN_OR_UNESTABLISHED.value
    assert package["sink"]["state"]["commits"], "the commit is in the ledger"
    assert not package["sink"]["state"]["receipts"], "but was never independently witnessed"


def test_missing_authority_evidence_does_not_imply_authorization():
    """With no authority state for the commit tick, the answer is unknown."""
    issuer = _issuer()
    empty_authority = AuthorityStore()
    authz = make_authorization(
        issuer, action_digest="sha256:" + "1" * 64, authority_state_digest="sha256:" + "2" * 64
    )
    commit = make_commit(
        commit_id="c3",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=5,
        authorization_ref=authz.authorization_id,
        authority_state_ref=None,
    )
    report = validate_authorization(
        authz, commit, authority_at_commit=empty_authority.at(5), issuer=issuer
    )
    outcomes = {r.dimension: r.outcome for r in report.results}
    assert outcomes["authority_state_at_commit"] == UNDETERMINED
    assert report.valid is False  # undetermined never yields valid


def test_undetermined_alone_never_becomes_a_crossing():
    """Unknown must not be laundered into FAIL any more than into PASS."""
    issuer = _issuer()
    authority = _authority()
    state = authority.at(0)
    assert state is not None
    authz = make_authorization(
        issuer,
        action_digest=exact_action_digest(BASE_ACTION),
        authority_state_digest=state.digest,
    )
    commit = make_commit(
        commit_id="c4",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=1,
        authorization_ref=authz.authorization_id,
        authority_state_ref=state.digest,
    )
    receipt = ConsequenceReceipt(
        receipt_id="r1",
        commit_id=commit.commit_id,
        sink_id=commit.sink_id,
        route_id=commit.route_id,
        observed_at=commit.committed_at,
        action_digest=commit.action_digest,
    )
    evidence = ConsequenceEvidence(
        protected_sink=SINK,
        commits=[commit],
        receipts=[receipt],
        authorizations={authz.authorization_id: authz},
        authority=authority,
        issuer=issuer,
        # use count and correlation deliberately absent
    )
    verdict = adjudicate(evidence)
    assert verdict.disposition is D.UNKNOWN_OR_UNESTABLISHED


def test_a_tampered_authorization_is_a_mismatch_not_an_unknown():
    """Integrity failure is a determinate negative, not missing evidence."""
    issuer = _issuer()
    authority = _authority()
    state = authority.at(0)
    assert state is not None
    authz: Authorization = make_authorization(
        issuer,
        action_digest=exact_action_digest(BASE_ACTION),
        authority_state_digest=state.digest,
    )
    forged = replace(authz, integrity="hmac-sha256:" + "f" * 64)
    commit = make_commit(
        commit_id="c5",
        route_id="route.api-guarded",
        action=BASE_ACTION,
        committed_at=1,
        authorization_ref=forged.authorization_id,
        authority_state_ref=state.digest,
    )
    report = validate_authorization(
        forged,
        commit,
        authority_at_commit=state,
        issuer=issuer,
        prior_use_count=1,
        correlated_token_digest=forged.digest,
    )
    assert "authorization_integrity" in {r.dimension for r in report.mismatches}
