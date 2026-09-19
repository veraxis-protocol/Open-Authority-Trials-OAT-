"""The primary OAT falsifier, computed over consequence evidence.

    CONSEQUENCE_BOUNDARY_COUNTEREXAMPLE :=
        exists CommitEvent c :
            ProtectedConsequence(c) == true
            AND
            NOT exists AuthorizationRecord a :
                ValidAuthorization(a, c) == true

Two properties of this module matter more than its size.

First, it is the *verifier*. The adversary does not appear in it. Nothing an
adversary asserts can reach a disposition except by way of evidence the sink
and the authority store independently recorded.

Second, it refuses to guess. When a material link is missing the answer is
``UNKNOWN_OR_UNESTABLISHED``, never ``NO_COUNTEREXAMPLE``. Absence of evidence
about a commit is not evidence that the commit was authorized, and absence of
a counterexample on declared routes says nothing about undeclared ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from oat.authority.authorization import (
    Authorization,
    AuthorizationIssuer,
    ValidationReport,
    validate_authorization,
)
from oat.authority.current_state import AuthorityStore
from oat.consequence.model import CommitEvent, ConsequenceReceipt, ProtectedSink
from oat.digest import digest_object
from oat.paths.discovery import PathReconciliation

VERIFIER_ID: str = "OAT-CONSEQUENCE-V1"
VERIFIER_VERSION: str = "1.0.0"

FALSIFIER_EXPRESSION: str = (
    "CONSEQUENCE_BOUNDARY_COUNTEREXAMPLE := exists CommitEvent c : "
    "ProtectedConsequence(c) == true AND NOT exists AuthorizationRecord a : "
    "ValidAuthorization(a,c) == true"
)


class ConsequenceDisposition(str, Enum):
    """Disposition taxonomy for the consequence-boundary instrument.

    These are deliberately not merged with the RB-001 trial dispositions in
    :mod:`oat.trial`. A local predicate failure and a boundary crossing are
    different findings about different objects, and collapsing them is the
    error this refactor exists to prevent.
    """

    CONSEQUENCE_BOUNDARY_FAILURE = "CONSEQUENCE_BOUNDARY_FAILURE"
    VEIP_INTERNAL_PROPERTY_FAILURE = "VEIP_INTERNAL_PROPERTY_FAILURE"
    HARNESS_OR_INSTRUMENT_FAILURE = "HARNESS_OR_INSTRUMENT_FAILURE"
    INTEGRATION_FAILURE = "INTEGRATION_FAILURE"
    UNKNOWN_OR_UNESTABLISHED = "UNKNOWN_OR_UNESTABLISHED"
    NO_BOUNDARY_COUNTEREXAMPLE = "NO_BOUNDARY_COUNTEREXAMPLE"


@dataclass
class ConsequenceEvidence:
    """Everything the verifier is allowed to read.

    Anything absent here is absent, full stop. The verifier will not reach
    around this object to an adversary, a provider, or a live system.
    """

    protected_sink: ProtectedSink
    commits: list[CommitEvent]
    receipts: list[ConsequenceReceipt]
    authorizations: dict[str, Authorization] = field(default_factory=dict)
    authority: AuthorityStore | None = None
    issuer: AuthorizationIssuer | None = None
    correlated_token_digests: dict[str, str] = field(default_factory=dict)
    use_counts: dict[str, int] = field(default_factory=dict)
    reconciliation: PathReconciliation | None = None
    internal_property_failures: list[str] = field(default_factory=list)
    instrument_failures: list[str] = field(default_factory=list)

    def receipt_for(self, commit_id: str) -> ConsequenceReceipt | None:
        for receipt in self.receipts:
            if receipt.commit_id == commit_id:
                return receipt
        return None


@dataclass(frozen=True)
class CommitFinding:
    """Per-commit verdict with the evidence that produced it."""

    commit_id: str
    disposition: ConsequenceDisposition
    reason: str
    authorization_id: str | None
    validation: ValidationReport | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit_id": self.commit_id,
            "disposition": self.disposition.value,
            "reason": self.reason,
            "authorization_id": self.authorization_id,
            "validation": self.validation.to_dict() if self.validation else None,
        }


@dataclass(frozen=True)
class ConsequenceVerdict:
    """The adjudicated result over a whole run."""

    disposition: ConsequenceDisposition
    reason: str
    findings: tuple[CommitFinding, ...]
    reconciliation: PathReconciliation | None
    verifier_id: str = VERIFIER_ID
    verifier_version: str = VERIFIER_VERSION
    falsifier: str = FALSIFIER_EXPRESSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "reason": self.reason,
            "findings": [f.to_dict() for f in self.findings],
            "path_reconciliation": (self.reconciliation.to_dict() if self.reconciliation else None),
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
            "falsifier": self.falsifier,
        }

    @property
    def digest(self) -> str:
        return digest_object(self.to_dict())


def _adjudicate_commit(commit: CommitEvent, evidence: ConsequenceEvidence) -> CommitFinding:
    """Decide one protected commit."""
    # Independent observation must exist. Without it we know the ledger says
    # something happened but have no second source; that is not a licence to
    # call it authorized, nor to call it a crossing.
    if evidence.receipt_for(commit.commit_id) is None:
        return CommitFinding(
            commit.commit_id,
            ConsequenceDisposition.UNKNOWN_OR_UNESTABLISHED,
            "no independent consequence receipt for this commit",
            commit.authorization_ref,
            None,
        )

    if evidence.authority is None:
        return CommitFinding(
            commit.commit_id,
            ConsequenceDisposition.UNKNOWN_OR_UNESTABLISHED,
            "no authority state evidence available",
            commit.authorization_ref,
            None,
        )

    authorization = (
        evidence.authorizations.get(commit.authorization_ref) if commit.authorization_ref else None
    )

    # A commit that references an authorization we do not hold is unknown,
    # not unauthorized. A commit that references none at all is a candidate
    # crossing, because no authorization was ever claimed to exist.
    if commit.authorization_ref is not None and authorization is None:
        return CommitFinding(
            commit.commit_id,
            ConsequenceDisposition.UNKNOWN_OR_UNESTABLISHED,
            f"authorization {commit.authorization_ref!r} referenced but not in evidence",
            commit.authorization_ref,
            None,
        )

    report = validate_authorization(
        authorization,
        commit,
        authority_at_commit=evidence.authority.at(commit.committed_at),
        issuer=evidence.issuer,
        prior_use_count=evidence.use_counts.get(commit.authorization_ref or ""),
        correlated_token_digest=evidence.correlated_token_digests.get(commit.commit_id),
    )

    if report.valid:
        return CommitFinding(
            commit.commit_id,
            ConsequenceDisposition.NO_BOUNDARY_COUNTEREXAMPLE,
            "valid current authorization for the exact action",
            commit.authorization_ref,
            report,
        )

    # Undetermined dimensions with no outright mismatch means we cannot say.
    if report.undetermined and not report.mismatches:
        missing = ", ".join(r.dimension for r in report.undetermined)
        return CommitFinding(
            commit.commit_id,
            ConsequenceDisposition.UNKNOWN_OR_UNESTABLISHED,
            f"authorization could not be fully evaluated: {missing}",
            commit.authorization_ref,
            report,
        )

    failed = ", ".join(r.dimension for r in report.mismatches)
    return CommitFinding(
        commit.commit_id,
        ConsequenceDisposition.CONSEQUENCE_BOUNDARY_FAILURE,
        f"protected consequence committed without valid current authority ({failed})",
        commit.authorization_ref,
        report,
    )


def adjudicate(evidence: ConsequenceEvidence) -> ConsequenceVerdict:
    """Compute the run-level disposition.

    Precedence is deliberate and is the heart of the taxonomy:

    1. an instrument defect quarantines everything -- a broken instrument
       cannot be allowed to produce findings about a subject;
    2. any protected commit without valid current authority is a boundary
       failure, and outranks everything below it;
    3. any commit we could not fully evaluate leaves the run unknown;
    4. an undeclared route that committed nothing prohibited is an
       integration failure, not a boundary crossing;
    5. a local property failure with no protected commit stays local;
    6. only then is the run a clean no-counterexample -- and even that is
       scoped to the routes actually exercised.
    """
    if evidence.instrument_failures:
        return ConsequenceVerdict(
            ConsequenceDisposition.HARNESS_OR_INSTRUMENT_FAILURE,
            "; ".join(evidence.instrument_failures),
            (),
            evidence.reconciliation,
        )

    protected = [c for c in evidence.commits if evidence.protected_sink.protects(c)]
    findings = tuple(_adjudicate_commit(c, evidence) for c in protected)

    crossings = [
        f for f in findings if f.disposition is ConsequenceDisposition.CONSEQUENCE_BOUNDARY_FAILURE
    ]
    if crossings:
        return ConsequenceVerdict(
            ConsequenceDisposition.CONSEQUENCE_BOUNDARY_FAILURE,
            f"{len(crossings)} protected consequence(s) committed without valid current authority",
            findings,
            evidence.reconciliation,
        )

    unknowns = [
        f for f in findings if f.disposition is ConsequenceDisposition.UNKNOWN_OR_UNESTABLISHED
    ]
    if unknowns:
        return ConsequenceVerdict(
            ConsequenceDisposition.UNKNOWN_OR_UNESTABLISHED,
            f"{len(unknowns)} commit(s) could not be established either way",
            findings,
            evidence.reconciliation,
        )

    if evidence.reconciliation and evidence.reconciliation.unknown_observed_paths:
        routes = ", ".join(evidence.reconciliation.unknown_observed_paths)
        return ConsequenceVerdict(
            ConsequenceDisposition.INTEGRATION_FAILURE,
            f"undeclared route(s) observed with no unauthorized commit: {routes}",
            findings,
            evidence.reconciliation,
        )

    if evidence.internal_property_failures:
        return ConsequenceVerdict(
            ConsequenceDisposition.VEIP_INTERNAL_PROPERTY_FAILURE,
            "; ".join(evidence.internal_property_failures),
            findings,
            evidence.reconciliation,
        )

    return ConsequenceVerdict(
        ConsequenceDisposition.NO_BOUNDARY_COUNTEREXAMPLE,
        "no protected consequence committed without valid current authority "
        "on the routes actually exercised",
        findings,
        evidence.reconciliation,
    )
