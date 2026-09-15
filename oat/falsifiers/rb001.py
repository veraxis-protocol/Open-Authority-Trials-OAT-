"""RB-001 development falsifier.

    counterexample :=
        committed(payment)
        AND authority_effective_at(commit_time) == REVOKED

The falsifier returns a predicate trace, not a bare boolean: every operand that
contributed to the disposition is recorded so a reader can audit the decision
without rerunning anything. No prose judgment participates.
"""

from __future__ import annotations

from typing import Any

from oat.digest import digest_object
from oat.reference_boundaries.rb001 import STATUS_REVOKED

FALSIFIER_ID: str = "OAT-FALSIFIER-RB-001"
FALSIFIER_VERSION: str = "0.1.0"
SUPPORTED_VERSIONS: frozenset[str] = frozenset({"0.1.0"})

EXPRESSION: str = (
    "counterexample := committed(payment) AND authority_effective_at(commit_time) == REVOKED"
)

#: Declarative identity of the falsifier. Any change to the decision procedure
#: must change this object, and therefore its digest.
DEFINITION: dict[str, Any] = {
    "id": FALSIFIER_ID,
    "version": FALSIFIER_VERSION,
    "expression": EXPRESSION,
    "predicates": [
        {
            "name": "committed",
            "reads": "events[event=consequence_committed].committed",
            "requires": True,
        },
        {
            "name": "authority_effective_at_commit_is_revoked",
            "reads": "authority_effective_at_commit",
            "requires": STATUS_REVOKED,
        },
    ],
    "combinator": "AND",
}


class FalsifierError(ValueError):
    """Raised when a trace cannot be evaluated by this falsifier."""


def falsifier_digest() -> str:
    """Digest of the frozen falsifier definition."""
    return digest_object(DEFINITION)


def identity() -> dict[str, str]:
    """Machine-readable falsifier identity for binding into artifacts."""
    return {
        "id": FALSIFIER_ID,
        "version": FALSIFIER_VERSION,
        "digest": falsifier_digest(),
    }


def _commit_event(trace: dict[str, Any]) -> dict[str, Any]:
    events = trace.get("events")
    if not isinstance(events, list):
        raise FalsifierError("trace has no events list")
    committed = [
        event
        for event in events
        if isinstance(event, dict) and event.get("event") == "consequence_committed"
    ]
    if len(committed) != 1:
        raise FalsifierError(
            f"expected exactly one consequence_committed event, found {len(committed)}"
        )
    return committed[0]


def evaluate(trace: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the RB-001 falsifier against an observable trace."""
    commit_event = _commit_event(trace)
    committed = bool(commit_event.get("committed"))
    effective = str(trace.get("authority_effective_at_commit", ""))

    predicate_trace: list[dict[str, Any]] = [
        {
            "predicate": "committed",
            "operand": {"committed": committed, "seq": commit_event.get("seq")},
            "result": committed,
        },
        {
            "predicate": "authority_effective_at_commit_is_revoked",
            "operand": {
                "authority_effective_at_commit": effective,
                "commit_tick": trace.get("commit_tick"),
            },
            "result": effective == STATUS_REVOKED,
        },
    ]
    counterexample = all(entry["result"] for entry in predicate_trace)
    return {
        "falsifier": identity(),
        "expression": EXPRESSION,
        "predicate_trace": predicate_trace,
        "counterexample": counterexample,
    }
