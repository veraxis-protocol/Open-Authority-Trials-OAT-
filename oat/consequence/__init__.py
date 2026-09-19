"""Protected consequences: the durable state OAT actually asks about.

A consequence is not a verifier boolean. It is a record that something
irreversible happened in a sink, observable independently of whatever the
authorization engine or the adversary says about it.
"""

from oat.consequence.model import (
    NON_APPLICABLE,
    CommitEvent,
    ConsequenceReceipt,
    NormalizedAction,
    ProtectedSink,
)

__all__ = [
    "NON_APPLICABLE",
    "CommitEvent",
    "ConsequenceReceipt",
    "NormalizedAction",
    "ProtectedSink",
]
