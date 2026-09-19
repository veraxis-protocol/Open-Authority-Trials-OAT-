"""Authority: what was actually true at the moment of commit.

OAT does not infer currentness from an authorization that was valid when it
was issued. Authority has a state, that state moves, and the only question
that matters is what it was when the consequence committed.
"""

from oat.authority.authorization import (
    Authorization,
    AuthorizationIssuer,
    DimensionResult,
    ValidationReport,
    validate_authorization,
)
from oat.authority.current_state import AuthorityState, AuthorityStore
from oat.authority.delegation import DelegationChain, DelegationLink, validate_delegation

__all__ = [
    "Authorization",
    "AuthorizationIssuer",
    "AuthorityState",
    "AuthorityStore",
    "DelegationChain",
    "DelegationLink",
    "DimensionResult",
    "ValidationReport",
    "validate_authorization",
    "validate_delegation",
]
