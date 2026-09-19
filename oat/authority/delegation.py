"""Delegation chains and the non-amplification rule."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DelegationLink:
    """One hop of delegated authority, carrying its own scope ceiling."""

    delegator: str
    delegate: str
    scope: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"delegator": self.delegator, "delegate": self.delegate, "scope": list(self.scope)}


@dataclass(frozen=True)
class DelegationChain:
    """An ordered chain from a root principal to the acting principal."""

    root: str
    links: tuple[DelegationLink, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"root": self.root, "links": [link.to_dict() for link in self.links]}

    @property
    def terminal_principal(self) -> str:
        return self.links[-1].delegate if self.links else self.root


def validate_delegation(
    chain: DelegationChain, *, acting_principal: str, required_scope: str
) -> tuple[bool, str]:
    """Validate a delegation chain for ``required_scope``.

    Returns ``(ok, reason)``. Three things are checked, and non-amplification
    is the one that matters most: a delegate can never hold a scope its
    delegator did not itself hold.
    """
    if not chain.links:
        if chain.root != acting_principal:
            return False, "DELEGATION_ROOT_IS_NOT_ACTING_PRINCIPAL"
        return True, "NO_DELEGATION"

    expected_delegator = chain.root
    held: set[str] | None = None
    for index, link in enumerate(chain.links):
        if link.delegator != expected_delegator:
            return False, f"DELEGATION_CHAIN_BROKEN_AT_LINK_{index}"
        scope = set(link.scope)
        if held is not None and not scope <= held:
            # Non-amplification: this hop claims more than its delegator held.
            return False, f"DELEGATION_AMPLIFIED_AT_LINK_{index}"
        held = scope
        expected_delegator = link.delegate

    if chain.terminal_principal != acting_principal:
        return False, "DELEGATION_TERMINAL_IS_NOT_ACTING_PRINCIPAL"
    if held is None or required_scope not in held:
        return False, "DELEGATION_SCOPE_INSUFFICIENT"
    return True, "DELEGATION_VALID"
