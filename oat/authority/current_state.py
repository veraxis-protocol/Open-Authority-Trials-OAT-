"""Authority state over logical time.

The store is an append-only sequence of epochs. Asking it for the authority
state "at commit" is a lookup, not an inference, so a verifier can never
accidentally substitute issue-time authority for commit-time authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from oat.digest import digest_object


@dataclass(frozen=True)
class AuthorityState:
    """A single authority epoch.

    ``active_grants`` are grant ids considered live in this epoch.
    ``revoked_grants`` and ``superseded_grants`` are tracked separately: a
    revoked grant and a superseded grant are different facts and must not be
    collapsed (see docs/CONSEQUENCE-BOUNDARY.md).
    """

    epoch: int
    effective_from: int
    active_grants: tuple[str, ...]
    revoked_grants: tuple[str, ...] = ()
    superseded_grants: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "epoch": self.epoch,
            "effective_from": self.effective_from,
            "active_grants": list(self.active_grants),
            "revoked_grants": list(self.revoked_grants),
            "superseded_grants": list(self.superseded_grants),
        }

    @property
    def digest(self) -> str:
        return digest_object(self.to_dict())

    def status_of(self, grant_id: str) -> str:
        if grant_id in self.revoked_grants:
            return "REVOKED"
        if grant_id in self.superseded_grants:
            return "SUPERSEDED"
        if grant_id in self.active_grants:
            return "ACTIVE"
        return "UNKNOWN_GRANT"


@dataclass
class AuthorityStore:
    """Ordered authority epochs, queryable at a logical tick."""

    epochs: list[AuthorityState] = field(default_factory=list)

    def add(self, state: AuthorityState) -> None:
        self.epochs.append(state)
        self.epochs.sort(key=lambda s: s.effective_from)

    def at(self, tick: int) -> AuthorityState | None:
        """Return the authority state in force at ``tick``, or ``None``.

        ``None`` means the store has no epoch covering that tick. The caller
        must treat that as missing evidence, never as "no authority" and never
        as "authority unchanged".
        """
        candidate: AuthorityState | None = None
        for state in self.epochs:
            if state.effective_from <= tick:
                candidate = state
            else:
                break
        return candidate

    def to_dict(self) -> dict[str, Any]:
        return {"epochs": [s.to_dict() for s in self.epochs]}
