"""The declared route inventory: what the system's designers wrote down."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DeclaredPath:
    """A route the system declares exists, and whether it claims it is guarded."""

    route_id: str
    description: str
    guarded: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_id": self.route_id,
            "description": self.description,
            "guarded": self.guarded,
        }


@dataclass(frozen=True)
class PathInventory:
    """A frozen declaration of routes.

    This object carries no authority over what exists. It records a claim,
    against which observations are compared.
    """

    paths: tuple[DeclaredPath, ...]

    @property
    def route_ids(self) -> frozenset[str]:
        return frozenset(p.route_id for p in self.paths)

    def to_dict(self) -> dict[str, Any]:
        return {"declared_paths": [p.to_dict() for p in self.paths]}
