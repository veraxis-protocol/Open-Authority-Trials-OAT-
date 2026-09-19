"""Reconciling declared routes against observed routes.

The two set differences are the whole mechanism. An observed route that was
never declared is the signal that the declared execution graph was incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from oat.paths.inventory import PathInventory
from oat.paths.observations import ObservedPath


@dataclass(frozen=True)
class PathReconciliation:
    """Declared versus observed, with both differences named."""

    declared_path_set: tuple[str, ...]
    observed_path_set: tuple[str, ...]
    unknown_observed_paths: tuple[str, ...]
    unexercised_declared_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "declared_path_set": list(self.declared_path_set),
            "observed_path_set": list(self.observed_path_set),
            "unknown_observed_paths": list(self.unknown_observed_paths),
            "unexercised_declared_paths": list(self.unexercised_declared_paths),
        }


def reconcile(
    inventory: PathInventory, observations: tuple[ObservedPath, ...]
) -> PathReconciliation:
    """Compute the declared/observed differences.

    Discovering an undeclared route is an integration finding. On its own it
    is *not* a consequence-boundary counterexample -- that requires a
    prohibited consequence to actually commit. See
    :func:`oat.verifier.consequence.adjudicate`.
    """
    declared = inventory.route_ids
    observed = frozenset(o.route_id for o in observations)
    return PathReconciliation(
        declared_path_set=tuple(sorted(declared)),
        observed_path_set=tuple(sorted(observed)),
        unknown_observed_paths=tuple(sorted(observed - declared)),
        unexercised_declared_paths=tuple(sorted(declared - observed)),
    )
