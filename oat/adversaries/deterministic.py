"""Deterministic local adversary.

Commit 1's adversary is an exhaustive, ordered grid search over the scenario's
declared dimensions: timing/order, retry, stale cached decision reuse, bounded
propagation delay, duplicate request, and race ordering. It uses no randomness
and no clock, so the same scenario always yields the same candidate sequence on
every host and interpreter.
"""

from __future__ import annotations

from collections.abc import Iterator
from itertools import product
from typing import Any

from oat.adversaries.base import Adversary
from oat.reference_boundaries.rb001 import Scenario, Variation

DEFAULT_MAX_CANDIDATES: int = 4096

#: Dimensions the adversary is permitted to vary, and their defaults.
DIMENSIONS: dict[str, list[Any]] = {
    "check_tick": [10],
    "revocation_tick": [20],
    "commit_offset": [1],
    "propagation_delay": [0],
    "retry_index": [0],
    "duplicate_request": [False],
}


class DeterministicAdversary(Adversary):
    """Ordered grid search over a scenario's allowed variation dimensions."""

    id = "OAT-ADVERSARY-DETERMINISTIC"
    version = "0.1.0"

    def __init__(self, max_candidates: int = DEFAULT_MAX_CANDIDATES) -> None:
        self.max_candidates = max_candidates

    def _axes(self, scenario: Scenario) -> dict[str, list[Any]]:
        axes: dict[str, list[Any]] = {}
        for name, default in DIMENSIONS.items():
            values = scenario.search_space.get(name, default)
            if not isinstance(values, list) or not values:
                raise ValueError(f"search_space.{name} must be a non-empty list")
            # Sorted so enumeration order never depends on how the JSON was written.
            axes[name] = sorted(values, key=repr)
        return axes

    def propose(self, scenario: Scenario) -> Iterator[Variation]:
        axes = self._axes(scenario)
        names = sorted(axes)
        for emitted, combination in enumerate(product(*(axes[name] for name in names)), start=1):
            point = dict(zip(names, combination, strict=True))
            revocation_tick = int(point["revocation_tick"])
            yield Variation(
                check_tick=int(point["check_tick"]),
                revocation_tick=revocation_tick,
                commit_tick=revocation_tick + int(point["commit_offset"]),
                propagation_delay=int(point["propagation_delay"]),
                retry_index=int(point["retry_index"]),
                duplicate_request=bool(point["duplicate_request"]),
            )
            if emitted >= self.max_candidates:
                return

    def identity(self) -> dict[str, Any]:
        identity = super().identity()
        identity["strategy"] = "ordered-grid-search"
        identity["max_candidates"] = self.max_candidates
        return identity
