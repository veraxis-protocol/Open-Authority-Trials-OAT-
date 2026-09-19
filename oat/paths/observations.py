"""Routes actually seen at the sink."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from oat.consequence.sink import PaymentLedgerSink


@dataclass(frozen=True)
class ObservedPath:
    """A route id observed in sink telemetry, with how it behaved."""

    route_id: str
    arrivals: int
    commits: int

    def to_dict(self) -> dict[str, Any]:
        return {"route_id": self.route_id, "arrivals": self.arrivals, "commits": self.commits}


def observations_from_sink(sink: PaymentLedgerSink) -> tuple[ObservedPath, ...]:
    """Derive observed routes from sink telemetry, not from the declaration."""
    arrivals: dict[str, int] = {}
    commits: dict[str, int] = {}
    for record in sink.route_log:
        arrivals[record.route_id] = arrivals.get(record.route_id, 0) + 1
        if record.committed:
            commits[record.route_id] = commits.get(record.route_id, 0) + 1
    return tuple(
        ObservedPath(route_id, arrivals[route_id], commits.get(route_id, 0))
        for route_id in sorted(arrivals)
    )
