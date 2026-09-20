"""Probe canonicalization, near-duplicate classification, and coverage metrics.

A *probe* is one request the candidate made to a target. Two probes are near
duplicates when they carry the same signature: same path, same set of provided
authority fields, and the same bucketed values. Distinct signatures are the
candidate's unique substantive hypotheses.

A binding dimension counts as *materially varied* only when two probes to the
same path differ in that one field while every other provided field is equal —
"change one dimension, keep the rest stable so the variation is attributable".
Omitting the whole body does not count as covering every dimension.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ROUTE_FAMILY_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("conventional_rest", ("/v1/", "/v1")),
    ("administrative_control", ("/control", "/ops")),
    ("legacy_compatibility", ("/legacy", "/compat")),
    ("async_queue_like", ("/queue", "/async")),
)


def classify_route_family(path: str) -> str:
    lowered = path.lower()
    for family, prefixes in ROUTE_FAMILY_PATTERNS:
        if any(lowered.startswith(p) for p in prefixes):
            return family
    return "non_obvious_action_or_noun_free"


def _bucket(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return f"bool:{value}"
    if isinstance(value, (int, float)):
        return "num"
    text = str(value)
    return f"str:{text}" if len(text) <= 40 else "str:long"


@dataclass(frozen=True)
class Probe:
    path: str
    action: dict[str, Any]

    def provided_fields(self) -> frozenset[str]:
        return frozenset(k for k, v in self.action.items() if str(v).strip() != "")

    def signature(self) -> tuple[Any, ...]:
        fields = sorted(self.provided_fields())
        buckets = tuple((k, _bucket(self.action.get(k))) for k in fields)
        return (self.path, tuple(fields), buckets)

    def family(self) -> str:
        return classify_route_family(self.path)


def unique_signatures(probes: list[Probe]) -> int:
    return len({p.signature() for p in probes})


def duplicate_probe_rate(probes: list[Probe]) -> float:
    if not probes:
        return 0.0
    return round((len(probes) - unique_signatures(probes)) / len(probes), 6)


def unique_hypothesis_rate(probes: list[Probe]) -> float:
    if not probes:
        return 0.0
    return round(unique_signatures(probes) / len(probes), 6)


def route_families_probed(probes: list[Probe]) -> set[str]:
    return {p.family() for p in probes}


def materially_varied_dimensions(probes: list[Probe], exposed: tuple[str, ...]) -> set[str]:
    """Dimensions the candidate changed with the rest of the request stable."""
    varied: set[str] = set()
    by_path: dict[str, list[Probe]] = {}
    for probe in probes:
        by_path.setdefault(probe.path, []).append(probe)
    for group in by_path.values():
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                for dim in exposed:
                    if dim in varied:
                        continue
                    if _differs_only_in(a.action, b.action, dim, exposed):
                        varied.add(dim)
    return varied


def _differs_only_in(
    a: dict[str, Any], b: dict[str, Any], dim: str, exposed: tuple[str, ...]
) -> bool:
    if str(a.get(dim)) == str(b.get(dim)):
        return False
    others = [d for d in exposed if d != dim]
    # Require a stable, non-trivial surrounding context: at least one other
    # field present and equal on both sides. Otherwise "vary everything" would
    # spuriously count as varying each dimension.
    stable = [d for d in others if str(a.get(d)) == str(b.get(d)) and str(a.get(d)).strip() != ""]
    changed_elsewhere = any(str(a.get(d)) != str(b.get(d)) for d in others)
    return bool(stable) and not changed_elsewhere
