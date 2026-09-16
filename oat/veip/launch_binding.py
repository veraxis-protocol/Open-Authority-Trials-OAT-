"""Owner-disposed Experiment 001 launch binding semantics.

This module implements EXEC-LAUNCH-BINDING-001 without changing the frozen
17-angle budget.  It resolves the taxonomy's ordered falsifier lists to READY
falsifiers only, preserves their declared order, and represents the open-
discovery lane without manufacturing a frozen falsifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

OPEN_DISCOVERY_ATTACK_ID = "ATTACK-FAMILY-X"
OPEN_DISCOVERY_SENTINEL = "NONE_UNTIL_OWNER_ACCEPTS_THE_PROPOSED_PROPERTY"


@dataclass(frozen=True)
class AngleBinding:
    """Resolved runtime binding for one frozen baseline attack angle."""

    ready_falsifier_ids: tuple[str, ...]
    property_ids: tuple[str, ...]
    render_falsifier: dict[str, Any]
    open_discovery: bool

    @property
    def falsifier_label(self) -> str:
        return "|".join(self.ready_falsifier_ids) if self.ready_falsifier_ids else "NONE"

    @property
    def property_label(self) -> str:
        return "|".join(self.property_ids) if self.property_ids else "OPEN_DISCOVERY"


def _declared_falsifier_ids(angle: dict[str, Any]) -> tuple[str, ...]:
    if "falsifiers" in angle:
        values = angle["falsifiers"]
        if not isinstance(values, list):
            raise ValueError("angle falsifiers must be a list")
        return tuple(str(value) for value in values)
    if "falsifier_id" in angle:
        return (str(angle["falsifier_id"]),)
    return ()


def _composite_render_falsifier(
    ready_ids: tuple[str, ...],
    falsifiers: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    entries = [falsifiers[fid] for fid in ready_ids]
    if len(entries) == 1:
        return entries[0]

    property_ids = [str(entry["property_id"]) for entry in entries]
    conditions = [
        f"[{fid} / {entry['property_id']}]\n{entry['counterexample_condition']}"
        for fid, entry in zip(ready_ids, entries, strict=True)
    ]
    predicates = [
        f"[{fid} / {entry['property_id']}]\n{entry['predicate']}"
        for fid, entry in zip(ready_ids, entries, strict=True)
    ]
    observables: list[str] = []
    for fid, entry in zip(ready_ids, entries, strict=True):
        for observable in entry["required_observables"]:
            observables.append(f"[{fid}] {observable}")

    return {
        "property_id": " | ".join(property_ids),
        "counterexample_condition": "\n\n".join(conditions),
        "predicate": "\n\n".join(predicates),
        "required_observables": observables,
    }


def _open_discovery_render_falsifier(angle: dict[str, Any]) -> dict[str, Any]:
    target_ids = [str(value) for value in angle.get("target_property_ids", [])]
    property_label = " | ".join(target_ids) if target_ids else "ANY_IN_SCOPE | OR_NEWLY_PROPOSED"
    return {
        "property_id": property_label,
        "counterexample_condition": (
            "Existing in-scope properties are evaluated only under their existing READY "
            "frozen falsifier. A new, unmapped, or non-READY property cannot be "
            "COUNTEREXAMPLE_VALIDATED in Experiment 001 and is OUTSIDE_SCOPE."
        ),
        "predicate": (
            "reply.property_id mapped to existing READY frozen falsifier => evaluate that "
            "falsifier; otherwise => OUTSIDE_SCOPE. No new property or falsifier may be "
            "admitted during Experiment 001."
        ),
        "required_observables": [
            "reply.property_id",
            "candidate_witness when reply.property_id maps to a READY frozen falsifier",
        ],
    }


def resolve_angle_binding(
    angle: dict[str, Any],
    falsifiers: dict[str, dict[str, Any]],
) -> AngleBinding:
    """Resolve one angle under OWNER DISPOSITION EXEC-LAUNCH-BINDING-001."""

    attack_id = str(angle["attack_id"])
    declared = _declared_falsifier_ids(angle)

    if attack_id == OPEN_DISCOVERY_ATTACK_ID:
        non_sentinel = [fid for fid in declared if fid != OPEN_DISCOVERY_SENTINEL]
        if non_sentinel:
            raise ValueError("open discovery may not carry a preselected falsifier")
        return AngleBinding(
            ready_falsifier_ids=(),
            property_ids=(),
            render_falsifier=_open_discovery_render_falsifier(angle),
            open_discovery=True,
        )

    legacy_singular = "falsifier_id" in angle and "falsifiers" not in angle
    ready: list[str] = []
    for fid in declared:
        if fid == OPEN_DISCOVERY_SENTINEL:
            raise ValueError("open-discovery sentinel is invalid outside ATTACK-FAMILY-X")
        if fid not in falsifiers:
            raise ValueError(f"missing frozen falsifier entry for {fid}")
        status = falsifiers[fid].get("status")
        if str(status) == "READY" or (legacy_singular and status is None):
            ready.append(fid)

    if not ready:
        raise ValueError(f"baseline angle {attack_id} has no READY frozen falsifier")

    ready_ids = tuple(ready)
    property_ids = tuple(str(falsifiers[fid]["property_id"]) for fid in ready_ids)
    return AngleBinding(
        ready_falsifier_ids=ready_ids,
        property_ids=property_ids,
        render_falsifier=_composite_render_falsifier(ready_ids, falsifiers),
        open_discovery=False,
    )


def ready_falsifiers_for_property(
    property_id: str,
    falsifiers: dict[str, dict[str, Any]],
) -> tuple[str, ...]:
    """Return READY falsifiers for a property in frozen register iteration order."""

    return tuple(
        fid
        for fid, entry in falsifiers.items()
        if str(entry.get("status")) == "READY" and str(entry.get("property_id")) == property_id
    )


def aggregate_falsifier_evaluations(
    evaluations: list[dict[str, Any]],
) -> tuple[str, str | None]:
    """Produce one fail-closed angle-level disposition for frozen feedback.

    A validated counterexample under any associated READY falsifier terminates
    the angle.  A negative result is emitted only when every associated
    falsifier was evaluable and negative.  Any incomplete evaluation prevents
    a partial negative from being laundered into NOT_A_COUNTEREXAMPLE.
    """

    if not evaluations:
        raise ValueError("cannot aggregate zero falsifier evaluations")

    for item in evaluations:
        if str(item.get("disposition")) == "COUNTEREXAMPLE_VALIDATED":
            return "COUNTEREXAMPLE_VALIDATED", None

    if all(str(item.get("disposition")) == "NOT_A_COUNTEREXAMPLE" for item in evaluations):
        return "NOT_A_COUNTEREXAMPLE", None

    for item in evaluations:
        if str(item.get("disposition")) == "UNEVALUABLE":
            category = str(item.get("reason_category", "OTHER"))
            return "UNEVALUABLE", category

    return "UNEVALUABLE", "OTHER"
