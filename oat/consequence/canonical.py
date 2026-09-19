"""Exact-action normalization.

Authorization is bound to an exact action, never to an action *type*. This
module fixes what "exact" means so that a mutation anywhere in the material
surface of an action changes its digest.

The normalization is deliberately total and explicit: every field that an
authorization can be bound to is named here. A field that is genuinely not
applicable to a profile is marked :data:`~oat.consequence.model.NON_APPLICABLE`
rather than omitted, because an omitted field and an inapplicable field are
different claims (see docs/CONSEQUENCE-BOUNDARY.md).
"""

from __future__ import annotations

from typing import Any

from oat.digest import digest_object

#: Fields that participate in the exact-action digest. Ordering is irrelevant
#: (the canonical encoder sorts), but membership is load-bearing: adding a
#: field here changes every action digest and is a breaking schema change.
EXACT_ACTION_FIELDS: tuple[str, ...] = (
    "action_type",
    "target",
    "parameters",
    "quantity",
    "unit",
    "principal_id",
    "sink_id",
    "tenant_id",
    "release_id",
)


class ActionNormalizationError(ValueError):
    """Raised when an action cannot be normalized into the exact-action form."""


def normalize_action(action: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical exact-action mapping for ``action``.

    Every field in :data:`EXACT_ACTION_FIELDS` must be present. Absence is an
    error rather than a default, so a caller cannot silently widen an
    authorization by leaving a binding dimension out.
    """
    missing = [field for field in EXACT_ACTION_FIELDS if field not in action]
    if missing:
        raise ActionNormalizationError(f"missing exact-action fields: {', '.join(sorted(missing))}")
    return {field: action[field] for field in EXACT_ACTION_FIELDS}


def exact_action_digest(action: dict[str, Any]) -> str:
    """Digest the normalized exact action.

    Any mutation of a material field -- target, action type, parameters,
    quantity, principal, sink, tenant, release -- produces a different digest.
    """
    return digest_object(normalize_action(action))
