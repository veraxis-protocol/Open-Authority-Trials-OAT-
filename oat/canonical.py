"""Canonical representation rules for OAT evidence material.

Canonicalization is observable-first: it encodes what was observed of a system
under test, never VEIP-native or vendor-native state. Two structurally equal
canonical objects MUST serialize to byte-identical output on every supported
interpreter, so digests are stable across hosts and runs.
"""

from __future__ import annotations

from typing import Any

#: Keys whose subtrees are runtime metadata and are excluded from the digest
#: domain. Volatile values (wall clock, host paths, interpreter build) live
#: here so they can be recorded without perturbing evidence digests.
NONCANONICAL_KEYS: frozenset[str] = frozenset({"runtime"})

CANONICAL_FORM: str = "oat-canonical-json/1"


def strip_noncanonical(value: Any) -> Any:
    """Return ``value`` with every non-canonical subtree removed, recursively."""
    if isinstance(value, dict):
        return {
            key: strip_noncanonical(item)
            for key, item in value.items()
            if key not in NONCANONICAL_KEYS
        }
    if isinstance(value, list):
        return [strip_noncanonical(item) for item in value]
    return value


def canonical_bytes(value: Any) -> bytes:
    """Serialize ``value`` to canonical UTF-8 bytes.

    Sorted keys, minimal separators, no NaN/Infinity, no trailing newline.
    Non-canonical subtrees are stripped before serialization.
    """
    import json

    return json.dumps(
        strip_noncanonical(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_text(value: Any) -> str:
    """Canonical serialization of ``value`` as text."""
    return canonical_bytes(value).decode("utf-8")
