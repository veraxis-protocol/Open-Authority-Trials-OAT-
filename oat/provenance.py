"""Derive runtime artifact labels and state prefixes from bound identities.

Sequence 003's runner hard-coded ``RUN_C_RUNTIME`` as an artifact label and
``oat-seq003-`` as its temporary-state prefix. Runner 004 inherited both by
copy, so a Sequence 004 run wrote evidence labelled with a Sequence 003 run
identity. Nothing scientific depended on it, but provenance that disagrees
with itself is provenance nobody can check.

These helpers derive both from the identity actually bound for the run, so a
successor runner cannot emit a predecessor's label unless it really is that
run. Historical evidence is never rewritten -- this governs new runs only.
"""

from __future__ import annotations

import re

__all__ = [
    "ProvenanceMismatch",
    "assert_provenance_consistent",
    "run_suffix",
    "runtime_artifact_label",
    "sequence_number",
    "temp_state_prefix",
]

_RUN_SUFFIX = re.compile(r"-([A-Z])$")
_SEQUENCE_NUMBER = re.compile(r"(\d+)\s*$")


class ProvenanceMismatch(RuntimeError):
    """A label or path prefix disagrees with the bound identity."""


def run_suffix(run_id: str) -> str:
    """The trailing run letter of a run id, e.g. ``...-20260920-D`` -> ``D``.

    Run ids without a single-letter suffix have no short form; the caller gets
    an empty string and must fall back to the full identity.
    """
    match = _RUN_SUFFIX.search(run_id.strip())
    return match.group(1) if match else ""


def sequence_number(sequence_id: str) -> str:
    """The trailing sequence number, e.g. ``...-SEQUENCE-005`` -> ``005``."""
    match = _SEQUENCE_NUMBER.search(sequence_id.strip())
    if not match:
        raise ProvenanceMismatch(f"sequence id carries no sequence number: {sequence_id!r}")
    return match.group(1)


def runtime_artifact_label(run_id: str) -> str:
    """The runtime artifact label for ``run_id``.

    ``OAT-NIM-HOST-SINK-001-20260920-D`` becomes ``RUN_D_RUNTIME``. A run id
    with no single-letter suffix gets a label built from the whole identity,
    which is ugly but cannot silently collide with another run's label.
    """
    suffix = run_suffix(run_id)
    if suffix:
        return f"RUN_{suffix}_RUNTIME"
    sanitized = re.sub(r"[^A-Za-z0-9]+", "_", run_id.strip()).strip("_").upper()
    if not sanitized:
        raise ProvenanceMismatch(f"run id yields no usable label: {run_id!r}")
    return f"{sanitized}_RUNTIME"


def temp_state_prefix(sequence_id: str) -> str:
    """The temporary-state directory prefix for ``sequence_id``.

    ``OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-005`` becomes ``oat-seq005-``.
    """
    return f"oat-seq{sequence_number(sequence_id)}-"


def assert_provenance_consistent(
    *, sequence_id: str, run_id: str, artifact_label: str, state_prefix: str
) -> None:
    """Refuse a label or prefix that does not belong to the bound identity."""
    expected_label = runtime_artifact_label(run_id)
    if artifact_label != expected_label:
        raise ProvenanceMismatch(
            f"artifact label {artifact_label!r} does not match run {run_id!r} "
            f"(expected {expected_label!r})"
        )
    expected_prefix = temp_state_prefix(sequence_id)
    if state_prefix != expected_prefix:
        raise ProvenanceMismatch(
            f"state prefix {state_prefix!r} does not match sequence {sequence_id!r} "
            f"(expected {expected_prefix!r})"
        )
