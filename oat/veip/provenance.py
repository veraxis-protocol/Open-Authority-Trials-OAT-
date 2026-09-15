"""Runtime import provenance checks for frozen VEIP subject artifacts."""

from __future__ import annotations

import importlib
import importlib.metadata
from collections.abc import Mapping, Sequence
from pathlib import Path


class ImportProvenanceError(RuntimeError):
    """Raised when a subject import escapes its isolated runtime."""


def record_import_provenance(
    *,
    modules: Mapping[str, tuple[str, str, str]],
    expected_runtime_root: str | Path,
    forbidden_roots: Sequence[str | Path],
) -> dict[str, dict[str, str]]:
    """Import subject modules and bind their paths to wheel/source identities.

    ``modules`` maps an import name to ``(distribution, wheel_sha256,
    frozen_commit)``.  The resolved module must live under the isolated runtime
    and outside every frozen or quarantined source checkout.
    """
    runtime = Path(expected_runtime_root).resolve()
    forbidden = tuple(Path(root).resolve() for root in forbidden_roots)
    result: dict[str, dict[str, str]] = {}
    for module_name, (distribution, artifact_digest, frozen_commit) in modules.items():
        module = importlib.import_module(module_name)
        raw_path = getattr(module, "__file__", None)
        if not raw_path:
            raise ImportProvenanceError(f"module has no file provenance: {module_name}")
        module_path = Path(raw_path).resolve()
        if not module_path.is_relative_to(runtime):
            raise ImportProvenanceError(f"module outside isolated runtime: {module_name}")
        if any(module_path.is_relative_to(root) for root in forbidden):
            raise ImportProvenanceError(f"module resolved to subject worktree: {module_name}")
        result[module_name] = {
            "module_file": str(module_path),
            "distribution": distribution,
            "version": importlib.metadata.version(distribution),
            "artifact_sha256": artifact_digest,
            "frozen_source_commit": frozen_commit,
        }
    return result
