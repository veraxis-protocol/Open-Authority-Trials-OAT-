"""Scenario loading, schema validation, and run-manifest binding."""

from __future__ import annotations

import json
import platform
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError
from referencing import Registry, Resource

from oat import CLAIM_BEARING_USE, CLAIM_CEILING, RUN_MODE, __version__
from oat.canonical import CANONICAL_FORM
from oat.digest import digest_file, digest_object, digest_source_tree
from oat.reference_boundaries import rb001 as rb001_boundary
from oat.reference_boundaries.rb001 import AuthorityInput, Scenario

SCHEMA_NAMES: tuple[str, ...] = (
    "run-manifest",
    "authority-input",
    "observable-trace",
    "witness",
    "verifier-result",
)


class BindingError(ValueError):
    """Raised when a scenario package cannot be loaded or bound."""


def _schema_dir() -> Path:
    """Locate the frozen schema directory.

    Installed distributions carry the schemas as ``oat.schemas`` package data;
    a plain source checkout reads the repository's ``schemas/`` directory. Both
    resolve to the same files, so there is no second copy to drift.
    """
    try:
        from importlib.resources import files

        packaged = Path(str(files("oat.schemas")))
        if packaged.is_dir():
            return packaged
    except (ImportError, ModuleNotFoundError, TypeError):  # pragma: no cover - layout fallback
        pass
    return Path(__file__).resolve().parent.parent / "schemas"


def load_schema(name: str) -> dict[str, Any]:
    """Load a JSON schema by short name, e.g. ``witness``."""
    if name not in SCHEMA_NAMES:
        raise BindingError(f"unknown schema: {name}")
    path = _schema_dir() / f"{name}.schema.json"
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


@lru_cache(maxsize=1)
def schema_registry() -> Registry[Any]:
    """Registry of all frozen schemas, keyed by ``$id``.

    Cross-schema ``$ref``s resolve locally against this registry, so validation
    never touches the network.
    """
    resources = []
    for name in SCHEMA_NAMES:
        schema = load_schema(name)
        resources.append((str(schema["$id"]), Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def validate(instance: Any, schema_name: str) -> list[str]:
    """Return a sorted list of schema violations; empty means valid."""
    validator = Draft202012Validator(load_schema(schema_name), registry=schema_registry())
    errors: list[JsonSchemaValidationError] = list(validator.iter_errors(instance))
    return sorted(f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors)


def read_json(path: str | Path) -> dict[str, Any]:
    """Read a UTF-8 JSON object from disk."""
    data: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
    return data


def write_json(path: str | Path, value: Any) -> None:
    """Write ``value`` as deterministic pretty JSON with a trailing newline."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
    target.write_text(text + "\n", encoding="utf-8", newline="\n")


@dataclass(frozen=True)
class ScenarioPackage:
    """A frozen scenario together with everything it is bound to."""

    scenario_name: str
    scenario_doc: dict[str, Any]
    manifest_doc: dict[str, Any]
    authority_doc: dict[str, Any]
    scenario: Scenario

    @property
    def scenario_digest(self) -> str:
        return digest_object(self.scenario_doc)

    @property
    def manifest_digest(self) -> str:
        return digest_object(self.manifest_doc)

    @property
    def authority_digest(self) -> str:
        return digest_object(self.authority_doc)


def load_scenario_package(scenario_path: str | Path) -> ScenarioPackage:
    """Load a scenario file plus its referenced family manifest and authority input."""
    path = Path(scenario_path)
    if not path.is_file():
        raise BindingError(f"scenario not found: {path}")
    scenario_doc = read_json(path)

    authority_doc = read_json(
        path.parent / str(scenario_doc.get("authority_ref", "authority.json"))
    )
    authority_errors = validate(authority_doc, "authority-input")
    if authority_errors:
        raise BindingError(f"authority input is schema-invalid: {authority_errors}")

    manifest_doc = read_json(path.parent / str(scenario_doc.get("manifest_ref", "manifest.json")))

    declared_boundary = str(scenario_doc.get("boundary_id", ""))
    if declared_boundary != str(manifest_doc.get("boundary_id", "")):
        raise BindingError(
            f"scenario boundary {declared_boundary!r} does not match family manifest "
            f"{manifest_doc.get('boundary_id')!r}"
        )

    scenario = Scenario.from_dict(scenario_doc, AuthorityInput.from_dict(authority_doc))
    return ScenarioPackage(
        scenario_name=path.name,
        scenario_doc=scenario_doc,
        manifest_doc=manifest_doc,
        authority_doc=authority_doc,
        scenario=scenario,
    )


def runtime_metadata(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Non-canonical runtime metadata.

    Never enters the digest domain: it records where a run happened without
    letting the host perturb the evidence. No wall-clock value is recorded, so
    two runs on one host produce byte-identical files.
    """
    meta: dict[str, Any] = {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform_system": platform.system(),
        "oat_version": __version__,
        "verifier_source_tree_digest": digest_source_tree(Path(__file__).resolve().parent),
    }
    if extra:
        meta.update(extra)
    # Environment identity, recorded as a digest so the environment is
    # attestable without any of its volatile values entering the evidence.
    meta["environment_digest"] = digest_object(meta)
    return meta


def target_identity() -> dict[str, Any]:
    """Hash the frozen target: the reference-boundary code under test.

    The runbook requires the target bytes to be pinned, so a run can be linked
    to exactly the code it exercised and a later mutation is detectable.
    """
    module_path = Path(str(rb001_boundary.__file__)).resolve()
    return {
        "boundary_id": rb001_boundary.BOUNDARY_ID,
        "boundary_version": rb001_boundary.BOUNDARY_VERSION,
        "module": f"oat.reference_boundaries.{module_path.stem}",
        "code_digest": digest_file(module_path),
    }


def formalism_identity(falsifier_identity: dict[str, str]) -> dict[str, Any]:
    """Pin the formalism layers this run relied on.

    ``protocol_adapter`` is null by construction: RB-001 is synthetic and
    protocol-free, so no adapter layer exists to pin. A cross-protocol trial
    would have to supply one before it could be claim-bearing.
    """
    witness_schema = load_schema("witness")
    return {
        "name": "oat-rb001-observable",
        "version": "0.1.0",
        "canonicalization": CANONICAL_FORM,
        "semantics": "observable-first; logical ticks; ground-truth authority state",
        "witness_schema": {
            "id": str(witness_schema["$id"]),
            "digest": digest_object(witness_schema),
        },
        "falsifier": dict(falsifier_identity),
        "protocol_adapter": None,
        "protocol_adapter_absent_reason": "RB-001 is synthetic and protocol-free",
    }


def build_run_manifest(
    package: ScenarioPackage,
    falsifier_identity: dict[str, str],
    adversary_identity: dict[str, Any],
) -> dict[str, Any]:
    """Build the per-run manifest that a witness binds itself to."""
    return {
        "manifest_form": "oat-run-manifest/1",
        "canonical_form": CANONICAL_FORM,
        "run_mode": RUN_MODE,
        "claim_bearing_use": CLAIM_BEARING_USE,
        "claim_ceiling": CLAIM_CEILING,
        "boundary": {
            "id": str(package.manifest_doc.get("boundary_id", "")),
            "version": str(package.manifest_doc.get("boundary_version", "")),
        },
        "scenario": {
            "id": package.scenario.scenario_id,
            "name": package.scenario_name,
            "digest": package.scenario_digest,
            "enforcement_path": package.scenario.enforcement_path,
        },
        "target": target_identity(),
        "formalism": formalism_identity(falsifier_identity),
        "scenario_manifest_digest": package.manifest_digest,
        "authority_digest": package.authority_digest,
        "falsifier": dict(falsifier_identity),
        "adversary": dict(adversary_identity),
        "verifier": {"id": "OAT-V1", "version": "0.1.0"},
        "runtime": runtime_metadata({"interpreter": sys.version.split()[0]}),
    }
