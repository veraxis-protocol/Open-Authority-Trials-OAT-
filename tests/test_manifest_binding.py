"""Scenario loading, schema validation, and manifest binding."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oat.digest import digest_object
from oat.manifest import (
    SCHEMA_NAMES,
    BindingError,
    build_run_manifest,
    load_scenario_package,
    load_schema,
    read_json,
    runtime_metadata,
    schema_registry,
    validate,
    write_json,
)
from oat.pipeline import run_scenario
from oat.reference_boundaries.rb001 import AuthorityInput, Scenario, ScenarioError
from tests.conftest import scenario_path


def test_every_declared_schema_loads_and_is_registered() -> None:
    registry = schema_registry()
    for name in SCHEMA_NAMES:
        schema = load_schema(name)
        assert schema["$id"]
        assert registry.get(str(schema["$id"])) is not None


def test_unknown_schema_is_refused() -> None:
    with pytest.raises(BindingError):
        load_schema("not-a-schema")


def test_run_artifacts_validate_against_their_schemas(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "run")
    assert validate(run["manifest"], "run-manifest") == []
    assert validate(run["witness"], "witness") == []
    assert validate(run["witness"]["trace"], "observable-trace") == []
    assert validate(run["verifier_result"], "verifier-result") == []


def test_witness_is_bound_to_the_run_manifest(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "run")
    assert run["witness"]["manifest_digest"] == digest_object(run["manifest"])


def test_manifest_digest_ignores_runtime_metadata() -> None:
    package = load_scenario_package(scenario_path("VULN-A"))
    manifest = build_run_manifest(package, {"id": "F", "version": "1", "digest": "d"}, {"id": "A"})
    before = digest_object(manifest)
    manifest["runtime"]["scenario_source"] = "somewhere/else.json"
    assert digest_object(manifest) == before


def test_runtime_metadata_records_no_wall_clock() -> None:
    meta = runtime_metadata({"extra": "value"})
    assert meta["extra"] == "value"
    assert not any("time" in key or "date" in key for key in meta)


def test_missing_scenario_is_refused(tmp_path: Path) -> None:
    with pytest.raises(BindingError, match="scenario not found"):
        load_scenario_package(tmp_path / "absent.json")


def test_boundary_mismatch_between_scenario_and_family_is_refused(tmp_path: Path) -> None:
    source = scenario_path("VULN-A").parent
    for name in ("manifest.json", "authority.json"):
        (tmp_path / name).write_text((source / name).read_text(encoding="utf-8"))
    doc: dict[str, Any] = read_json(source / "VULN-A.json")
    doc["boundary_id"] = "RB-999"
    write_json(tmp_path / "VULN-A.json", doc)

    with pytest.raises(BindingError, match="does not match family manifest"):
        load_scenario_package(tmp_path / "VULN-A.json")


def test_schema_invalid_authority_is_refused(tmp_path: Path) -> None:
    source = scenario_path("VULN-A").parent
    (tmp_path / "manifest.json").write_text((source / "manifest.json").read_text(encoding="utf-8"))
    (tmp_path / "VULN-A.json").write_text((source / "VULN-A.json").read_text(encoding="utf-8"))
    write_json(tmp_path / "authority.json", {"subject": "S", "max_quantity": -1})

    with pytest.raises(BindingError, match="schema-invalid"):
        load_scenario_package(tmp_path / "VULN-A.json")


def test_unknown_enforcement_path_is_refused() -> None:
    authority = AuthorityInput("S", "B", 10, "USD", 0, 100)
    with pytest.raises(ScenarioError, match="unknown enforcement_path"):
        Scenario.from_dict(
            {
                "scenario_id": "X",
                "enforcement_path": "MAGIC",
                "action_quantity": 1,
                "execution_identity": "e",
                "baseline": {"check_tick": 1, "revocation_tick": 2, "commit_tick": 3},
            },
            authority,
        )


def test_authority_round_trips_through_its_dict_form() -> None:
    authority = AuthorityInput("AP_AGENT_17", "SUPPLIER_A", 250000, "USD", 0, 1000)
    assert AuthorityInput.from_dict(authority.to_dict()) == authority


def test_write_json_is_deterministic_and_newline_terminated(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "out.json"
    write_json(target, {"b": 1, "a": 2})
    text = target.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert list(json.loads(text)) == ["a", "b"]


def test_run_manifest_pins_the_target_boundary_code(tmp_path: Path) -> None:
    """The runbook requires target bytes to be hashed, so mutation is detectable."""
    from oat.digest import digest_file
    from oat.reference_boundaries import rb001

    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "run")
    target = run["manifest"]["target"]

    assert target["boundary_id"] == "RB-001"
    assert target["module"] == "oat.reference_boundaries.rb001"
    assert target["code_digest"] == digest_file(str(rb001.__file__))


def test_run_manifest_pins_the_formalism_identity(tmp_path: Path) -> None:
    run = run_scenario(scenario_path("VULN-A"), out_dir=tmp_path / "run")
    formalism = run["manifest"]["formalism"]

    assert formalism["canonicalization"] == "oat-canonical-json/1"
    assert formalism["witness_schema"]["id"] == load_schema("witness")["$id"]
    assert formalism["falsifier"]["id"] == "OAT-FALSIFIER-RB-001"
    # No protocol adapter exists for a synthetic, protocol-free boundary, and
    # the manifest says so rather than leaving the layer silently unpinned.
    assert formalism["protocol_adapter"] is None
    assert formalism["protocol_adapter_absent_reason"]


def test_environment_identity_is_recorded_as_a_digest() -> None:
    meta = runtime_metadata()
    assert meta["environment_digest"].startswith("sha256:")
    assert meta["verifier_source_tree_digest"].startswith("sha256:")


def test_scenarios_match_the_frozen_rb001_timeline() -> None:
    """The frozen RB-001 source fixes the payment and the authority envelope."""
    authority = read_json(scenario_path("VULN-A").parent / "authority.json")
    assert authority["subject"] == "AP_AGENT_17"
    assert authority["resource_or_beneficiary"] == "SUPPLIER_A"
    assert authority["max_quantity"] == 250000
    assert authority["unit"] == "USD"

    for name in ("VULN-A", "VULN-B", "CONTROL"):
        assert read_json(scenario_path(name))["action_quantity"] == 200000
