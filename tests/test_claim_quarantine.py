"""Quarantine labels must be inescapable.

CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE. Every artifact a reader could mistake
for a result has to say so on its face and in its machine-readable form.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import oat
from oat.cli import main
from oat.manifest import read_json
from oat.pipeline import run_scenario
from oat.replay import replay_run
from tests.conftest import scenario_path

QUARANTINE = ("METHOD_DEVELOPMENT_ONLY", "PROHIBITED")


def test_constitutional_state_is_frozen_in_code() -> None:
    assert oat.RUN_MODE == "METHOD_DEVELOPMENT_ONLY"
    assert oat.CLAIM_BEARING_USE == "PROHIBITED"
    assert oat.CLAIM_BEARING_TRIAL_AUTHORIZED is False


def test_claim_ceiling_disclaims_external_systems() -> None:
    ceiling = oat.CLAIM_CEILING
    assert "VEIP" in ceiling
    assert "no claim" in ceiling.lower()


@pytest.mark.parametrize("name", ["VULN-A", "VULN-B", "CONTROL"])
def test_every_run_artifact_carries_the_labels(name: str, tmp_path: Path) -> None:
    run_dir = tmp_path / name
    run = run_scenario(scenario_path(name), out_dir=run_dir)
    replay = replay_run(run_dir, write=True)

    for artifact in (run["manifest"], run["witness"], run["verifier_result"], replay):
        assert artifact["run_mode"] == "METHOD_DEVELOPMENT_ONLY"
        assert artifact["claim_bearing_use"] == "PROHIBITED"

    assert run["manifest"]["claim_ceiling"] == oat.CLAIM_CEILING
    assert run["verifier_result"]["claim_ceiling"] == oat.CLAIM_CEILING


@pytest.mark.parametrize("name", ["VULN-A", "CONTROL"])
def test_written_files_carry_the_labels_on_disk(name: str, tmp_path: Path) -> None:
    run_dir = tmp_path / name
    run_scenario(scenario_path(name), out_dir=run_dir)
    replay_run(run_dir, write=True)

    for filename in (
        "manifest.json",
        "witness.json",
        "verifier-result.json",
        "replay-result.json",
        "SHA256SUMS.json",
    ):
        document = read_json(run_dir / filename)
        assert document["run_mode"] == "METHOD_DEVELOPMENT_ONLY"
        assert document["claim_bearing_use"] == "PROHIBITED"


@pytest.mark.parametrize("name", ["VULN-A", "VULN-B", "CONTROL"])
def test_cli_run_prints_the_banner(name: str, tmp_path: Path) -> None:
    stream = io.StringIO()
    main(["run", str(scenario_path(name)), "--out", str(tmp_path / name)], stream=stream)
    text = stream.getvalue()
    assert "STATUS = METHOD_DEVELOPMENT_ONLY" in text
    assert "CLAIM_BEARING_USE = PROHIBITED" in text


def test_cli_json_output_is_machine_checkable(tmp_path: Path) -> None:
    stream = io.StringIO()
    main(
        ["--json", "run", str(scenario_path("VULN-A")), "--out", str(tmp_path / "run")],
        stream=stream,
    )
    text = stream.getvalue()
    payload = json.loads(text[text.index("{") :])
    assert payload["run_mode"] == "METHOD_DEVELOPMENT_ONLY"
    assert payload["claim_bearing_use"] == "PROHIBITED"


def test_readme_states_the_non_claim_bearing_position(repo_root: Path) -> None:
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    for label in QUARANTINE:
        assert label in readme
    assert "does not certify" in readme.lower()


def test_no_certification_language_anywhere_in_the_tree(repo_root: Path) -> None:
    """Guard against the specific phrases the work order prohibits."""
    banned = ("VEIP PASSED", "VEIP SURVIVED", "CERTIFIED BY OAT")
    for path in sorted(repo_root.rglob("*")):
        if (
            not path.is_file()
            or ".git" in path.parts
            or path.suffix not in {".py", ".md", ".json", ".yml", ".toml"}
        ):
            continue
        if path.name == "test_claim_quarantine.py":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").upper()
        for phrase in banned:
            assert phrase not in text, f"{path} contains prohibited phrase {phrase!r}"
