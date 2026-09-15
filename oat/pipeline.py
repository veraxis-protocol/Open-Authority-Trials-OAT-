"""End-to-end RB-001 run pipeline.

frozen scenario -> frozen canonical representation -> deterministic
adversarial search -> candidate witness -> V1 -> evidence digest
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oat import CLAIM_BEARING_USE, RUN_MODE
from oat.adversaries.base import Adversary
from oat.adversaries.deterministic import DeterministicAdversary
from oat.canonical import strip_noncanonical
from oat.digest import digest_file, digest_object
from oat.falsifiers import rb001 as rb001_falsifier
from oat.manifest import (
    ScenarioPackage,
    build_run_manifest,
    load_scenario_package,
    read_json,
    write_json,
)
from oat.reference_boundaries import rb001
from oat.verifier import v1
from oat.witness import build_witness

RUN_FILES: tuple[str, ...] = (
    "manifest.json",
    "witness.json",
    "verifier-result.json",
)


def search(
    package: ScenarioPackage, adversary: Adversary
) -> tuple[dict[str, Any], dict[str, Any], int, list[dict[str, Any]]]:
    """Search the scenario's allowed space for a counterexample candidate.

    Returns ``(trace, evaluation, selected_index, transcript)``. The first
    counterexample in deterministic enumeration order wins; if none is found,
    candidate 0 is retained as the negative witness so the control case still
    produces a verifiable artifact.

    Every candidate the adversary proposed is captured in the transcript, so a
    reader can audit what was searched rather than trusting that it was.
    """
    first_trace: dict[str, Any] | None = None
    first_evaluation: dict[str, Any] | None = None
    selected_index = 0
    transcript: list[dict[str, Any]] = []
    for index, variation in enumerate(adversary.propose(package.scenario)):
        trace = rb001.execute(package.scenario, variation)
        evaluation = rb001_falsifier.evaluate(trace)
        transcript.append(
            {
                "index": index,
                "variation": variation.to_dict(),
                "authority_effective_at_commit": trace["authority_effective_at_commit"],
                "counterexample": bool(evaluation["counterexample"]),
                "trace_digest": digest_object(trace),
            }
        )
        if first_trace is None:
            first_trace, first_evaluation, selected_index = trace, evaluation, index
        if evaluation["counterexample"]:
            return trace, evaluation, index, transcript
    if first_trace is None or first_evaluation is None:
        raise ValueError("adversary proposed no candidates")
    return first_trace, first_evaluation, selected_index, transcript


def run_scenario(
    scenario_path: str | Path,
    out_dir: str | Path | None = None,
    adversary: Adversary | None = None,
) -> dict[str, Any]:
    """Execute one scenario end to end and optionally write the run package."""
    package = load_scenario_package(scenario_path)
    active_adversary = adversary or DeterministicAdversary()
    adversary_identity = active_adversary.identity()

    run_manifest = build_run_manifest(package, rb001_falsifier.identity(), adversary_identity)
    run_manifest["runtime"]["scenario_source"] = Path(scenario_path).as_posix()

    trace, evaluation, selected_index, transcript = search(package, active_adversary)
    witness = build_witness(
        run_manifest, trace, evaluation, adversary_identity, transcript, selected_index
    )
    verifier_result = v1.verify(witness, expected_manifest=run_manifest)

    run = {
        "run_mode": RUN_MODE,
        "claim_bearing_use": CLAIM_BEARING_USE,
        "scenario_id": package.scenario.scenario_id,
        "expected_disposition": package.scenario_doc.get("expected_disposition"),
        "manifest": run_manifest,
        "witness": witness,
        "verifier_result": verifier_result,
    }
    if out_dir is not None:
        run["run_dir"] = write_run_package(out_dir, run)
    return run


def write_run_package(out_dir: str | Path, run: dict[str, Any]) -> str:
    """Write a run package plus its SHA256SUMS.json and return the directory."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    write_json(directory / "manifest.json", run["manifest"])
    write_json(directory / "witness.json", run["witness"])
    write_json(directory / "verifier-result.json", run["verifier_result"])
    write_sha256sums(directory)
    return directory.as_posix()


def write_sha256sums(run_dir: str | Path) -> dict[str, Any]:
    """Write SHA256SUMS.json covering every JSON file in the run directory."""
    directory = Path(run_dir)
    sums = {
        "sums_form": "oat-sha256sums/1",
        "run_mode": RUN_MODE,
        "claim_bearing_use": CLAIM_BEARING_USE,
        "files": {
            path.name: digest_file(path)
            for path in sorted(directory.iterdir())
            if path.is_file() and path.name != "SHA256SUMS.json"
        },
    }
    write_json(directory / "SHA256SUMS.json", sums)
    return sums


def strip_runtime_from_run_dir(run_dir: str | Path) -> list[str]:
    """Rewrite a run package keeping only canonical evidence material.

    Runtime metadata is provenance, not evidence: it records the interpreter
    and host a run happened on. A run package that is checked into version
    control must be identical whichever supported interpreter produced it, so
    the reference run drops it. No digest changes, because no digest ever
    included it.
    """
    directory = Path(run_dir)
    rewritten: list[str] = []
    for path in sorted(directory.glob("*.json")):
        if path.name == "SHA256SUMS.json":
            continue
        document = read_json(path)
        if "runtime" in document:
            write_json(path, strip_noncanonical(document))
            rewritten.append(path.name)
    write_sha256sums(directory)
    return rewritten


def verify_sha256sums(run_dir: str | Path) -> dict[str, Any]:
    """Re-verify a run directory against its SHA256SUMS.json."""
    directory = Path(run_dir)
    sums_path = directory / "SHA256SUMS.json"
    if not sums_path.is_file():
        return {"ok": False, "detail": ["SHA256SUMS.json is missing"], "checked": 0}
    import json

    recorded: dict[str, str] = json.loads(sums_path.read_text(encoding="utf-8"))["files"]
    detail: list[str] = []
    for name, expected in sorted(recorded.items()):
        path = directory / name
        if not path.is_file():
            detail.append(f"{name}: missing")
            continue
        actual = digest_file(path)
        if actual != expected:
            detail.append(f"{name}: {actual} != {expected}")
    return {"ok": not detail, "detail": detail, "checked": len(recorded)}
