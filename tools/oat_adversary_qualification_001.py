#!/usr/bin/env python3
"""OAT Adversary Qualification 001 — freeze and execute the synthetic matrix.

Two modes:

  freeze   record exact SHA-256 digests of every candidate prompt, the
           generator, the runner, the leak audit, the selection rules and the
           schema, plus the seed commitment, into a frozen qualification
           manifest. No provider is contacted.

  run      execute the blind 8-target matrix for every frozen candidate using
           the NIM transport, apply the frozen selection rules exactly, and
           write the result matrix, selection outcome and evidence manifest.
           Requires the frozen manifest and a provider preflight PASS.

This tool never touches the real frozen OAT target, never reads Sequence 004
adjudicator ground truth, and never authorizes Sequence 005.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from oat.qualification import GENERATOR_VERSION, QUALIFICATION_ID
from oat.qualification.runner import run_candidate_on_target
from oat.qualification.selection import CandidateAggregate, select
from oat.qualification.synthetic_targets import generate_corpus, seed_commitment

ROOT = Path(__file__).resolve().parents[1]

CANDIDATES: dict[str, Path] = {
    # Candidate A is the byte-identical Sequence 004 adversary baseline.
    "candidate-A": ROOT / "docs" / "experiment-runs" / "OAT_NIM_ADVERSARY_PROMPT_001.txt",
    # Candidate B is the breadth-oriented successor, frozen before any results.
    "candidate-B": ROOT / "docs" / "qualification" / "OAT_ADVERSARY_CANDIDATE_B_PROMPT_001.txt",
}

FROZEN_INPUTS: dict[str, Path] = {
    "generator": ROOT / "oat" / "qualification" / "synthetic_targets.py",
    "target_service": ROOT / "oat" / "qualification" / "target_service.py",
    "runner": ROOT / "oat" / "qualification" / "runner.py",
    "leak_audit": ROOT / "oat" / "qualification" / "leak_audit.py",
    "probes": ROOT / "oat" / "qualification" / "probes.py",
    "selection": ROOT / "oat" / "qualification" / "selection.py",
    "provider": ROOT / "oat" / "qualification" / "provider.py",
    "generator_spec": ROOT / "docs" / "qualification" / "02_SYNTHETIC_TARGET_GENERATOR_SPEC.json",
    "selection_rules": ROOT / "docs" / "qualification" / "03_SELECTION_RULES.json",
    "results_schema": ROOT / "docs" / "qualification" / "04_RESULTS_SCHEMA.json",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_freeze(seed_commitment_value: str) -> dict[str, Any]:
    return {
        "artifact": "OAT_ADVERSARY_QUALIFICATION_001_FROZEN_MANIFEST",
        "candidate_prompts": {cid: sha256_file(path) for cid, path in CANDIDATES.items()},
        "candidate_freeze_note": (
            "Candidate B was authored and hashed before the synthetic generator "
            "was written, so it cannot be tuned to the corpus. Candidate A is the "
            "byte-identical Sequence 004 adversary baseline."
        ),
        "claim_bearing_use": "PROHIBITED",
        "frozen_inputs": {name: sha256_file(path) for name, path in FROZEN_INPUTS.items()},
        "generator_version": GENERATOR_VERSION,
        "qualification_id": QUALIFICATION_ID,
        "seed_commitment": seed_commitment_value,
        "seed_visibility": "ADJUDICATOR_ONLY_UNTIL_ALL_RUNS_COMPLETE",
        "sequence_005": "NOT_BOUND / NOT_AUTHORIZED / NOT_EXECUTABLE",
    }


def cmd_freeze(args: argparse.Namespace) -> int:
    commitment = seed_commitment(args.seed) if args.seed else args.seed_commitment
    if not commitment:
        raise SystemExit("freeze requires --seed or --seed-commitment")
    freeze = build_freeze(commitment)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(freeze, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"frozen_manifest": str(args.out), "seed_commitment": commitment}, indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if not args.seed:
        raise SystemExit("run requires --seed (adjudicator-only)")
    freeze = json.loads(args.frozen_manifest.read_text())
    if freeze["seed_commitment"] != seed_commitment(args.seed):
        raise SystemExit("seed does not match the frozen seed commitment; refusing to run")
    for name, path in FROZEN_INPUTS.items():
        if sha256_file(path) != freeze["frozen_inputs"][name]:
            raise SystemExit(f"frozen input changed since freeze: {name}")
    for cid, path in CANDIDATES.items():
        if sha256_file(path) != freeze["candidate_prompts"][cid]:
            raise SystemExit(f"candidate prompt changed since freeze: {cid}")

    from oat.qualification.provider import NimTransport

    transport = NimTransport()
    corpus = generate_corpus(args.seed)
    matrix: dict[str, list[dict[str, Any]]] = {}
    for cid, path in CANDIDATES.items():
        prompt = path.read_text(encoding="utf-8")
        matrix[cid] = [
            run_candidate_on_target(
                candidate_id=cid,
                candidate_prompt=prompt,
                target=target,
                transport=transport,
                seed=args.seed,
            )
            for target in corpus
        ]

    outcome = select([CandidateAggregate(cid, results) for cid, results in matrix.items()])
    args.out.mkdir(parents=True, exist_ok=True)
    # Strip adjudicator-only evidence from the published matrix.
    published = {
        cid: [{k: v for k, v in r.items() if k != "adjudicator_evidence"} for r in results]
        for cid, results in matrix.items()
    }
    (args.out / "result-matrix.json").write_text(
        json.dumps(published, sort_keys=True, indent=2) + "\n"
    )
    (args.out / "selection.json").write_text(json.dumps(outcome, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"outcome": outcome["outcome"], "out": str(args.out)}, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=QUALIFICATION_ID)
    sub = parser.add_subparsers(dest="command", required=True)

    f = sub.add_parser("freeze", help="freeze the qualification manifest (no provider)")
    f.add_argument("--seed", default="", help="adjudicator-only seed; its commitment is recorded")
    f.add_argument("--seed-commitment", default="", help="precomputed seed commitment")
    f.add_argument("--out", type=Path, required=True)
    f.set_defaults(func=cmd_freeze)

    r = sub.add_parser("run", help="execute the blind matrix (requires credential + preflight)")
    r.add_argument(
        "--seed", required=True, help="adjudicator-only seed matching the frozen commitment"
    )
    r.add_argument("--frozen-manifest", type=Path, required=True)
    r.add_argument("--out", type=Path, required=True)
    r.set_defaults(func=cmd_run)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
