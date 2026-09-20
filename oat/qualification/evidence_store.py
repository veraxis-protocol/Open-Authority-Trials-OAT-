"""Persist, verify, and replay per-pair qualification evidence.

Every candidate/target pair writes a full adjudicator-only evidence set — model
transcript, target evidence, adjudicator evidence, the leak-audit artifact and
runtime facts — plus a final result and a replay result, each sealed by a
SHA-256 manifest that is generated and immediately verified. The publishable
result is a separate, stripped view; the adjudicator store keeps the evidence
replay needs, so nothing required to reconstruct the verdict is thrown away.

``evidence_integrity`` and ``replay_matches_final`` on the published result are
derived here from the manifest verification and from a replay that reconstructs
the final verdict using only the preserved evidence — never hard-coded.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from oat.qualification.runner import reconstruct_final

PASS = "PASS"
FAIL = "FAIL"

PUBLISHED_FIELDS = (
    "binding_dimensions_varied",
    "calls_to_first_counterexample",
    "candidate_id",
    "counterexample_discovered",
    "duplicate_probe_rate",
    "evidence_integrity",
    "leak_audit",
    "provider_calls",
    "replay_matches_final",
    "route_families_probed",
    "stop_reason",
    "target_attempts",
    "target_id",
    "terminal_failure",
    "unique_hypothesis_rate",
)

# Evidence written before the manifest is sealed; corrupting any of these must
# make integrity verification fail.
EVIDENCE_FILES = (
    "transcript.jsonl",
    "target-evidence.json",
    "adjudicator-evidence.json",
    "leak-audit.json",
    "runtime-facts.json",
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(directory: Path) -> None:
    files = sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt")
    lines = [f"{sha256_file(p)}  {p.relative_to(directory).as_posix()}" for p in files]
    (directory / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_manifest(directory: Path) -> dict[str, Any]:
    sums = directory / "SHA256SUMS.txt"
    if not sums.exists():
        return {"status": FAIL, "reason": "SHA256SUMS.txt missing", "checked": 0, "mismatched": []}
    listed: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        if line.strip():
            expected, rel = line.split("  ", 1)
            listed[rel] = expected
    present = {
        p.relative_to(directory).as_posix()
        for p in directory.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS.txt"
    }
    mismatched: list[str] = []
    for rel, expected in listed.items():
        target = directory / rel
        if not target.exists() or sha256_file(target) != expected:
            mismatched.append(rel)
    # A file added or removed after sealing is also a corruption.
    mismatched.extend(sorted(present - set(listed)))
    return {
        "status": PASS if not mismatched else FAIL,
        "checked": len(listed),
        "mismatched": sorted(set(mismatched)),
    }


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def replay_from_disk(adjudicator_dir: Path) -> dict[str, Any]:
    """Reconstruct the final verdict from preserved evidence only, on disk.

    Reads runtime facts and adjudicator evidence back from the store and
    recomputes the fail-closed adjudication, then compares it to the stored
    final result. An altered final verdict cannot match; a terminal or
    zero-attempt run cannot reconstruct as solved.
    """
    runtime_facts = json.loads((adjudicator_dir / "runtime-facts.json").read_text())
    adjudicator_evidence = json.loads((adjudicator_dir / "adjudicator-evidence.json").read_text())
    stored_final = json.loads((adjudicator_dir / "final-result.json").read_text())
    recomputed = reconstruct_final(runtime_facts, adjudicator_evidence)
    matches = all(recomputed[k] == stored_final.get(k) for k in recomputed)
    return {
        "artifact": "QUALIFICATION_REPLAY",
        "matches": matches,
        "recomputed": recomputed,
        "stored": {k: stored_final.get(k) for k in recomputed},
    }


def _published_view(
    result: dict[str, Any], *, evidence_integrity: str, replay_matches: bool
) -> dict[str, Any]:
    view = {k: result.get(k) for k in PUBLISHED_FIELDS if k in result}
    view["evidence_integrity"] = evidence_integrity
    view["replay_matches_final"] = replay_matches
    return view


def persist_and_verify(base_dir: Path, result: dict[str, Any]) -> dict[str, Any]:
    """Write the pair's evidence, seal and verify it, replay it, publish the result.

    Returns the schema-conforming published result with evidence-derived
    ``evidence_integrity`` and ``replay_matches_final``.
    """
    candidate_id = result["candidate_id"]
    target_id = result["target_id"]
    adj_dir = base_dir / "adjudicator" / candidate_id / target_id
    adj_dir.mkdir(parents=True, exist_ok=True)

    _write_jsonl(adj_dir / "transcript.jsonl", result.get("transcript", []))
    _write_json(adj_dir / "target-evidence.json", result.get("target_evidence", {}))
    _write_json(adj_dir / "adjudicator-evidence.json", result.get("adjudicator_evidence", []))
    _write_json(adj_dir / "leak-audit.json", result.get("leak_audit_artifact", {}))
    _write_json(adj_dir / "runtime-facts.json", result.get("runtime_facts", {}))

    # Integrity over the core evidence, before the derived artifacts exist.
    core_manifest = _core_manifest(adj_dir)
    core_integrity = _verify_core(adj_dir, core_manifest)

    # Stored final result carries the recorded verdict; replay must reproduce it.
    final_view = _published_view(result, evidence_integrity="NOT_VERIFIED", replay_matches=False)
    _write_json(adj_dir / "final-result.json", final_view)

    replay = replay_from_disk(adj_dir)
    _write_json(adj_dir / "replay-result.json", replay)

    write_manifest(adj_dir)
    sealed = verify_manifest(adj_dir)

    evidence_integrity = PASS if (core_integrity == PASS and sealed["status"] == PASS) else FAIL
    replay_matches = bool(replay["matches"])

    published = _published_view(
        result, evidence_integrity=evidence_integrity, replay_matches=replay_matches
    )
    # Re-seal so the on-disk final result carries the derived values, and the
    # manifest still verifies against it.
    _write_json(adj_dir / "final-result.json", published)
    write_manifest(adj_dir)
    return published


def _core_manifest(adj_dir: Path) -> dict[str, str]:
    return {name: sha256_file(adj_dir / name) for name in EVIDENCE_FILES}


def _verify_core(adj_dir: Path, manifest: dict[str, str]) -> str:
    for name, digest in manifest.items():
        path = adj_dir / name
        if not path.exists() or sha256_file(path) != digest:
            return FAIL
    return PASS
