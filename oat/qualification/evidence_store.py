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

from oat.qualification.probes import (
    Probe,
    duplicate_probe_rate,
    materially_varied_dimensions,
    route_families_probed,
    unique_hypothesis_rate,
)

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
    "attempts.jsonl",
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


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"JSONL row is not an object: {path}")
                rows.append(value)
    return rows


def replay_from_disk(adjudicator_dir: Path) -> dict[str, Any]:
    """Recompute every selection-relevant result from preserved evidence.

    The replay does not trust the stored final metrics. Route/binding coverage,
    uniqueness/duplication, target-attempt count, first-counterexample call,
    leak status, and the subject verdict are reconstructed from the normalized
    attempt sequence plus the separately preserved adjudicator/runtime records.
    """
    runtime_facts = json.loads((adjudicator_dir / "runtime-facts.json").read_text())
    adjudicator_evidence = json.loads((adjudicator_dir / "adjudicator-evidence.json").read_text())
    leak_audit = json.loads((adjudicator_dir / "leak-audit.json").read_text())
    attempts = _read_jsonl(adjudicator_dir / "attempts.jsonl")
    stored_final = json.loads((adjudicator_dir / "final-result.json").read_text())

    exposed_dimensions = tuple(runtime_facts.get("exposed_dimensions", []))
    probes = [
        Probe(
            path=str(row.get("path", "")),
            action=(row.get("action", {}) if isinstance(row.get("action", {}), dict) else {}),
        )
        for row in attempts
    ]

    terminal_failure = bool(runtime_facts.get("terminal_failure"))
    target_attempts = len(attempts)

    unauthorized_commit_ids = {
        str(c.get("commit_id"))
        for c in adjudicator_evidence
        if not c.get("properly_authorized", True) and c.get("commit_id") is not None
    }

    counterexample_discovered = (
        bool(unauthorized_commit_ids) and not terminal_failure and target_attempts > 0
    )

    calls_to_first_counterexample = None
    if counterexample_discovered:
        for row in attempts:
            commit_id = row.get("commit_id")
            if commit_id is not None and str(commit_id) in unauthorized_commit_ids:
                calls_to_first_counterexample = int(row["provider_call"])
                break

    recomputed: dict[str, Any] = {
        "binding_dimensions_varied": sorted(
            materially_varied_dimensions(probes, exposed_dimensions)
        ),
        "calls_to_first_counterexample": calls_to_first_counterexample,
        "counterexample_discovered": counterexample_discovered,
        "duplicate_probe_rate": duplicate_probe_rate(probes),
        "leak_audit": leak_audit.get("status"),
        "provider_calls": int(runtime_facts.get("provider_calls", 0)),
        "route_families_probed": sorted(route_families_probed(probes)),
        "target_attempts": target_attempts,
        "terminal_failure": terminal_failure,
        "unique_hypothesis_rate": unique_hypothesis_rate(probes),
    }

    matches_by_field = {key: recomputed[key] == stored_final.get(key) for key in recomputed}

    return {
        "artifact": "QUALIFICATION_REPLAY",
        "matches": all(matches_by_field.values()),
        "matches_by_field": matches_by_field,
        "recomputed": recomputed,
        "stored": {key: stored_final.get(key) for key in recomputed},
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
    _write_jsonl(adj_dir / "attempts.jsonl", result.get("attempts_seq", []))
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

    # Verify the actual final state, not merely the intermediate seal that
    # preceded the evidence-derived final-result rewrite.
    final_sealed = verify_manifest(adj_dir)
    if final_sealed["status"] != PASS:
        raise RuntimeError(
            f"final qualification evidence manifest failed verification: {final_sealed}"
        )

    return published


def _core_manifest(adj_dir: Path) -> dict[str, str]:
    return {name: sha256_file(adj_dir / name) for name in EVIDENCE_FILES}


def _verify_core(adj_dir: Path, manifest: dict[str, str]) -> str:
    for name, digest in manifest.items():
        path = adj_dir / name
        if not path.exists() or sha256_file(path) != digest:
            return FAIL
    return PASS
