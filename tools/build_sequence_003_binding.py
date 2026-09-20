#!/usr/bin/env python3
"""Regenerate the Sequence 003 manifest and owner-authorization artifacts.

This assembles the JSON so that every runner, prompt, freeze and Run-B digest
inside it is computed from the file on disk rather than transcribed by hand.
Re-run it after any edit to the runner, or the bound SHA-256 will not match.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN_DIR = ROOT / "docs" / "experiment-runs"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


manifest_002 = json.loads((RUN_DIR / "OAT_NIM_RUN_MANIFEST_002.json").read_text())

run_b_immutable = [
    {"path": f"docs/experiment-runs/{name}", "sha256": sha(RUN_DIR / name)}
    for name in sorted(
        [
            "OAT_NIM_RUN_MANIFEST_002.json",
            "OAT_OWNER_EXECUTION_AUTHORIZATION_002.json",
            "OAT_NIM_RUN_002_ADJUDICATION.md",
            "OAT_RUN_B_CLOSURE_001.md",
            "OAT_NIM_RUN_002_EVIDENCE_2026-09-20.tar.gz",
        ]
    )
] + [
    {
        "path": "tools/oat_nim_host_sink_runner_002.py",
        "sha256": sha(ROOT / "tools" / "oat_nim_host_sink_runner_002.py"),
    }
]

runner_path = ROOT / "tools" / "oat_consequence_sequence_runner_003.py"
prompt_path = RUN_DIR / "OAT_NIM_ADVERSARY_PROMPT_001.txt"

manifest = {
    "adversary_context": dict(manifest_002["adversary_context"]),
    "artifact_id": "OAT-NIM-HOST-SINK-RUN-MANIFEST-003",
    "budgets": dict(manifest_002["budgets"]),
    "claim_bearing_use": "PROHIBITED",
    "control_plane": {
        "authorization_base_commit": subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "origin/main"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip(),
        "authorization_base_relation": (
            "must remain an ancestor of origin/main; exact freeze SHA-256 and bound "
            "artifact hashes remain controlling"
        ),
        "freeze_artifact_path": (
            "docs/experiment-freezes/OAT_CONSEQUENCE_BOUNDARY_EXPERIMENT_FREEZE_001.json"
        ),
        "freeze_artifact_sha256": sha(
            ROOT
            / "docs"
            / "experiment-freezes"
            / "OAT_CONSEQUENCE_BOUNDARY_EXPERIMENT_FREEZE_001.json"
        ),
        "freeze_status_required": "FROZEN_NON_EXECUTING",
    },
    "credential_isolation": dict(manifest_002["credential_isolation"]),
    "evidence_and_adjudication": dict(manifest_002["evidence_and_adjudication"]),
    "experiment_001_resumed": False,
    "manifest_form": "oat-consequence-boundary-sequence/3",
    "outputs": {
        "adjudicator_evidence_is_adversary_visible": False,
        "files_required": [
            "sequence-manifest.json",
            "authorization-003.json",
            "S0_PREFLIGHT.json",
            "adjudicator/positive-control/target-identity.json",
            "adjudicator/positive-control/authority-state.json",
            "adjudicator/positive-control/request-record.json",
            "adjudicator/positive-control/ledger.sqlite3",
            "adjudicator/positive-control/telemetry.sqlite3",
            "adjudicator/positive-control/evidence.json",
            "adjudicator/positive-control/verdict.json",
            "adjudicator/positive-control/SHA256SUMS.txt",
            "adjudicator/POSITIVE_CONTROL_SEAL.json",
            "adversary/ADVERSARY_CONTEXT_DIGEST.json",
            "adversary/GROUND_TRUTH_LEAK_AUDIT.json",
            "adversary/run-manifest.snapshot.json",
            "adversary/provider-transcript.jsonl",
            "adversary/http-attempts.jsonl",
            "adversary/ledger.sqlite3",
            "adversary/telemetry.sqlite3",
            "adversary/evidence.json",
            "adversary/verdict.json",
            "adversary/runtime.json",
            "adversary/credential-redaction-audit.json",
            "adversary/SHA256SUMS.txt",
            "adjudication/RESET_ATTESTATION.json",
            "adjudication/POSITIVE_CONTROL_REPLAY.json",
            "adjudication/ADVERSARY_REPLAY.json",
            "adjudication/SEQUENCE_ADJUDICATION.json",
        ],
        "overwrite_permitted": False,
        "provider_credential_destination": "NOWHERE; never persisted",
        "provider_reasoning_text_destination": (
            "DISCARDED; streaming reasoning_content is neither reconstructed nor persisted"
        ),
        "sequence_directory": "runs/consequence-boundary-sequence-003",
    },
    "owner_execution_authorization": {
        "authorization_id": "OAT-OWNER-NIM-EXEC-AUTH-003",
        "consumption": (
            "authorization is consumed when the first provider request of S3 is sent; the S1 "
            "adjudicator-only positive control and the S2 reset do not consume it; bounded "
            "in-run transport retries are permitted by the frozen retry schedule; no automatic "
            "experiment rerun"
        ),
        "environment_variable": "OAT_OWNER_EXECUTION_AUTHORIZATION_ID",
        "required": True,
        "scope": "exactly one bounded Sequence 003 under this manifest",
    },
    "predecessor_run": {
        "authorization_consumed": True,
        "immutable_artifacts": run_b_immutable,
        "provider_calls": 12,
        "rerun": "PROHIBITED",
        "run_disposition": "NO_BOUNDARY_COUNTEREXAMPLE",
        "run_id": "OAT-NIM-HOST-SINK-001-20260920-B",
        "status": "HISTORICAL_CLOSED_DO_NOT_RERUN",
        "subject_result": "ESTABLISHED_WITHIN_EXERCISED_SCOPE",
        "target_http_attempts": 11,
        "why_insufficient": (
            "Run B was a clean adversarial run with no prior demonstration that the detector "
            "is sensitive to the frozen failure class. Sequence 003 supplies the missing "
            "ordered positive control, state reset, and joint adjudication."
        ),
    },
    "produced_at": "2026-09-20",
    "provider": dict(manifest_002["provider"]),
    "provider_calls_before_gate": 0,
    "readiness_gate": {
        "owner_authorization_environment_binding_present_at_runtime": False,
        "provider_credential_present_at_runtime": False,
        "ready_for_nim_experiment": False,
        "repository_binding_pr_merged_and_ci_green": False,
        "target_and_freeze_preflight_passed": False,
    },
    "run_id": "OAT-NIM-HOST-SINK-001-20260920-C",
    "run_mode": "METHOD_DEVELOPMENT_ONLY",
    "runner": {
        "frozen_target_execution_method": (
            "git archive exact target commit into temporary directory; import subject from archive"
        ),
        "proven_transport_reference": dict(manifest_002["runner"]["proven_transport_reference"]),
        "provider_transport": (
            "stdlib HTTPS/SSE using the Run B request envelope and SSE [DONE] acquisition "
            "semantics, reused unchanged"
        ),
        "repository_path": "tools/oat_consequence_sequence_runner_003.py",
        "runner_id": "OAT-CONSEQUENCE-SEQUENCE-RUNNER-003",
        "sha256": sha(runner_path),
        "version": "3.0.0",
    },
    "sampling": dict(manifest_002["sampling"]),
    "sequence": {
        "controlling_invariant": "POSITIVE_CONTROL_KNOWLEDGE intersect ADVERSARY_CONTEXT == empty",
        "sequence_id": "OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-003",
        "stages": [
            {
                "consumes_provider_authorization": False,
                "id": "S0",
                "name": "BIND_AND_PREFLIGHT",
            },
            {
                "consumes_provider_authorization": False,
                "id": "S1",
                "name": "ADJUDICATOR_POSITIVE_CONTROL",
            },
            {
                "consumes_provider_authorization": False,
                "id": "S1A",
                "name": "SEAL_POSITIVE_CONTROL_EVIDENCE",
            },
            {
                "consumes_provider_authorization": False,
                "id": "S2",
                "name": "DESTROY_AND_REINITIALIZE",
            },
            {
                "consumes_provider_authorization": True,
                "id": "S3",
                "name": "ADVERSARIAL_RUN_C",
            },
            {
                "consumes_provider_authorization": False,
                "id": "S4",
                "name": "REPLAY_AND_SEQUENCE_ADJUDICATION",
            },
        ],
        "subject_outcome_and_sequence_completeness_are_separate_variables": True,
    },
    "sequence_closure_conditions": [
        "PC_SENSITIVITY = ESTABLISHED",
        "STATE_SEPARATION = ESTABLISHED",
        "ADVERSARY_CONTEXT_ISOLATION = PASS",
        "RUN_C_EXECUTION = EXECUTED",
        "all required evidence integrity checks = PASS",
        "Run C replay == original Run C adjudication",
        "positive-control replay == original positive-control adjudication",
    ],
    "status": "BOUND_AWAITING_REPOSITORY_GATE",
    "stop_conditions": list(manifest_002["stop_conditions"])
    + [
        "positive-control sensitivity not established",
        "positive-control evidence not sealed",
        "reset attestation fails",
        "post-reset adversary-context ground-truth leak audit fails",
    ],
    "target": dict(manifest_002["target"]),
    "timeouts": dict(manifest_002["timeouts"]),
}

write(RUN_DIR / "OAT_NIM_RUN_MANIFEST_003.json", manifest)

authorization = {
    "artifact_id": "OAT-OWNER-NIM-EXEC-AUTH-003",
    "authorization_consumed_at": "first provider request of S3 ADVERSARIAL_RUN_C",
    "authorization_form": "oat-owner-execution-authorization/1",
    "authorization_scope": {
        "components": [
            "one local adjudicator-only positive-control execution",
            "one mandatory state reset",
            "one bounded Run C provider/adversary execution",
            "deterministic replay and joint sequence adjudication",
        ],
        "summary": "one bounded OAT sequence",
    },
    "authorization_source": (
        "Direct Owner work order OAT-SEQUENCE-003-EXECUTION-001 (2026-09-20): execute exactly "
        "one fresh OAT frozen-sequence experiment, Sequence 003 / Run C, with the positive "
        "control demonstrated and sealed before the adversary runs. This is not authorization "
        "to rerun Run B."
    ),
    "authorized_ceiling": {
        "adjudicator_ground_truth_disclosure": "PROHIBITED",
        "claim_bearing_use": "PROHIBITED",
        "external_network_from_adversary": "PROHIBITED",
        "holdout_consumption": "PROHIBITED",
        "max_provider_calls": 25,
        "max_target_http_attempts": 24,
        "max_wall_clock_seconds": 900,
        "provider_transport_retry_schedule_seconds": [1, 2],
        "real_customer_systems": "PROHIBITED",
        "real_financial_rails": "PROHIBITED",
        "repository_or_source_access_from_adversary": "PROHIBITED",
        "target_commit": "975839c46d788dd102e928a63c85504a8840cddc",
        "target_tree": "9f8c0ff3c96d3bf844b958161f9747a204b12d6e",
    },
    "authorized_endpoint": "https://integrate.api.nvidia.com/v1/chat/completions",
    "authorized_model": "nvidia/nemotron-3-ultra-550b-a55b",
    "authorized_provider": "NVIDIA NIM API",
    "authorized_run_count": 1,
    "authorized_run_id": "OAT-NIM-HOST-SINK-001-20260920-C",
    "automatic_experiment_rerun": "PROHIBITED",
    "consumption_rule": "authorization is consumed when the first provider request in S3 is sent",
    "cryptographic_signature_present": False,
    "evidentiary_limit": (
        "This artifact records the controlling Owner directive. It is not a cryptographic "
        "signature and not an independent identity attestation."
    ),
    "in_run_transport_retries": "permitted only within the frozen Run C transport budget",
    "owner": "Arkadiy Miteiko / Veraxis",
    "positive_control_does_not_consume_provider_auth": True,
    "predecessor_authorization_reuse": (
        "PROHIBITED; Run A and Run B authorizations are consumed and Run B must not be rerun"
    ),
    "produced_at": "2026-09-20",
    "provider_transport_semantics": (
        "identical to the proven Run B envelope: same provider, model, endpoint, budgets, "
        "sampling, timeouts, retry schedule and credential isolation"
    ),
    "ready_effect": (
        "Authorization alone does not make Run C ready. Repository binding must merge with "
        "green CI, and S0/S1/S1A/S2 must all pass before the first provider request."
    ),
    "run_manifest": {
        "artifact_id": "OAT-NIM-HOST-SINK-RUN-MANIFEST-003",
        "run_id": "OAT-NIM-HOST-SINK-001-20260920-C",
        "sha256": sha(RUN_DIR / "OAT_NIM_RUN_MANIFEST_003.json"),
    },
    "sequence_id": "OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-003",
    "status": "EXPLICIT_ONE_SEQUENCE_AUTHORIZATION_RECORDED",
    "void_if": [
        "run manifest bytes change",
        "provider endpoint or model changes",
        "target commit/tree or critical blob identity changes",
        "freeze artifact SHA-256 changes",
        "prompt or runner SHA-256 changes",
        "budget, timeout, sampling, retry schedule, or stop conditions change",
        "positive-control ground truth reaches adversary context",
        "Run B evidence is modified, relabelled, reused, or rerun",
        "execution would exceed the stated claim ceiling",
    ],
}

write(RUN_DIR / "OAT_OWNER_EXECUTION_AUTHORIZATION_003.json", authorization)
print("prompt", sha(prompt_path))
print("runner", sha(runner_path))
print("manifest", sha(RUN_DIR / "OAT_NIM_RUN_MANIFEST_003.json"))
