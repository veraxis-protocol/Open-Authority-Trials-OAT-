#!/usr/bin/env python3
"""Regenerate the Sequence 004 manifest and owner-authorization artifacts.

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


base = json.loads((RUN_DIR / "OAT_NIM_RUN_MANIFEST_003.json").read_text())

historical_immutable = [
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
    + [
        "OAT_NIM_RUN_MANIFEST_003.json",
        "OAT_OWNER_EXECUTION_AUTHORIZATION_003.json",
        "OAT_SEQUENCE_003_PROTOCOL.md",
    ]
] + [
    {"path": f"tools/{name}", "sha256": sha(ROOT / "tools" / name)}
    for name in (
        "oat_nim_host_sink_runner_002.py",
        "oat_consequence_sequence_runner_003.py",
    )
]

runner_path = ROOT / "tools" / "oat_consequence_sequence_runner_004.py"
prompt_path = RUN_DIR / "OAT_NIM_ADVERSARY_PROMPT_001.txt"

manifest = {
    "adversary_context": dict(base["adversary_context"]),
    "artifact_id": "OAT-NIM-HOST-SINK-RUN-MANIFEST-004",
    "budgets": dict(base["budgets"]),
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
    "credential_isolation": dict(base["credential_isolation"]),
    "evidence_and_adjudication": dict(base["evidence_and_adjudication"]),
    "experiment_001_resumed": False,
    "manifest_form": "oat-consequence-boundary-sequence/4",
    "outputs": {
        "adjudicator_evidence_is_adversary_visible": False,
        "files_required": [
            "sequence-manifest.json",
            "authorization-004.json",
            "adjudication/PROVIDER_PREFLIGHT_GATE.json",
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
        "sequence_directory": "runs/consequence-boundary-sequence-004",
    },
    "owner_execution_authorization": {
        "authorization_id": "OAT-OWNER-NIM-EXEC-AUTH-004",
        "consumption": (
            "authorization is consumed when the first provider request of S3 is sent; the S1 "
            "adjudicator-only positive control and the S2 reset do not consume it; bounded "
            "in-run transport retries are permitted by the frozen retry schedule; no automatic "
            "experiment rerun"
        ),
        "environment_variable": "OAT_OWNER_EXECUTION_AUTHORIZATION_ID",
        "required": True,
        "scope": "exactly one bounded Sequence 004 under this manifest",
    },
    "predecessor_run": {
        "authorization_consumed": True,
        "authorization_id": "OAT-OWNER-NIM-EXEC-AUTH-003",
        "immutable_artifacts": historical_immutable,
        "provider_calls": 1,
        "provider_http_status": 401,
        "provider_transport_failures": 1,
        "rerun": "PROHIBITED",
        "run_disposition": "HARNESS_OR_INSTRUMENT_FAILURE",
        "run_id": "OAT-NIM-HOST-SINK-001-20260920-C",
        "runner_closure_output": "INVALIDATED_BY_ADJUDICATION_DEFECT",
        "status": "HISTORICAL_AUTHORIZATION_CONSUMED_DO_NOT_RERUN",
        "subject_result": "NOT_ESTABLISHED",
        "target_http_attempts": 0,
        "why_insufficient": (
            "Run C consumed Authorization 003 on its first provider request and received "
            "HTTP 401 with zero target attempts. Runner 003 nevertheless reported closure, "
            "because it inferred execution from provider contact and replayed the raw "
            "subject verdict rather than the final fail-closed adjudication. Both defects "
            "are corrected in runner 004; the Run C evidence itself is preserved unaltered."
        ),
    },
    "produced_at": "2026-09-20",
    "provider": dict(base["provider"]),
    "provider_calls_before_gate": 0,
    "provider_preflight": {
        "consumes_experiment_authorization": False,
        "gate": "PROVIDER_PREFLIGHT = PASS is required before Run D may enter S3",
        "is_oat_experiment": False,
        "must_not_read_adjudicator_ground_truth": True,
        "must_not_touch_frozen_target": True,
        "must_not_use_adversary_prompt": True,
        "must_not_write_into_run_evidence_directory": True,
        "rationale": (
            "Run C spent a one-run owner authorization to discover an HTTP 401. The "
            "credential and transport are now proven before any authorization is at stake."
        ),
        "required": True,
        "sha256": sha(ROOT / "tools" / "oat_nvidia_provider_preflight.py"),
        "tool_id": "OAT-NVIDIA-PROVIDER-PREFLIGHT",
        "tool_path": "tools/oat_nvidia_provider_preflight.py",
        "tool_version": "1.0.0",
    },
    "readiness_gate": {
        "owner_authorization_environment_binding_present_at_runtime": False,
        "provider_credential_present_at_runtime": False,
        "ready_for_nim_experiment": False,
        "repository_binding_pr_merged_and_ci_green": False,
        "target_and_freeze_preflight_passed": False,
    },
    "run_id": "OAT-NIM-HOST-SINK-001-20260920-D",
    "run_mode": "METHOD_DEVELOPMENT_ONLY",
    "runner": {
        "frozen_target_execution_method": (
            "git archive exact target commit into temporary directory; import subject from archive"
        ),
        "proven_transport_reference": dict(base["runner"]["proven_transport_reference"]),
        "provider_transport": (
            "stdlib HTTPS/SSE using the Run B request envelope and SSE [DONE] acquisition "
            "semantics, reused unchanged"
        ),
        "repository_path": "tools/oat_consequence_sequence_runner_004.py",
        "runner_id": "OAT-CONSEQUENCE-SEQUENCE-RUNNER-004",
        "sha256": sha(runner_path),
        "version": "4.0.0",
    },
    "sampling": dict(base["sampling"]),
    "sequence": {
        "controlling_invariant": "POSITIVE_CONTROL_KNOWLEDGE intersect ADVERSARY_CONTEXT == empty",
        "sequence_id": "OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-004",
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
                "consumes_provider_authorization": False,
                "id": "PROVIDER_PREFLIGHT",
                "name": "PROVIDER_CREDENTIAL_AND_TRANSPORT_PREFLIGHT",
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
        "PROVIDER_PREFLIGHT = PASS",
        "RUN_D_EXECUTION = EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT",
        "positive-control evidence integrity = PASS",
        "Run D evidence integrity = PASS",
        "positive-control replay matches the FINAL original adjudication",
        "Run D replay matches the FINAL original adjudication",
    ],
    "sequence_closure_semantics": {
        "provider_contact_is_not_execution": (
            "RUN_D_EXECUTION is derived from instrument_status == EXECUTED and "
            "target_http_attempts > 0, never from provider_call_performed"
        ),
        "replay_compares_final_adjudication": (
            "replay re-applies the fail-closed wrapper over preserved execution facts and "
            "compares disposition, subject_result and instrument_status"
        ),
        "subject_outcome_does_not_gate_closure": (
            "a genuine Run D counterexample still permits closure when every completeness "
            "condition passes"
        ),
    },
    "status": "BOUND_AWAITING_REPOSITORY_GATE",
    "stop_conditions": list(base["stop_conditions"])
    + [
        "positive-control sensitivity not established",
        "positive-control evidence not sealed",
        "reset attestation fails",
        "post-reset adversary-context ground-truth leak audit fails",
    ],
    "target": dict(base["target"]),
    "timeouts": dict(base["timeouts"]),
}

write(RUN_DIR / "OAT_NIM_RUN_MANIFEST_004.json", manifest)

authorization = {
    "artifact_id": "OAT-OWNER-NIM-EXEC-AUTH-004",
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
        "Direct Owner work order OAT-SEQUENCE-004-CORRECTIVE-BIND-001 (2026-09-20): preserve "
        "Run C as a consumed failed experiment, correct the Sequence 003 adjudication and "
        "replay defects without rewriting historical evidence, add a non-experiment provider "
        "credential preflight, and bind exactly one new sequence, Sequence 004 / Run D. This "
        "is not authorization to rerun Run B or Run C."
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
    "authorized_run_id": "OAT-NIM-HOST-SINK-001-20260920-D",
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
    "predecessor_run_c": {
        "authorization_id": "OAT-OWNER-NIM-EXEC-AUTH-003",
        "reuse": "PROHIBITED; consumed permanently on the Run C 401",
        "rerun": "PROHIBITED",
        "status": "HISTORICAL_AUTHORIZATION_CONSUMED",
    },
    "provider_preflight_does_not_consume_provider_auth": True,
    "provider_preflight_required_before_s3": True,
    "predecessor_authorization_reuse": (
        "PROHIBITED; Run A and Run B authorizations are consumed and Run B must not be rerun"
    ),
    "produced_at": "2026-09-20",
    "provider_transport_semantics": (
        "identical to the proven Run B envelope: same provider, model, endpoint, budgets, "
        "sampling, timeouts, retry schedule and credential isolation"
    ),
    "ready_effect": (
        "Authorization alone does not make Run D ready. The corrective binding must merge "
        "with green CI, the non-experiment provider preflight must PASS, and S0/S1/S1A/S2 "
        "must all pass before the first provider request."
    ),
    "run_manifest": {
        "artifact_id": "OAT-NIM-HOST-SINK-RUN-MANIFEST-004",
        "run_id": "OAT-NIM-HOST-SINK-001-20260920-D",
        "sha256": sha(RUN_DIR / "OAT_NIM_RUN_MANIFEST_004.json"),
    },
    "sequence_id": "OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-004",
    "status": "EXPLICIT_ONE_SEQUENCE_AUTHORIZATION_RECORDED",
    "void_if": [
        "run manifest bytes change",
        "provider endpoint or model changes",
        "target commit/tree or critical blob identity changes",
        "freeze artifact SHA-256 changes",
        "prompt or runner SHA-256 changes",
        "budget, timeout, sampling, retry schedule, or stop conditions change",
        "positive-control ground truth reaches adversary context",
        "Run B or Run C evidence is modified, relabelled, reused, or rerun",
        "the provider preflight has not passed on the credential used for Run D",
        "execution would exceed the stated claim ceiling",
    ],
}

write(RUN_DIR / "OAT_OWNER_EXECUTION_AUTHORIZATION_004.json", authorization)
print("prompt", sha(prompt_path))
print("runner", sha(runner_path))
print("manifest", sha(RUN_DIR / "OAT_NIM_RUN_MANIFEST_004.json"))
