from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = (
    Path(__file__).resolve().parents[1]
    if Path(__file__).resolve().parent.name == "tests"
    else Path(__file__).resolve().parent
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _repo_file(*parts: str) -> Path:
    candidate = ROOT.joinpath(*parts)
    if candidate.exists():
        return candidate
    # package-local fallback for standalone validation
    return Path(__file__).resolve().parent.joinpath(*parts[-1:])


def test_bound_manifest_prompt_runner_and_authorization() -> None:
    manifest_path = _repo_file("docs", "experiment-runs", "OAT_NIM_RUN_MANIFEST_001.json")
    auth_path = _repo_file("docs", "experiment-runs", "OAT_OWNER_EXECUTION_AUTHORIZATION_001.json")
    prompt_path = _repo_file("docs", "experiment-runs", "OAT_NIM_ADVERSARY_PROMPT_001.txt")
    runner_path = _repo_file("tools", "oat_nim_host_sink_runner_001.py")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    auth = json.loads(auth_path.read_text(encoding="utf-8"))

    assert manifest["provider"]["provider"] == "NVIDIA NIM API"
    assert (
        manifest["provider"]["endpoint"] == "https://integrate.api.nvidia.com/v1/chat/completions"
    )
    assert manifest["provider"]["model"] == "nvidia/nemotron-3-ultra-550b-a55b"
    assert manifest["credential_isolation"]["environment_variable"] == "NVIDIA_API_KEY"
    assert manifest["adversary_context"]["repository_access"] is False
    assert manifest["adversary_context"]["source_code_access"] is False
    assert manifest["adversary_context"]["external_network_access"] is False
    assert manifest["sampling"] == {
        "api_stop": None,
        "max_tokens": 6144,
        "n": 1,
        "reasoning_budget": 4096,
        "reasoning_content_digest_recorded_if_returned": True,
        "reasoning_content_persisted": False,
        "reasoning_effort": "high",
        "seed": 20260920,
        "stream": False,
        "temperature": 1.0,
        "top_p": 0.95,
    }
    assert manifest["budgets"]["max_provider_calls"] == 25
    assert manifest["budgets"]["max_target_http_attempts"] == 24
    assert manifest["timeouts"]["run_wall_clock_seconds"] == 900
    assert manifest["outputs"]["overwrite_permitted"] is False
    assert manifest["claim_bearing_use"] == "PROHIBITED"
    assert manifest["owner_execution_authorization"]["authorization_id"] == auth["artifact_id"]
    assert auth["authorized_run_count"] == 1
    assert auth["no_automatic_retry"] is True
    assert auth["run_manifest"]["sha256"] == _sha(manifest_path)
    assert manifest["adversary_context"]["prompt_sha256"] == _sha(prompt_path)
    assert manifest["runner"]["sha256"] == _sha(runner_path)


def test_adversary_material_contains_no_adjudicator_ground_truth() -> None:
    # Read the control freeze dynamically so this test does not duplicate or
    # publish the adjudicator-only route/path in the run-binding artifacts.
    freeze_path = (
        ROOT / "docs" / "experiment-freezes" / "OAT_CONSEQUENCE_BOUNDARY_EXPERIMENT_FREEZE_001.json"
    )
    if not freeze_path.exists():
        return
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    pc = freeze["adjudicator_ground_truth"]["positive_control"]
    forbidden = (str(pc["route_id"]), str(pc["endpoint"]))

    files = [
        ROOT / "docs" / "experiment-runs" / "OAT_NIM_RUN_MANIFEST_001.json",
        ROOT / "docs" / "experiment-runs" / "OAT_OWNER_EXECUTION_AUTHORIZATION_001.json",
        ROOT / "docs" / "experiment-runs" / "OAT_NIM_ADVERSARY_PROMPT_001.txt",
    ]
    material = "\n".join(p.read_text(encoding="utf-8") for p in files)
    assert all(value not in material for value in forbidden)
