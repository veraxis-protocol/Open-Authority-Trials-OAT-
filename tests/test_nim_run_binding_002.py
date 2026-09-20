from __future__ import annotations

import hashlib
import importlib.util
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
    return Path(__file__).resolve().parent.joinpath(*parts[-1:])


def _load_runner():
    path = _repo_file("tools", "oat_nim_host_sink_runner_002.py")
    spec = importlib.util.spec_from_file_location("oat_nim_runner_002_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bound_manifest_prompt_runner_and_authorization() -> None:
    manifest_path = _repo_file(
        "docs",
        "experiment-runs",
        "OAT_NIM_RUN_MANIFEST_002.json",
    )
    auth_path = _repo_file(
        "docs",
        "experiment-runs",
        "OAT_OWNER_EXECUTION_AUTHORIZATION_002.json",
    )
    prompt_path = _repo_file(
        "docs",
        "experiment-runs",
        "OAT_NIM_ADVERSARY_PROMPT_001.txt",
    )
    runner_path = _repo_file("tools", "oat_nim_host_sink_runner_002.py")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    auth = json.loads(auth_path.read_text(encoding="utf-8"))

    assert manifest["run_id"] == "OAT-NIM-HOST-SINK-001-20260920-B"
    assert manifest["provider"]["provider"] == "NVIDIA NIM API"
    assert manifest["provider"]["model"] == "nvidia/nemotron-3-ultra-550b-a55b"
    assert manifest["sampling"] == {
        "api_stop": None,
        "max_tokens": 4096,
        "n": 1,
        "reasoning_budget": "NOT_SENT",
        "reasoning_effort": "NOT_SENT",
        "seed": 20260915,
        "stream": True,
        "temperature": 0.0,
        "top_p": 1.0,
    }
    assert manifest["owner_execution_authorization"]["authorization_id"] == auth["artifact_id"]
    assert auth["authorized_run_count"] == 1
    assert auth["predecessor_authorization_reuse"].startswith("PROHIBITED")
    assert auth["run_manifest"]["sha256"] == _sha(manifest_path)
    assert manifest["adversary_context"]["prompt_sha256"] == _sha(prompt_path)
    assert manifest["runner"]["sha256"] == _sha(runner_path)


def test_proven_request_envelope_is_exactly_reused() -> None:
    manifest_path = _repo_file(
        "docs",
        "experiment-runs",
        "OAT_NIM_RUN_MANIFEST_002.json",
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    runner = _load_runner()
    messages = [
        {
            "content": "Return exactly OAT_TRANSPORT_REACHABLE.",
            "role": "user",
        }
    ]
    body = runner.provider_request_body(manifest, messages)
    assert "reasoning_effort" not in body
    assert "reasoning_budget" not in body
    assert "chat_template_kwargs" not in body
    assert runner.sha256_bytes(runner.canonical_json(body)) == runner.PROVEN_REQUEST_SHA256


def test_sse_reconstruction_reuses_done_terminated_content_semantics() -> None:
    runner = _load_runner()
    event = {
        "choices": [{"delta": {"content": '{"action":"STOP","reason":"done"}'}}],
        "model": "nvidia/nemotron-3-ultra-550b-a55b",
    }
    raw = (
        b"data: "
        + json.dumps(event, separators=(",", ":")).encode()
        + b"\n\n"
        + b"data: [DONE]\n\n"
    )
    content, model, done = runner.reconstruct_sse(raw)
    assert done is True
    assert model == "nvidia/nemotron-3-ultra-550b-a55b"
    assert content == '{"action":"STOP","reason":"done"}'


def test_fail_closed_when_boundary_was_not_exercised() -> None:
    runner = _load_runner()
    subject = {
        "disposition": "NO_BOUNDARY_COUNTEREXAMPLE",
        "path_reconciliation": {"observed_path_set": []},
    }
    verdict = runner.fail_closed_verdict(
        subject,
        attempts=0,
        terminal_provider_failure=False,
    )
    assert verdict["disposition"] == "HARNESS_OR_INSTRUMENT_FAILURE"
    assert verdict["subject_result"] == "NOT_ESTABLISHED"
    assert verdict["subject_verifier_disposition"] == "NO_BOUNDARY_COUNTEREXAMPLE"


def test_exercised_subject_verdict_remains_scoped_subject_result() -> None:
    runner = _load_runner()
    subject = {
        "disposition": "NO_BOUNDARY_COUNTEREXAMPLE",
        "path_reconciliation": {"observed_path_set": ["route.example"]},
    }
    verdict = runner.fail_closed_verdict(
        subject,
        attempts=1,
        terminal_provider_failure=False,
    )
    assert verdict["disposition"] == "NO_BOUNDARY_COUNTEREXAMPLE"
    assert verdict["subject_result"] == "ESTABLISHED_WITHIN_EXERCISED_SCOPE"
