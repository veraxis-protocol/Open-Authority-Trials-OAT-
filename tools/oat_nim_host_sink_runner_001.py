#!/usr/bin/env python3
"""Bounded NVIDIA NIM adversary runner for OAT host/sink experiment 001.

Control-plane runner only. It executes the frozen target commit from a git
archive, never imports the mutable control-plane checkout as the subject, and
never exposes repository/source contents or adjudicator-only ground truth to
the model.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

RUNNER_ID = "OAT-NIM-HOST-SINK-RUNNER-001"
RUNNER_VERSION = "1.0.0"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], *, cwd: Path | None = None, capture: bool = True) -> str:
    p = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=True,
        text=True,
        capture_output=capture,
    )
    return p.stdout.strip() if capture else ""


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected object: {path}")
    return data


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n")


def git_blob_sha(repo: Path, commit: str, path: str) -> str:
    return run(["git", "-C", str(repo), "rev-parse", f"{commit}:{path}"])


def verify_target(repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    target = manifest["target"]
    commit = target["commit"]
    expected_tree = target["tree"]
    observed_tree = run(["git", "-C", str(repo), "rev-parse", f"{commit}^{{tree}}"])
    if observed_tree != expected_tree:
        raise RuntimeError(
            f"target tree mismatch: expected {expected_tree}, observed {observed_tree}"
        )
    checked: list[dict[str, str]] = []
    for item in target["critical_files"]:
        observed = git_blob_sha(repo, commit, item["path"])
        expected = item["git_blob_sha"]
        if observed != expected:
            raise RuntimeError(
                f"blob mismatch for {item['path']}: expected {expected}, observed {observed}"
            )
        checked.append({"path": item["path"], "git_blob_sha": observed})
    return {"commit": commit, "tree": observed_tree, "critical_files": checked}


def verify_control_freeze(
    control_repo: Path, manifest: dict[str, Any]
) -> tuple[dict[str, Any], tuple[str, str]]:
    control = manifest["control_plane"]
    minimum_base = control["authorization_base_commit"]
    observed_head = run(["git", "-C", str(control_repo), "rev-parse", "origin/main"])
    ancestry = subprocess.run(
        ["git", "-C", str(control_repo), "merge-base", "--is-ancestor", minimum_base, observed_head]
    )
    if ancestry.returncode != 0:
        raise RuntimeError(
            f"control-plane main no longer descends from authorization base {minimum_base}: "
            f"{observed_head}"
        )
    freeze_path = control_repo / control["freeze_artifact_path"]
    observed_sha = sha256_file(freeze_path)
    if observed_sha != control["freeze_artifact_sha256"]:
        raise RuntimeError("freeze artifact SHA-256 mismatch")
    freeze = load_json(freeze_path)
    pc = freeze["adjudicator_ground_truth"]["positive_control"]
    hidden_route = str(pc["route_id"])
    hidden_endpoint = str(pc["endpoint"])
    if not pc.get("must_not_be_disclosed_to_adversary"):
        raise RuntimeError("freeze no longer marks positive control as non-disclosable")
    return (
        {
            "origin_main": observed_head,
            "authorization_base_is_ancestor": True,
            "freeze_sha256": observed_sha,
            "freeze_status": freeze["status"],
        },
        (hidden_route, hidden_endpoint),
    )


def extract_target(repo: Path, commit: str, dest: Path) -> None:
    archive = dest.parent / "target.tar"
    with archive.open("wb") as f:
        subprocess.run(["git", "-C", str(repo), "archive", commit], check=True, stdout=f)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tf:
        tf.extractall(dest)
    archive.unlink()


def validate_prompt_no_ground_truth(
    prompt: str, initial_context: dict[str, Any], forbidden: tuple[str, str]
) -> None:
    material = prompt + "\n" + json.dumps(initial_context, sort_keys=True)
    for value in forbidden:
        if value and value in material:
            raise RuntimeError("adjudicator-only ground truth leaked into adversary context")


def parse_action(text: str) -> dict[str, Any]:
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("model output must be a JSON object")
    action = obj.get("action")
    if action == "STOP":
        return obj
    if action != "REQUEST":
        raise ValueError("action must be REQUEST or STOP")
    if obj.get("method") != "POST":
        raise ValueError("only POST is permitted")
    path = obj.get("path")
    if not isinstance(path, str) or not path.startswith("/") or "://" in path or ".." in path:
        raise ValueError("invalid relative path")
    body = obj.get("json")
    if not isinstance(body, dict):
        raise ValueError("json must be an object")
    return obj


def provider_call(
    manifest: dict[str, Any], messages: list[dict[str, str]], api_key: str
) -> tuple[str, dict[str, Any]]:
    provider = manifest["provider"]
    params = manifest["sampling"]
    body = {
        "model": provider["model"],
        "messages": messages,
        "temperature": params["temperature"],
        "top_p": params["top_p"],
        "max_tokens": params["max_tokens"],
        "reasoning_effort": params["reasoning_effort"],
        "reasoning_budget": params["reasoning_budget"],
        "seed": params["seed"],
        "stream": False,
    }
    data = canonical_json(body)
    req = urllib.request.Request(
        provider["endpoint"],
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    timeout = float(manifest["timeouts"]["provider_call_seconds"])
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    response = json.loads(raw)
    msg = response["choices"][0]["message"]
    content = msg.get("content") or ""
    reasoning = msg.get("reasoning_content") or ""
    audit = {
        "http_status": 200,
        "model": response.get("model", provider["model"]),
        "usage": response.get("usage"),
        "finish_reason": response["choices"][0].get("finish_reason"),
        "final_content": content,
        "reasoning_content_sha256": sha256_bytes(reasoning.encode()) if reasoning else None,
        "reasoning_content_chars": len(reasoning),
        "reasoning_content_persisted": False,
        "response_sha256": sha256_bytes(raw),
    }
    return content, audit


def target_post(
    base_url: str, path: str, payload: dict[str, Any], timeout: float
) -> tuple[int, dict[str, Any] | str]:
    u = urlparse(base_url)
    if u.scheme != "http" or u.hostname != "127.0.0.1" or u.port is None:
        raise RuntimeError("target BASE_URL escaped loopback binding")
    conn = http.client.HTTPConnection("127.0.0.1", u.port, timeout=timeout)
    body = canonical_json(payload)
    try:
        conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        raw = resp.read()
        try:
            decoded: dict[str, Any] | str = json.loads(raw)
        except json.JSONDecodeError:
            decoded = raw.decode("utf-8", errors="replace")
        return int(resp.status), decoded
    finally:
        conn.close()


def write_sha256sums(root: Path) -> None:
    paths = [p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt"]
    lines = [f"{sha256_file(p)}  {p.relative_to(root).as_posix()}" for p in sorted(paths)]
    (root / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def secret_leak_audit(root: Path, secret: str) -> dict[str, Any]:
    leaks: list[str] = []
    if not secret:
        return {"credential_present": False, "secret_leak_scan": "NOT_RUN"}
    token = secret.encode()
    for p in root.rglob("*"):
        if p.is_file() and p.name not in {"ledger.sqlite3", "telemetry.sqlite3"}:
            try:
                if token in p.read_bytes():
                    leaks.append(p.relative_to(root).as_posix())
            except OSError:
                pass
    return {
        "credential_present": True,
        "secret_leak_scan": "PASS" if not leaks else "FAIL",
        "leaks": leaks,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, type=Path, help="local OAT git repository")
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("--prompt", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--preflight-only", action="store_true")
    args = ap.parse_args()

    manifest = load_json(args.manifest)
    prompt = args.prompt.read_text(encoding="utf-8")
    repo = args.repo.resolve()
    run_id = manifest["run_id"]
    out = (args.out or (repo / manifest["outputs"]["run_directory"])).resolve()

    if sha256_file(args.prompt) != manifest["adversary_context"]["prompt_sha256"]:
        raise RuntimeError("prompt SHA-256 mismatch")
    if sha256_file(Path(__file__)) != manifest["runner"]["sha256"]:
        raise RuntimeError("runner SHA-256 mismatch")

    run(["git", "-C", str(repo), "fetch", "origin", "--prune"], capture=True)
    target_check = verify_target(repo, manifest)
    control_check, forbidden = verify_control_freeze(repo, manifest)

    initial_context_template = manifest["adversary_context"]["initial_context_template"]
    validate_prompt_no_ground_truth(prompt, initial_context_template, forbidden)

    auth_env = manifest["credential_isolation"]["environment_variable"]
    api_key = os.environ.get(auth_env, "")
    auth_id_env = manifest["owner_execution_authorization"]["environment_variable"]
    supplied_auth_id = os.environ.get(auth_id_env, "")

    preflight = {
        "runner_id": RUNNER_ID,
        "runner_version": RUNNER_VERSION,
        "run_id": run_id,
        "target": target_check,
        "control_plane": control_check,
        "adversary_context_ground_truth_leak_check": "PASS",
        "credential_environment_variable": auth_env,
        "credential_present": bool(api_key),
        "owner_authorization_id_present": bool(supplied_auth_id),
        "owner_authorization_id_matches": supplied_auth_id
        == manifest["owner_execution_authorization"]["authorization_id"]
        if supplied_auth_id
        else False,
        "provider_call_performed": False,
    }

    if args.preflight_only:
        print(json.dumps(preflight, sort_keys=True, indent=2))
        return 0

    if not api_key:
        raise RuntimeError(f"missing provider credential in {auth_env}")
    if supplied_auth_id != manifest["owner_execution_authorization"]["authorization_id"]:
        raise RuntimeError(
            "explicit owner execution authorization environment binding missing or incorrect"
        )
    if out.exists():
        raise RuntimeError(
            f"run output already exists: {out}; one-run authorization forbids overwrite/retry"
        )
    out.mkdir(parents=True)
    write_json(out / "run-manifest.snapshot.json", manifest)

    started = time.monotonic()
    stop_reason = "UNSET"
    provider_calls = 0
    attempts = 0
    invalid_outputs = 0
    provider_errors = 0

    with tempfile.TemporaryDirectory(prefix="oat-nim-target-") as td:
        target_dir = Path(td) / "target"
        extract_target(repo, manifest["target"]["commit"], target_dir)
        sys.path.insert(0, str(target_dir))
        from oat.authority.authorization import token_digest  # type: ignore
        from oat.integration.host_sink import (  # type: ignore
            REFERENCE_ACTION,
            IntegrationServer,
            new_reference_integration,
        )

        state_dir = out / "target-state"
        host, auth = new_reference_integration(state_dir)
        try:
            with IntegrationServer(host) as server:
                safe_context = json.loads(json.dumps(initial_context_template))
                safe_context["base_url"] = server.base_url
                safe_context["reference_action"] = REFERENCE_ACTION
                safe_context["target_side_credential_capsule"] = {
                    "authorization_id": auth.authorization_id,
                    "token_digest": token_digest(auth),
                    "note": "target-side authorization artifact only; not a provider credential",
                }
                validate_prompt_no_ground_truth(prompt, safe_context, forbidden)

                messages: list[dict[str, str]] = [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": json.dumps(safe_context, sort_keys=True)},
                ]

                budgets = manifest["budgets"]
                timeouts = manifest["timeouts"]
                while True:
                    elapsed = time.monotonic() - started
                    if elapsed >= float(timeouts["run_wall_clock_seconds"]):
                        stop_reason = "RUN_WALL_CLOCK_TIMEOUT"
                        break
                    if provider_calls >= int(budgets["max_provider_calls"]):
                        stop_reason = "PROVIDER_CALL_BUDGET_EXHAUSTED"
                        break
                    if attempts >= int(budgets["max_target_http_attempts"]):
                        stop_reason = "TARGET_ATTEMPT_BUDGET_EXHAUSTED"
                        break
                    if invalid_outputs >= int(budgets["max_consecutive_invalid_model_outputs"]):
                        stop_reason = "INVALID_MODEL_OUTPUT_LIMIT"
                        break
                    if provider_errors >= int(budgets["max_provider_errors"]):
                        stop_reason = "PROVIDER_ERROR_LIMIT"
                        break

                    provider_calls += 1
                    try:
                        content, audit = provider_call(manifest, messages, api_key)
                    except Exception as e:
                        provider_errors += 1
                        append_jsonl(
                            out / "provider-transcript.jsonl",
                            {
                                "provider_call": provider_calls,
                                "error_type": type(e).__name__,
                                "error": str(e),
                            },
                        )
                        messages.append(
                            {
                                "role": "user",
                                "content": json.dumps({"provider_error": type(e).__name__}),
                            }
                        )
                        continue

                    append_jsonl(
                        out / "provider-transcript.jsonl",
                        {
                            "provider_call": provider_calls,
                            **audit,
                        },
                    )
                    try:
                        action = parse_action(content)
                    except Exception as e:
                        invalid_outputs += 1
                        messages.extend(
                            [
                                {"role": "assistant", "content": content},
                                {
                                    "role": "user",
                                    "content": json.dumps(
                                        {"observation": "INVALID_ACTION_JSON", "detail": str(e)}
                                    ),
                                },
                            ]
                        )
                        continue
                    invalid_outputs = 0
                    if action["action"] == "STOP":
                        stop_reason = "MODEL_VOLUNTARY_STOP"
                        break

                    attempts += 1
                    status: int
                    response: dict[str, Any] | str
                    try:
                        status, response = target_post(
                            server.base_url,
                            action["path"],
                            action["json"],
                            float(timeouts["target_request_seconds"]),
                        )
                    except Exception as e:
                        status = 0
                        response = {"transport_error": type(e).__name__, "detail": str(e)}

                    append_jsonl(
                        out / "http-attempts.jsonl",
                        {
                            "attempt": attempts,
                            "method": "POST",
                            "path": action["path"],
                            "request_json": action["json"],
                            "response_status": status,
                            "response_body": response,
                            "provider_call": provider_calls,
                        },
                    )

                    verdict = host.verdict().to_dict()
                    if verdict["disposition"] == "CONSEQUENCE_BOUNDARY_FAILURE":
                        stop_reason = "VERIFIER_CONFIRMED_CONSEQUENCE_BOUNDARY_FAILURE"
                        break

                    messages.extend(
                        [
                            {"role": "assistant", "content": content},
                            {
                                "role": "user",
                                "content": json.dumps(
                                    {
                                        "observation": {
                                            "attempt": attempts,
                                            "response_status": status,
                                            "response_body": response,
                                        },
                                        "instruction": (
                                            "Continue systematic bounded exploration or STOP."
                                        ),
                                    },
                                    sort_keys=True,
                                ),
                            },
                        ]
                    )

            verdict = host.verdict().to_dict()
            evidence = {
                "protected_sink": {
                    "sink_id": host.sink.sink_id,
                    "description": host.sink.description,
                },
                "commits": [c.to_dict() for c in host.ledger.commits()],
                "receipts": [r.to_dict() for r in host.observer.receipts()],
                "observed_paths": [o.to_dict() for o in host.observer.observed_paths()],
                "authority": host.authority.to_dict(),
                "authorizations": {k: v.to_dict() for k, v in host.authorizations.items()},
                "verdict": verdict,
            }
            write_json(out / "verdict.json", verdict)
            write_json(out / "evidence.json", evidence)
        finally:
            host.close()

    runtime = {
        **preflight,
        "provider_call_performed": provider_calls > 0,
        "provider_calls": provider_calls,
        "target_http_attempts": attempts,
        "stop_reason": stop_reason,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "reasoning_content_persisted": False,
        "claim_bearing_use": "PROHIBITED",
        "experiment_001_resumed": True,
        "run_mode": "METHOD_DEVELOPMENT_ONLY",
    }
    write_json(out / "runtime.json", runtime)
    leak_audit = secret_leak_audit(out, api_key)
    write_json(out / "credential-redaction-audit.json", leak_audit)
    if leak_audit.get("secret_leak_scan") != "PASS":
        raise RuntimeError("provider credential leaked into output artifacts")
    write_sha256sums(out)
    print(
        json.dumps(
            {
                "run_id": run_id,
                "out": str(out),
                "stop_reason": stop_reason,
                "provider_calls": provider_calls,
                "attempts": attempts,
                "verdict": json.loads((out / "verdict.json").read_text())["disposition"],
                "credential_redaction": "PASS",
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
