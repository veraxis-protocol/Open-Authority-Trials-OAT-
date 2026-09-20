#!/usr/bin/env python3
"""Bounded NVIDIA NIM adversary runner for OAT host/sink Run B.

This control-plane runner preserves the frozen target and adversary context,
reuses the previously successful NVIDIA streaming request envelope, and fails
closed when the boundary was not actually exercised.
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
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

RUNNER_ID = "OAT-NIM-HOST-SINK-RUNNER-002"
RUNNER_VERSION = "2.0.0"
PROVEN_REQUEST_SHA256 = "a53b49c201b689cfcabb7b2628ada8f56d892ce1b42604dfc4f064270fa8e61c"
PROVIDER_RETRY_DELAYS_SECONDS = (1, 2)
ALLOWED_PROVIDER_HEADERS = frozenset(
    {"content-type", "date", "nvcf-reqid", "nvcf-status", "x-request-id"}
)


class ProviderTransportError(RuntimeError):
    def __init__(self, record: dict[str, Any]) -> None:
        super().__init__(str(record["classification"]))
        self.record = record


class ProviderTerminalError(RuntimeError):
    pass


class ProviderBudgetStop(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


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
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
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
    control_repo: Path,
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], tuple[str, str]]:
    control = manifest["control_plane"]
    minimum_base = control["authorization_base_commit"]
    observed_head = run(["git", "-C", str(control_repo), "rev-parse", "origin/main"])
    ancestry = subprocess.run(
        [
            "git",
            "-C",
            str(control_repo),
            "merge-base",
            "--is-ancestor",
            minimum_base,
            observed_head,
        ]
    )
    if ancestry.returncode != 0:
        raise RuntimeError(
            "control-plane main no longer descends from authorization base "
            f"{minimum_base}: {observed_head}"
        )
    freeze_path = control_repo / control["freeze_artifact_path"]
    observed_sha = sha256_file(freeze_path)
    if observed_sha != control["freeze_artifact_sha256"]:
        raise RuntimeError("freeze artifact SHA-256 mismatch")
    freeze = load_json(freeze_path)
    if freeze["status"] != control["freeze_status_required"]:
        raise RuntimeError("freeze status mismatch")
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
        subprocess.run(
            ["git", "-C", str(repo), "archive", commit],
            check=True,
            stdout=f,
        )
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tf:
        tf.extractall(dest)
    archive.unlink()


def validate_prompt_no_ground_truth(
    prompt: str,
    initial_context: dict[str, Any],
    forbidden: tuple[str, str],
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


def provider_request_body(
    manifest: dict[str, Any],
    messages: list[dict[str, str]],
) -> dict[str, Any]:
    provider = manifest["provider"]
    params = manifest["sampling"]
    return {
        "max_tokens": params["max_tokens"],
        "messages": messages,
        "model": provider["model"],
        "seed": params["seed"],
        "stream": True,
        "temperature": params["temperature"],
        "top_p": params["top_p"],
    }


def _allowed_provider_headers(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    return {
        str(k).lower(): str(v)
        for k, v in headers.items()
        if str(k).lower() in ALLOWED_PROVIDER_HEADERS
    }


def _data_payloads(raw: bytes) -> list[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("MALFORMED_SSE") from exc
    payloads: list[str] = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        data_lines = [line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")]
        if data_lines:
            payloads.append("\n".join(data_lines))
    return payloads


def _read_sse_until_done(response: Any, raw: bytearray) -> bool:
    readline = getattr(response, "readline", None)
    if not callable(readline):
        raw.extend(response.read())
        try:
            return "[DONE]" in _data_payloads(bytes(raw))
        except ValueError:
            return False

    event_data: list[bytes] = []
    while True:
        line = readline()
        if line == b"":
            return False
        raw.extend(line)
        normalized = line.rstrip(b"\r\n")
        if normalized:
            if normalized.startswith(b"data:"):
                event_data.append(normalized[5:].lstrip())
            continue
        if event_data and b"\n".join(event_data) == b"[DONE]":
            return True
        event_data = []


def reconstruct_sse(raw: bytes) -> tuple[str, str, bool]:
    content: list[str] = []
    model = ""
    done = False
    for data in _data_payloads(raw):
        if data == "[DONE]":
            done = True
            continue
        try:
            event = json.loads(data)
            if not isinstance(event, dict):
                raise ValueError
            model = str(event.get("model", model))
            choices = event.get("choices")
            if not isinstance(choices, list):
                raise ValueError
            for choice in choices:
                if not isinstance(choice, dict):
                    raise ValueError
                delta = choice.get("delta", {})
                if not isinstance(delta, dict):
                    raise ValueError
                value = delta.get("content")
                if isinstance(value, str):
                    content.append(value)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("MALFORMED_SSE") from exc
    return "".join(content), model, done


def _provider_sse_error(raw: bytes) -> dict[str, Any] | None:
    try:
        payloads = _data_payloads(raw)
    except ValueError:
        return None
    for data in payloads:
        if data == "[DONE]":
            continue
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or "error" not in event:
            continue
        error = event["error"]
        return error if isinstance(error, dict) else {"type": "unknown_provider_error"}
    return None


def _safe_http_error(raw: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    error = value.get("error")
    return error if isinstance(error, dict) else None


def _transport_error_record(
    *,
    classification: str,
    retryable: bool,
    request_sha256: str,
    started: float,
    http_status: int | None = None,
    response_headers: dict[str, str] | None = None,
    raw: bytes = b"",
    provider_error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "classification": classification,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "http_status": http_status,
        "provider_error": provider_error,
        "request_sha256": request_sha256,
        "response_bytes": len(raw),
        "response_headers": response_headers or {},
        "response_sha256": sha256_bytes(raw),
        "retryable": retryable,
    }


def provider_call_once(
    manifest: dict[str, Any],
    messages: list[dict[str, str]],
    api_key: str,
) -> tuple[str, dict[str, Any]]:
    body = provider_request_body(manifest, messages)
    data = canonical_json(body)
    request_sha256 = sha256_bytes(data)
    started = time.monotonic()
    req = urllib.request.Request(
        manifest["provider"]["endpoint"],
        data=data,
        method="POST",
        headers={
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    timeout = float(manifest["timeouts"]["provider_call_seconds"])
    raw_buffer = bytearray()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = int(response.status)
            headers = _allowed_provider_headers(response.headers)
            done = _read_sse_until_done(response, raw_buffer)
    except urllib.error.HTTPError as exc:
        try:
            raw = bytes(exc.read())
        except Exception:
            raw = b""
        status = int(exc.code)
        retryable = status == 429 or status >= 500
        classification = "HTTP_RETRYABLE" if retryable else "HTTP_4XX_FATAL_FOR_RUN"
        raise ProviderTransportError(
            _transport_error_record(
                classification=classification,
                retryable=retryable,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=_allowed_provider_headers(exc.headers),
                raw=raw,
                provider_error=_safe_http_error(raw),
            )
        ) from None
    except TimeoutError:
        raise ProviderTransportError(
            _transport_error_record(
                classification="TIMEOUT",
                retryable=True,
                request_sha256=request_sha256,
                started=started,
            )
        ) from None
    except OSError:
        raise ProviderTransportError(
            _transport_error_record(
                classification="CONNECT_FAILURE",
                retryable=True,
                request_sha256=request_sha256,
                started=started,
            )
        ) from None

    raw = bytes(raw_buffer)
    provider_error = _provider_sse_error(raw)
    if provider_error is not None:
        code = provider_error.get("code")
        retryable = isinstance(code, int) and (code == 429 or 500 <= code < 600)
        classification = "PROVIDER_SSE_RETRYABLE_ERROR" if retryable else "PROVIDER_SSE_FATAL_ERROR"
        raise ProviderTransportError(
            _transport_error_record(
                classification=classification,
                retryable=retryable,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=headers,
                raw=raw,
                provider_error=provider_error,
            )
        )
    if not done:
        raise ProviderTransportError(
            _transport_error_record(
                classification="STREAM_INCOMPLETE",
                retryable=True,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=headers,
                raw=raw,
            )
        )
    try:
        content, returned_model, reconstructed_done = reconstruct_sse(raw)
    except ValueError:
        raise ProviderTransportError(
            _transport_error_record(
                classification="MALFORMED_SSE",
                retryable=True,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=headers,
                raw=raw,
            )
        ) from None
    if not reconstructed_done:
        raise ProviderTransportError(
            _transport_error_record(
                classification="STREAM_INCOMPLETE",
                retryable=True,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=headers,
                raw=raw,
            )
        )
    audit = {
        "done_seen": True,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "final_content": content,
        "http_status": status,
        "model": returned_model or manifest["provider"]["model"],
        "reasoning_content_persisted": False,
        "request_sha256": request_sha256,
        "response_headers": headers,
        "response_sha256": sha256_bytes(raw),
        "transport_classification": "SUCCESSFUL_MODEL_RESPONSE",
    }
    return content, audit


def provider_call_with_retries(
    manifest: dict[str, Any],
    messages: list[dict[str, str]],
    api_key: str,
    provider_state: dict[str, Any],
    started: float,
) -> tuple[str, dict[str, Any]]:
    budgets = manifest["budgets"]
    timeouts = manifest["timeouts"]
    delays = (*PROVIDER_RETRY_DELAYS_SECONDS, 0)
    for retry_ordinal, delay in enumerate(delays):
        if time.monotonic() - started >= float(timeouts["run_wall_clock_seconds"]):
            raise ProviderBudgetStop("RUN_WALL_CLOCK_TIMEOUT")
        if provider_state["calls"] >= int(budgets["max_provider_calls"]):
            raise ProviderBudgetStop("PROVIDER_CALL_BUDGET_EXHAUSTED")
        provider_state["calls"] += 1
        provider_call = provider_state["calls"]
        try:
            content, audit = provider_call_once(manifest, messages, api_key)
        except ProviderTransportError as exc:
            record = {
                **exc.record,
                "event": "provider_transport_failure",
                "provider_call": provider_call,
                "retry_ordinal": retry_ordinal,
            }
            provider_state["failures"].append(record)
            if not bool(exc.record["retryable"]) or retry_ordinal == len(delays) - 1:
                raise ProviderTerminalError(str(exc)) from None
            time.sleep(delay)
            continue
        audit.update(
            {
                "event": "provider_success",
                "provider_call": provider_call,
                "retry_ordinal": retry_ordinal,
            }
        )
        return content, audit
    raise AssertionError("unreachable")


def target_post(
    base_url: str,
    path: str,
    payload: dict[str, Any],
    timeout: float,
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


def fail_closed_verdict(
    subject_verdict: dict[str, Any],
    *,
    attempts: int,
    terminal_provider_failure: bool,
) -> dict[str, Any]:
    path_reconciliation = subject_verdict.get("path_reconciliation", {})
    observed = path_reconciliation.get("observed_path_set", [])
    reasons: list[str] = []
    if terminal_provider_failure:
        reasons.append("terminal provider or transport failure")
    if attempts == 0:
        reasons.append("zero target HTTP attempts")
    if not observed:
        reasons.append("zero exercised consequence paths")
    if reasons:
        return {
            "disposition": "HARNESS_OR_INSTRUMENT_FAILURE",
            "instrument_status": "NOT_EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT",
            "reason": "; ".join(reasons),
            "subject_result": "NOT_ESTABLISHED",
            "subject_verifier_disposition": subject_verdict.get("disposition"),
            "subject_verifier_verdict": subject_verdict,
        }
    verdict = dict(subject_verdict)
    verdict["instrument_status"] = "EXECUTED"
    verdict["subject_result"] = "ESTABLISHED_WITHIN_EXERCISED_SCOPE"
    return verdict


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
        "leaks": leaks,
        "secret_leak_scan": "PASS" if not leaks else "FAIL",
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
        "adversary_context_ground_truth_leak_check": "PASS",
        "control_plane": control_check,
        "credential_environment_variable": auth_env,
        "credential_present": bool(api_key),
        "owner_authorization_id_matches": supplied_auth_id
        == manifest["owner_execution_authorization"]["authorization_id"]
        if supplied_auth_id
        else False,
        "owner_authorization_id_present": bool(supplied_auth_id),
        "provider_call_performed": False,
        "run_id": run_id,
        "runner_id": RUNNER_ID,
        "runner_version": RUNNER_VERSION,
        "target": target_check,
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
    (out / "provider-transcript.jsonl").touch()
    (out / "http-attempts.jsonl").touch()

    started = time.monotonic()
    stop_reason = "UNSET"
    attempts = 0
    invalid_outputs = 0
    terminal_provider_failure = False
    provider_state: dict[str, Any] = {"calls": 0, "failures": []}

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
                    "note": "target-side authorization artifact only; not a provider credential",
                    "token_digest": token_digest(auth),
                }
                validate_prompt_no_ground_truth(prompt, safe_context, forbidden)

                messages: list[dict[str, str]] = [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": json.dumps(safe_context, sort_keys=True)},
                ]

                budgets = manifest["budgets"]
                timeouts = manifest["timeouts"]
                logical_turn = 0
                while True:
                    elapsed = time.monotonic() - started
                    if elapsed >= float(timeouts["run_wall_clock_seconds"]):
                        stop_reason = "RUN_WALL_CLOCK_TIMEOUT"
                        break
                    if provider_state["calls"] >= int(budgets["max_provider_calls"]):
                        stop_reason = "PROVIDER_CALL_BUDGET_EXHAUSTED"
                        break
                    if attempts >= int(budgets["max_target_http_attempts"]):
                        stop_reason = "TARGET_ATTEMPT_BUDGET_EXHAUSTED"
                        break
                    if invalid_outputs >= int(budgets["max_consecutive_invalid_model_outputs"]):
                        stop_reason = "INVALID_MODEL_OUTPUT_LIMIT"
                        break

                    logical_turn += 1
                    failure_start = len(provider_state["failures"])
                    try:
                        content, audit = provider_call_with_retries(
                            manifest,
                            messages,
                            api_key,
                            provider_state,
                            started,
                        )
                    except ProviderBudgetStop as exc:
                        new_failures = provider_state["failures"][failure_start:]
                        for record in new_failures:
                            append_jsonl(
                                out / "provider-transcript.jsonl",
                                {**record, "logical_turn": logical_turn},
                            )
                        if new_failures:
                            terminal_provider_failure = True
                        stop_reason = str(exc)
                        break
                    except ProviderTerminalError:
                        new_failures = provider_state["failures"][failure_start:]
                        for record in new_failures:
                            append_jsonl(
                                out / "provider-transcript.jsonl",
                                {**record, "logical_turn": logical_turn},
                            )
                        terminal_provider_failure = True
                        stop_reason = "PROVIDER_TRANSPORT_FAILURE"
                        break

                    for record in provider_state["failures"][failure_start:]:
                        append_jsonl(
                            out / "provider-transcript.jsonl",
                            {**record, "logical_turn": logical_turn},
                        )
                    append_jsonl(
                        out / "provider-transcript.jsonl",
                        {**audit, "logical_turn": logical_turn},
                    )

                    try:
                        action = parse_action(content)
                    except Exception as exc:
                        invalid_outputs += 1
                        messages.extend(
                            [
                                {"role": "assistant", "content": content},
                                {
                                    "role": "user",
                                    "content": json.dumps(
                                        {
                                            "detail": str(exc),
                                            "observation": "INVALID_ACTION_JSON",
                                        }
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
                    except Exception as exc:
                        status = 0
                        response = {
                            "detail": str(exc),
                            "transport_error": type(exc).__name__,
                        }

                    append_jsonl(
                        out / "http-attempts.jsonl",
                        {
                            "attempt": attempts,
                            "method": "POST",
                            "path": action["path"],
                            "provider_call": provider_state["calls"],
                            "request_json": action["json"],
                            "response_body": response,
                            "response_status": status,
                        },
                    )

                    subject_verdict = host.verdict().to_dict()
                    if subject_verdict["disposition"] == "CONSEQUENCE_BOUNDARY_FAILURE":
                        stop_reason = "VERIFIER_CONFIRMED_CONSEQUENCE_BOUNDARY_FAILURE"
                        break

                    messages.extend(
                        [
                            {"role": "assistant", "content": content},
                            {
                                "role": "user",
                                "content": json.dumps(
                                    {
                                        "instruction": (
                                            "Continue systematic bounded exploration or STOP."
                                        ),
                                        "observation": {
                                            "attempt": attempts,
                                            "response_body": response,
                                            "response_status": status,
                                        },
                                    },
                                    sort_keys=True,
                                ),
                            },
                        ]
                    )

            subject_verdict = host.verdict().to_dict()
            verdict = fail_closed_verdict(
                subject_verdict,
                attempts=attempts,
                terminal_provider_failure=terminal_provider_failure,
            )
            evidence = {
                "authority": host.authority.to_dict(),
                "authorizations": {k: v.to_dict() for k, v in host.authorizations.items()},
                "commits": [c.to_dict() for c in host.ledger.commits()],
                "observed_paths": [o.to_dict() for o in host.observer.observed_paths()],
                "protected_sink": {
                    "description": host.sink.description,
                    "sink_id": host.sink.sink_id,
                },
                "receipts": [r.to_dict() for r in host.observer.receipts()],
                "subject_verifier_verdict": subject_verdict,
                "verdict": verdict,
            }
            write_json(out / "verdict.json", verdict)
            write_json(out / "evidence.json", evidence)
        finally:
            host.close()

    runtime = {
        **preflight,
        "claim_bearing_use": "PROHIBITED",
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "experiment_001_resumed": provider_state["calls"] > 0,
        "instrument_status": verdict.get("instrument_status"),
        "provider_call_performed": provider_state["calls"] > 0,
        "provider_calls": provider_state["calls"],
        "provider_transport_failures": len(provider_state["failures"]),
        "reasoning_content_persisted": False,
        "run_mode": "METHOD_DEVELOPMENT_ONLY",
        "stop_reason": stop_reason,
        "subject_result": verdict.get("subject_result"),
        "target_http_attempts": attempts,
    }
    write_json(out / "runtime.json", runtime)
    leak_audit = secret_leak_audit(out, api_key)
    write_json(out / "credential-redaction-audit.json", leak_audit)
    if leak_audit.get("secret_leak_scan") != "PASS":
        subject_verdict = evidence["subject_verifier_verdict"]
        verdict = fail_closed_verdict(
            subject_verdict,
            attempts=0,
            terminal_provider_failure=True,
        )
        verdict["reason"] = "provider credential redaction audit failed"
        verdict["subject_result"] = "NOT_ESTABLISHED"
        evidence["verdict"] = verdict
        write_json(out / "verdict.json", verdict)
        write_json(out / "evidence.json", evidence)
        runtime["instrument_status"] = verdict["instrument_status"]
        runtime["subject_result"] = "NOT_ESTABLISHED"
        write_json(out / "runtime.json", runtime)
        write_sha256sums(out)
        raise RuntimeError("provider credential leaked into output artifacts")

    write_sha256sums(out)
    print(
        json.dumps(
            {
                "attempts": attempts,
                "credential_redaction": "PASS",
                "out": str(out),
                "provider_calls": provider_state["calls"],
                "run_id": run_id,
                "stop_reason": stop_reason,
                "subject_result": verdict.get("subject_result"),
                "verdict": verdict["disposition"],
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
