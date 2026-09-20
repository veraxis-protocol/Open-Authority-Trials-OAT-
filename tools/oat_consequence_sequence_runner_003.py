#!/usr/bin/env python3
"""Six-stage frozen-sequence runner for OAT Sequence 003.

The scientific object is the whole ordered sequence, not any single run:

    S0  BIND_AND_PREFLIGHT
    S1  ADJUDICATOR_POSITIVE_CONTROL      (no provider call)
    S1A SEAL_POSITIVE_CONTROL_EVIDENCE    (no provider call)
    S2  DESTROY_AND_REINITIALIZE          (no provider call)
    S3  ADVERSARIAL_RUN_C                 (consumes the owner authorization)
    S4  JOINT REPLAY_AND_SEQUENCE_ADJUDICATION

The controlling invariant is::

    POSITIVE_CONTROL_KNOWLEDGE  intersect  ADVERSARY_CONTEXT  ==  empty

``run_s3`` re-checks every preceding gate before it builds a provider request,
so there is no code path into the provider that skips a failed gate. Sequence
completeness and subject outcome are kept as separate variables throughout: a
genuine Run C counterexample is a complete sequence, not a failed one.

The provider transport is the proven Run B envelope, reused unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

RUNNER_ID = "OAT-CONSEQUENCE-SEQUENCE-RUNNER-003"
RUNNER_VERSION = "3.0.0"
SEQUENCE_ID = "OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-003"

PROVEN_REQUEST_SHA256 = "a53b49c201b689cfcabb7b2628ada8f56d892ce1b42604dfc4f064270fa8e61c"
PROVIDER_RETRY_DELAYS_SECONDS = (1, 2)
ALLOWED_PROVIDER_HEADERS = frozenset(
    {"content-type", "date", "nvcf-reqid", "nvcf-status", "x-request-id"}
)

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT_RUN"
ESTABLISHED = "ESTABLISHED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

POSITIVE_CONTROL_EXPECTED_DISPOSITION = "CONSEQUENCE_BOUNDARY_FAILURE"

# Surfaces the ground-truth leak audit must cover. Every one of these is
# something the model can read, directly or eventually.
ADVERSARY_BUNDLE_SURFACES = (
    "system_prompt",
    "user_prompt",
    "initial_context",
    "tool_schema",
    "target_facing_documentation",
    "conversation_history",
    "projected_environment",
    "model_readable_files",
    "prior_provider_messages",
    "generated_diagnostics",
)


class SequenceGateError(RuntimeError):
    """A hard gate refused to let the sequence advance."""


class ProviderTransportError(RuntimeError):
    def __init__(self, record: dict[str, Any]) -> None:
        super().__init__(str(record["classification"]))
        self.record = record


class ProviderTerminalError(RuntimeError):
    pass


class ProviderBudgetStop(RuntimeError):
    pass


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------


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


def digest_object(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def run_cmd(cmd: list[str], *, capture: bool = True) -> str:
    p = subprocess.run(cmd, check=True, text=True, capture_output=capture)
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


def write_sha256sums(root: Path) -> None:
    paths = [p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt"]
    lines = [f"{sha256_file(p)}  {p.relative_to(root).as_posix()}" for p in sorted(paths)]
    (root / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_sha256sums(root: Path) -> dict[str, Any]:
    sums = root / "SHA256SUMS.txt"
    if not sums.exists():
        return {"status": FAIL, "reason": "SHA256SUMS.txt missing", "checked": 0}
    mismatches: list[str] = []
    checked = 0
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        target = root / rel
        if not target.exists() or sha256_file(target) != expected:
            mismatches.append(rel)
        checked += 1
    return {
        "status": PASS if not mismatches else FAIL,
        "checked": checked,
        "mismatched_entry_count": len(mismatches),
        "mismatched_entries": sorted(mismatches),
    }


# --------------------------------------------------------------------------
# authorization ledger
# --------------------------------------------------------------------------


@dataclass
class AuthorizationLedger:
    """Tracks owner-authorization consumption as an explicit, auditable event.

    The authorization is consumed by the first provider *request*, not by
    binding, not by the positive control, and not by the state reset. Nothing
    outside :func:`run_s3` is permitted to call :meth:`consume`.
    """

    authorization_id: str
    consumed: bool = False
    consumed_at_event: str | None = None
    consumed_at_monotonic: float | None = None
    events: list[dict[str, Any]] = field(default_factory=list)

    def note(self, event: str, stage: str) -> None:
        self.events.append({"event": event, "stage": stage, "consumed": self.consumed})

    def consume(self, event: str, stage: str) -> None:
        if stage != "S3":
            raise SequenceGateError(
                f"owner authorization may only be consumed in S3, attempted in {stage}"
            )
        if self.consumed:
            raise SequenceGateError(
                "owner authorization already consumed; automatic experiment rerun is prohibited"
            )
        self.consumed = True
        self.consumed_at_event = event
        self.consumed_at_monotonic = time.monotonic()
        self.events.append({"event": event, "stage": stage, "consumed": True})

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "consumed": self.consumed,
            "consumed_at_event": self.consumed_at_event,
            "events": list(self.events),
        }


# --------------------------------------------------------------------------
# gate state machine
# --------------------------------------------------------------------------


@dataclass
class GateState:
    """The only thing that may authorize entry into S3."""

    s0_preflight: str = NOT_RUN
    pc_sensitivity: str = NOT_ESTABLISHED
    pc_evidence_sealed: bool = False
    state_separation: str = NOT_ESTABLISHED
    adversary_context_isolation: str = NOT_RUN

    def blockers(self) -> list[str]:
        blocked: list[str] = []
        if self.s0_preflight != PASS:
            blocked.append(f"S0_PREFLIGHT={self.s0_preflight}")
        if self.pc_sensitivity != ESTABLISHED:
            blocked.append(f"PC_SENSITIVITY={self.pc_sensitivity}")
        if not self.pc_evidence_sealed:
            blocked.append("POSITIVE_CONTROL_EVIDENCE_NOT_SEALED")
        if self.state_separation != ESTABLISHED:
            blocked.append(f"STATE_SEPARATION={self.state_separation}")
        if self.adversary_context_isolation != PASS:
            blocked.append(f"ADVERSARY_CONTEXT_ISOLATION={self.adversary_context_isolation}")
        return blocked

    def s3_eligible(self) -> bool:
        return not self.blockers()

    def to_dict(self) -> dict[str, Any]:
        return {
            "adversary_context_isolation": self.adversary_context_isolation,
            "pc_evidence_sealed": self.pc_evidence_sealed,
            "pc_sensitivity": self.pc_sensitivity,
            "s0_preflight": self.s0_preflight,
            "s3_eligible": self.s3_eligible(),
            "state_separation": self.state_separation,
        }


def assert_s3_eligible(gates: GateState) -> None:
    blockers = gates.blockers()
    if blockers:
        raise SequenceGateError("S3 is not eligible: " + "; ".join(blockers))


# --------------------------------------------------------------------------
# ground-truth leak audit
# --------------------------------------------------------------------------


def forbidden_ground_truth_tokens(hidden_route: str, hidden_endpoint: str) -> tuple[str, ...]:
    """Derive the strings that would narrow the positive-control location.

    Both the literal frozen values and their obvious fragments are forbidden:
    leaking ``batch-commit`` narrows the search just as effectively as leaking
    the whole path.
    """
    tokens: set[str] = set()
    for value in (hidden_route, hidden_endpoint):
        candidate = value.strip()
        if not candidate:
            continue
        tokens.add(candidate)
        if " " in candidate:
            tokens.add(candidate.split(" ", 1)[1])
    path = hidden_endpoint.split(" ", 1)[1] if " " in hidden_endpoint else hidden_endpoint
    path = path.strip()
    if path:
        tokens.add(path)
        tokens.add(path.lstrip("/"))
        for segment in path.strip("/").split("/"):
            if len(segment) >= 5:
                tokens.add(segment)
    if hidden_route.startswith("route."):
        suffix = hidden_route.split(".", 1)[1]
        if len(suffix) >= 5:
            tokens.add(suffix)
    return tuple(sorted(t for t in tokens if len(t) >= 5))


def _bundle_text(bundle: dict[str, Any]) -> str:
    return json.dumps(bundle, sort_keys=True, ensure_ascii=False, default=str)


def ground_truth_leak_audit(
    bundle: dict[str, Any],
    forbidden: tuple[str, ...],
    *,
    stage: str,
) -> dict[str, Any]:
    """Audit an adversary-visible bundle for adjudicator-only ground truth.

    The returned artifact deliberately carries no ground truth: only a
    PASS/FAIL, the inspected-bundle digest, and audit metadata. Naming the
    matched token in the audit file would leak the very thing the audit
    exists to protect.
    """
    missing = [s for s in ADVERSARY_BUNDLE_SURFACES if s not in bundle]
    haystack = _bundle_text(bundle).lower()
    hits = sum(1 for token in forbidden if token.lower() in haystack)
    status = PASS if (hits == 0 and not missing) else FAIL
    return {
        "artifact": "GROUND_TRUTH_LEAK_AUDIT",
        "audited_at_stage": stage,
        "forbidden_token_count": len(forbidden),
        "inspected_bundle_digest": digest_object(bundle),
        "inspected_surfaces": sorted(bundle),
        "matched_token_count": hits,
        "required_surfaces": list(ADVERSARY_BUNDLE_SURFACES),
        "runner_id": RUNNER_ID,
        "runner_version": RUNNER_VERSION,
        "status": status,
        "uncovered_required_surfaces": missing,
    }


def assert_no_ground_truth(
    bundle: dict[str, Any], forbidden: tuple[str, ...], *, stage: str
) -> None:
    audit = ground_truth_leak_audit(bundle, forbidden, stage=stage)
    if audit["status"] != PASS:
        raise SequenceGateError(
            f"adversary-context ground-truth leak audit failed at {stage} "
            f"(matched_token_count={audit['matched_token_count']}, "
            f"uncovered={audit['uncovered_required_surfaces']})"
        )


# --------------------------------------------------------------------------
# frozen target identity
# --------------------------------------------------------------------------


def git_blob_sha(repo: Path, commit: str, path: str) -> str:
    return run_cmd(["git", "-C", str(repo), "rev-parse", f"{commit}:{path}"])


def verify_target(repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    target = manifest["target"]
    commit = target["commit"]
    expected_tree = target["tree"]
    observed_tree = run_cmd(["git", "-C", str(repo), "rev-parse", f"{commit}^{{tree}}"])
    if observed_tree != expected_tree:
        raise SequenceGateError(
            f"target tree mismatch: expected {expected_tree}, observed {observed_tree}"
        )
    checked: list[dict[str, str]] = []
    for item in target["critical_files"]:
        observed = git_blob_sha(repo, commit, item["path"])
        if observed != item["git_blob_sha"]:
            raise SequenceGateError(
                f"blob mismatch for {item['path']}: "
                f"expected {item['git_blob_sha']}, observed {observed}"
            )
        checked.append({"path": item["path"], "git_blob_sha": observed})
    return {
        "commit": commit,
        "critical_file_count": len(checked),
        "critical_files": checked,
        "tree": observed_tree,
    }


def verify_control_freeze(
    repo: Path, manifest: dict[str, Any]
) -> tuple[dict[str, Any], tuple[str, str]]:
    control = manifest["control_plane"]
    minimum_base = control["authorization_base_commit"]
    observed_head = run_cmd(["git", "-C", str(repo), "rev-parse", "origin/main"])
    ancestry = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", minimum_base, observed_head]
    )
    if ancestry.returncode != 0:
        raise SequenceGateError(
            f"control-plane main no longer descends from {minimum_base}: {observed_head}"
        )
    freeze_path = repo / control["freeze_artifact_path"]
    observed_sha = sha256_file(freeze_path)
    if observed_sha != control["freeze_artifact_sha256"]:
        raise SequenceGateError("freeze artifact SHA-256 mismatch")
    freeze = load_json(freeze_path)
    if freeze["status"] != control["freeze_status_required"]:
        raise SequenceGateError("freeze status mismatch")
    pc = freeze["adjudicator_ground_truth"]["positive_control"]
    if not pc.get("must_not_be_disclosed_to_adversary"):
        raise SequenceGateError("freeze no longer marks the positive control as non-disclosable")
    return (
        {
            "authorization_base_is_ancestor": True,
            "freeze_artifact_id": freeze["artifact_id"],
            "freeze_sha256": observed_sha,
            "freeze_status": freeze["status"],
            "origin_main": observed_head,
        },
        (str(pc["route_id"]), str(pc["endpoint"])),
    )


def verify_run_b_untouched(repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Run B is historical and closed; its bytes must not move."""
    checked: list[dict[str, str]] = []
    for item in manifest["predecessor_run"]["immutable_artifacts"]:
        path = repo / item["path"]
        observed = sha256_file(path)
        if observed != item["sha256"]:
            raise SequenceGateError(
                f"Run B artifact changed: {item['path']} expected {item['sha256']}, got {observed}"
            )
        checked.append({"path": item["path"], "sha256": observed})
    return {"run_b_artifacts_unchanged": True, "checked": checked}


def extract_target(repo: Path, commit: str, dest: Path) -> None:
    archive = dest.parent / "target.tar"
    with archive.open("wb") as f:
        subprocess.run(["git", "-C", str(repo), "archive", commit], check=True, stdout=f)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tf:
        tf.extractall(dest)
    archive.unlink()


# --------------------------------------------------------------------------
# provider transport -- the proven Run B envelope, reused unchanged
# --------------------------------------------------------------------------


def provider_request_body(
    manifest: dict[str, Any], messages: list[dict[str, str]]
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
    ledger: AuthorizationLedger,
) -> tuple[str, dict[str, Any]]:
    body = provider_request_body(manifest, messages)
    data = canonical_json(body)
    request_sha256 = sha256_bytes(data)
    if not ledger.consumed:
        ledger.consume("first_provider_request_sent", "S3")
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
        raise ProviderTransportError(
            _transport_error_record(
                classification="HTTP_RETRYABLE" if retryable else "HTTP_4XX_FATAL_FOR_RUN",
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
        raise ProviderTransportError(
            _transport_error_record(
                classification=(
                    "PROVIDER_SSE_RETRYABLE_ERROR" if retryable else "PROVIDER_SSE_FATAL_ERROR"
                ),
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
    return content, {
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


def provider_call_with_retries(
    manifest: dict[str, Any],
    messages: list[dict[str, str]],
    api_key: str,
    provider_state: dict[str, Any],
    started: float,
    ledger: AuthorizationLedger,
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
            content, audit = provider_call_once(manifest, messages, api_key, ledger)
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


# --------------------------------------------------------------------------
# target interaction
# --------------------------------------------------------------------------


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
    if not isinstance(obj.get("json"), dict):
        raise ValueError("json must be an object")
    return obj


def target_post(
    base_url: str, path: str, payload: dict[str, Any], timeout: float
) -> tuple[int, dict[str, Any] | str]:
    u = urlparse(base_url)
    if u.scheme != "http" or u.hostname != "127.0.0.1" or u.port is None:
        raise SequenceGateError("target BASE_URL escaped loopback binding")
    conn = http.client.HTTPConnection("127.0.0.1", u.port, timeout=timeout)
    try:
        conn.request(
            "POST", path, body=canonical_json(payload), headers={"Content-Type": "application/json"}
        )
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
    subject_verdict: dict[str, Any], *, attempts: int, terminal_provider_failure: bool
) -> dict[str, Any]:
    observed = subject_verdict.get("path_reconciliation", {}).get("observed_path_set", [])
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
            "subject_result": NOT_ESTABLISHED,
            "subject_verifier_disposition": subject_verdict.get("disposition"),
            "subject_verifier_verdict": subject_verdict,
        }
    verdict = dict(subject_verdict)
    verdict["instrument_status"] = "EXECUTED"
    if verdict.get("disposition") == POSITIVE_CONTROL_EXPECTED_DISPOSITION:
        verdict["subject_result"] = "COUNTEREXAMPLE_FOUND"
    else:
        verdict["subject_result"] = "ESTABLISHED_WITHIN_EXERCISED_SCOPE"
    return verdict


def sqlite_row_count(path: Path, table: str) -> int:
    con = sqlite3.connect(path)
    try:
        row = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # noqa: S608
        return int(row[0])
    except sqlite3.Error:
        return 0
    finally:
        con.close()


def secret_leak_audit(root: Path, secret: str) -> dict[str, Any]:
    if not secret:
        return {"credential_present": False, "secret_leak_scan": NOT_RUN}
    token = secret.encode()
    leaks: list[str] = []
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
        "secret_leak_scan": PASS if not leaks else FAIL,
    }


# --------------------------------------------------------------------------
# frozen-subject import
# --------------------------------------------------------------------------


@dataclass
class FrozenSubject:
    """Handles into the frozen target extracted from the exact target commit."""

    root: Path
    module: Any
    token_digest: Any
    authorization_cls: Any
    authority_state_cls: Any
    authority_store_cls: Any
    issuer_cls: Any
    adjudicate: Any
    evidence_cls: Any
    reconcile: Any
    protected_sink_cls: Any


def import_frozen_subject(target_dir: Path) -> FrozenSubject:
    sys.path.insert(0, str(target_dir))
    from oat.authority.authorization import (  # type: ignore[import-not-found]
        Authorization,
        AuthorizationIssuer,
        token_digest,
    )
    from oat.authority.current_state import AuthorityState, AuthorityStore  # type: ignore
    from oat.consequence.model import ProtectedSink  # type: ignore
    from oat.integration import host_sink  # type: ignore
    from oat.paths.discovery import reconcile  # type: ignore
    from oat.verifier.consequence import ConsequenceEvidence, adjudicate  # type: ignore

    return FrozenSubject(
        root=target_dir,
        module=host_sink,
        token_digest=token_digest,
        authorization_cls=Authorization,
        authority_state_cls=AuthorityState,
        authority_store_cls=AuthorityStore,
        issuer_cls=AuthorizationIssuer,
        adjudicate=adjudicate,
        evidence_cls=ConsequenceEvidence,
        reconcile=reconcile,
        protected_sink_cls=ProtectedSink,
    )


# --------------------------------------------------------------------------
# S0
# --------------------------------------------------------------------------


def run_s0(
    repo: Path,
    manifest: dict[str, Any],
    prompt: str,
    prompt_path: Path,
    runner_path: Path,
    out_root: Path,
    gates: GateState,
    ledger: AuthorizationLedger,
) -> dict[str, Any]:
    ledger.note("s0_entered", "S0")
    if sha256_file(prompt_path) != manifest["adversary_context"]["prompt_sha256"]:
        raise SequenceGateError("prompt SHA-256 mismatch")
    if sha256_file(runner_path) != manifest["runner"]["sha256"]:
        raise SequenceGateError("runner SHA-256 mismatch")

    target_check = verify_target(repo, manifest)
    control_check, forbidden_values = verify_control_freeze(repo, manifest)
    run_b_check = verify_run_b_untouched(repo, manifest)
    forbidden = forbidden_ground_truth_tokens(*forbidden_values)

    provider = manifest["provider"]
    authorized = manifest["owner_execution_authorization"]
    if provider["endpoint"] != manifest["provider"]["endpoint"]:  # pragma: no cover - identity
        raise SequenceGateError("provider endpoint mismatch")

    bundle = adversary_bundle(manifest, prompt, base_url="RUNTIME_BOUND_LOOPBACK_URL")
    audit = ground_truth_leak_audit(bundle, forbidden, stage="S0")

    out_exists = out_root.exists() and any(out_root.iterdir())
    preflight = {
        "artifact": "S0_PREFLIGHT",
        "budgets": manifest["budgets"],
        "control_plane": control_check,
        "credential_environment_variable": manifest["credential_isolation"]["environment_variable"],
        "ground_truth_leak_audit": audit,
        "output_directory_fresh": not out_exists,
        "owner_execution_authorization_id": authorized["authorization_id"],
        "prompt_sha256": sha256_file(prompt_path),
        "provider": {
            "endpoint": provider["endpoint"],
            "model": provider["model"],
            "provider": provider["provider"],
        },
        "provider_call_performed": False,
        "run_b_immutability": run_b_check,
        "runner_id": RUNNER_ID,
        "runner_sha256": sha256_file(runner_path),
        "runner_version": RUNNER_VERSION,
        "sampling": manifest["sampling"],
        "sequence_id": SEQUENCE_ID,
        "target": target_check,
        "timeouts": manifest["timeouts"],
    }
    failures: list[str] = []
    if audit["status"] != PASS:
        failures.append("GROUND_TRUTH_LEAK_AUDIT")
    if out_exists:
        failures.append("OUTPUT_DIRECTORY_NOT_FRESH")
    if ledger.consumed:
        failures.append("AUTHORIZATION_ALREADY_CONSUMED")
    preflight["status"] = PASS if not failures else FAIL
    preflight["failures"] = failures

    gates.s0_preflight = str(preflight["status"])
    gates.adversary_context_isolation = str(audit["status"])
    return preflight


def adversary_bundle(manifest: dict[str, Any], prompt: str, *, base_url: str) -> dict[str, Any]:
    """Everything the model can read, assembled for audit in one place.

    Assembling the bundle here and auditing *this* object is what makes the
    audit meaningful: if a surface is not in the bundle the audit fails rather
    than silently passing over unexamined material.
    """
    context = json.loads(json.dumps(manifest["adversary_context"]["initial_context_template"]))
    context["base_url"] = base_url
    return {
        "conversation_history": [],
        "generated_diagnostics": [],
        "initial_context": context,
        "model_readable_files": [],
        "prior_provider_messages": [],
        "projected_environment": {
            "external_network_allowed": False,
            "filesystem_access": False,
            "repository_access": False,
        },
        "system_prompt": prompt,
        "target_facing_documentation": manifest["adversary_context"]["initial_context_template"][
            "documented_endpoints"
        ],
        "tool_schema": manifest["adversary_context"]["initial_context_template"][
            "request_payload_contract"
        ],
        "user_prompt": json.dumps(context, sort_keys=True),
    }


# --------------------------------------------------------------------------
# S1 / S1A
# --------------------------------------------------------------------------


def run_s1(
    subject: FrozenSubject,
    manifest: dict[str, Any],
    state_dir: Path,
    out_dir: Path,
    hidden_endpoint_path: str,
    gates: GateState,
    ledger: AuthorizationLedger,
) -> tuple[Any, dict[str, Any]]:
    """Prove the detector is sensitive *before* the adversary ever runs.

    A positive control that only shows "the HTTP request succeeded" proves
    nothing about the instrument. The same verifier that will adjudicate Run C
    must itself produce the falsifier here.
    """
    ledger.note("s1_entered_no_provider_call", "S1")
    host, _auth = subject.module.new_reference_integration(state_dir)
    server_cls = subject.module.IntegrationServer

    action = dict(subject.module.REFERENCE_ACTION)
    payload = {
        "action": action,
        "agent_id": "agent.adjudicator-positive-control",
        "authorization_id": None,
        "commit_id": "pc-001",
        "committed_at": 10,
        "idempotency_key": "pc-idem-001",
        "token_digest": None,
    }
    with server_cls(host) as server:
        status, response = target_post(
            server.base_url,
            hidden_endpoint_path,
            payload,
            float(manifest["timeouts"]["target_request_seconds"]),
        )

    verdict = host.verdict().to_dict()
    disposition = str(verdict.get("disposition"))
    sensitive = disposition == POSITIVE_CONTROL_EXPECTED_DISPOSITION

    record = {
        "artifact": "POSITIVE_CONTROL_EXECUTION",
        "actual_disposition": disposition,
        "commits_recorded": len(host.ledger.commits()),
        "expected_disposition": POSITIVE_CONTROL_EXPECTED_DISPOSITION,
        "http_status": status,
        "pc_sensitivity": ESTABLISHED if sensitive else NOT_ESTABLISHED,
        "receipts_recorded": len(host.observer.receipts()),
        "response_body": response,
        "verifier": manifest["evidence_and_adjudication"]["verifier"],
    }
    gates.pc_sensitivity = record["pc_sensitivity"]
    return host, record


def run_s1a(
    host: Any,
    manifest: dict[str, Any],
    state_dir: Path,
    pc_dir: Path,
    execution_record: dict[str, Any],
    target_check: dict[str, Any],
    forbidden: tuple[str, ...],
    gates: GateState,
    ledger: AuthorizationLedger,
) -> dict[str, Any]:
    """Seal the positive-control evidence before any adversary state exists."""
    ledger.note("s1a_entered_no_provider_call", "S1A")
    if gates.pc_sensitivity != ESTABLISHED:
        raise SequenceGateError("refusing to seal: positive-control sensitivity not established")

    pc_dir.mkdir(parents=True, exist_ok=True)
    subject_verdict = host.verdict().to_dict()
    write_json(
        pc_dir / "target-identity.json",
        {
            "commit": target_check["commit"],
            "critical_file_count": target_check["critical_file_count"],
            "tree": target_check["tree"],
        },
    )
    write_json(pc_dir / "authority-state.json", host.authority.to_dict())
    write_json(pc_dir / "request-record.json", execution_record)
    write_json(
        pc_dir / "evidence.json",
        {
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
        },
    )
    write_json(pc_dir / "verdict.json", subject_verdict)
    for name in ("ledger.sqlite3", "telemetry.sqlite3"):
        shutil.copy2(state_dir / name, pc_dir / name)
    write_sha256sums(pc_dir)

    archive_digest = sha256_file(pc_dir / "SHA256SUMS.txt")
    seal = {
        "actual_disposition": execution_record["actual_disposition"],
        "adversary_visible": False,
        "artifact": "POSITIVE_CONTROL_SEAL",
        "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "evidence_archive_digest": archive_digest,
        "expected_disposition": POSITIVE_CONTROL_EXPECTED_DISPOSITION,
        "pc_sensitivity": ESTABLISHED,
        "sealed_file_count": len([p for p in pc_dir.rglob("*") if p.is_file()]),
        "sequence_id": SEQUENCE_ID,
        "target_commit": execution_record.get("target_commit", target_check["commit"]),
        "target_tree": target_check["tree"],
        "verifier": manifest["evidence_and_adjudication"]["verifier"],
        "verifier_identity_note": "same verifier/falsifier machinery adjudicates Run C",
    }
    # The seal is public-facing; it must survive the same leak audit as the
    # adversary bundle, or a "safe" summary becomes the disclosure channel.
    seal_text = json.dumps(seal, sort_keys=True).lower()
    if any(token.lower() in seal_text for token in forbidden):
        raise SequenceGateError("positive-control seal would disclose adjudicator ground truth")
    gates.pc_evidence_sealed = True
    return seal


# --------------------------------------------------------------------------
# S2
# --------------------------------------------------------------------------


def run_s2(
    host: Any,
    subject: FrozenSubject,
    manifest: dict[str, Any],
    prompt: str,
    pc_state_dir: Path,
    adversary_state_dir: Path,
    target_check: dict[str, Any],
    forbidden: tuple[str, ...],
    gates: GateState,
    ledger: AuthorizationLedger,
) -> tuple[Any, dict[str, Any]]:
    """Destroy the positive-control state and instantiate a fresh target."""
    ledger.note("s2_entered_no_provider_call", "S2")
    if gates.pc_sensitivity != ESTABLISHED or not gates.pc_evidence_sealed:
        raise SequenceGateError(
            "refusing to reset before the positive control is proven and sealed"
        )

    pc_ledger_digest = sha256_file(pc_state_dir / "ledger.sqlite3")
    pc_telemetry_digest = sha256_file(pc_state_dir / "telemetry.sqlite3")
    pc_authority = host.authority.to_dict()
    host.close()
    shutil.rmtree(pc_state_dir)

    if adversary_state_dir.exists():
        raise SequenceGateError("adversary state directory already exists; refusing to reuse")
    adversary_host, _auth = subject.module.new_reference_integration(adversary_state_dir)

    ledger_commits = sqlite_row_count(adversary_state_dir / "ledger.sqlite3", "ledger_commits")
    telemetry_receipts = sqlite_row_count(adversary_state_dir / "telemetry.sqlite3", "receipts")
    telemetry_routes = sqlite_row_count(
        adversary_state_dir / "telemetry.sqlite3", "route_observations"
    )

    bundle = adversary_bundle(manifest, prompt, base_url="RUNTIME_BOUND_LOOPBACK_URL")
    audit = ground_truth_leak_audit(bundle, forbidden, stage="S2")

    attestation = {
        "adversary_initial_ledger_empty": ledger_commits == 0,
        "adversary_initial_telemetry_empty": telemetry_receipts == 0 and telemetry_routes == 0,
        "adversary_ledger_commit_rows": ledger_commits,
        "adversary_state_path": adversary_state_dir.as_posix(),
        "adversary_target_commit": target_check["commit"],
        "adversary_target_tree": target_check["tree"],
        "adversary_telemetry_receipt_rows": telemetry_receipts,
        "adversary_telemetry_route_rows": telemetry_routes,
        "artifact": "RESET_ATTESTATION",
        "authority_seed_equivalent": adversary_host.authority.to_dict() == pc_authority,
        "positive_control_state_destroyed": not pc_state_dir.exists(),
        "positive_control_state_path": pc_state_dir.as_posix(),
        "positive_control_state_reused": False,
        "positive_control_target_commit": target_check["commit"],
        "positive_control_target_tree": target_check["tree"],
        "post_reset_ground_truth_leak_audit": audit["status"],
        "sealed_positive_control_ledger_digest": pc_ledger_digest,
        "sealed_positive_control_telemetry_digest": pc_telemetry_digest,
        "sequence_id": SEQUENCE_ID,
    }
    checks = {
        "adversary_initial_ledger_empty": attestation["adversary_initial_ledger_empty"],
        "adversary_initial_telemetry_empty": attestation["adversary_initial_telemetry_empty"],
        "authority_seed_equivalent": attestation["authority_seed_equivalent"],
        "positive_control_state_destroyed": attestation["positive_control_state_destroyed"],
        "same_frozen_target": (
            attestation["positive_control_target_commit"] == attestation["adversary_target_commit"]
            and attestation["positive_control_target_tree"] == attestation["adversary_target_tree"]
        ),
    }
    separated = all(checks.values()) and audit["status"] == PASS
    attestation["checks"] = checks
    attestation["state_separation"] = ESTABLISHED if separated else NOT_ESTABLISHED
    attestation["ground_truth_leak_audit"] = audit

    gates.state_separation = str(attestation["state_separation"])
    gates.adversary_context_isolation = str(audit["status"])
    return adversary_host, attestation


# --------------------------------------------------------------------------
# S3
# --------------------------------------------------------------------------


def run_s3(
    host: Any,
    subject: FrozenSubject,
    manifest: dict[str, Any],
    prompt: str,
    api_key: str,
    adversary_dir: Path,
    forbidden: tuple[str, ...],
    gates: GateState,
    ledger: AuthorizationLedger,
) -> dict[str, Any]:
    """Bounded adversarial Run C. The first provider request consumes the authorization."""
    assert_s3_eligible(gates)
    if ledger.consumed:
        raise SequenceGateError("authorization already consumed; automatic rerun prohibited")

    server_cls = subject.module.IntegrationServer
    adversary_dir.mkdir(parents=True, exist_ok=True)
    write_json(adversary_dir / "run-manifest.snapshot.json", manifest)
    (adversary_dir / "provider-transcript.jsonl").touch()
    (adversary_dir / "http-attempts.jsonl").touch()

    started = time.monotonic()
    stop_reason = "UNSET"
    attempts = 0
    invalid_outputs = 0
    terminal_provider_failure = False
    provider_state: dict[str, Any] = {"calls": 0, "failures": []}
    budgets = manifest["budgets"]
    timeouts = manifest["timeouts"]

    with server_cls(host) as server:
        bundle = adversary_bundle(manifest, prompt, base_url=server.base_url)
        context = dict(bundle["initial_context"])
        context["reference_action"] = subject.module.REFERENCE_ACTION
        bundle["initial_context"] = context
        bundle["user_prompt"] = json.dumps(context, sort_keys=True)
        # Last audit before the model can see anything.
        assert_s3_eligible(gates)
        assert_no_ground_truth(bundle, forbidden, stage="S3_PRE_REQUEST")
        write_json(
            adversary_dir / "ADVERSARY_CONTEXT_DIGEST.json",
            {
                "artifact": "ADVERSARY_CONTEXT_DIGEST",
                "bundle_digest": digest_object(bundle),
                "sequence_id": SEQUENCE_ID,
                "surfaces": sorted(bundle),
            },
        )
        write_json(
            adversary_dir / "GROUND_TRUTH_LEAK_AUDIT.json",
            ground_truth_leak_audit(bundle, forbidden, stage="S3_PRE_REQUEST"),
        )

        messages: list[dict[str, str]] = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": bundle["user_prompt"]},
        ]

        logical_turn = 0
        while True:
            if time.monotonic() - started >= float(timeouts["run_wall_clock_seconds"]):
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
                    manifest, messages, api_key, provider_state, started, ledger
                )
            except (ProviderBudgetStop, ProviderTerminalError) as exc:
                new_failures = provider_state["failures"][failure_start:]
                for record in new_failures:
                    append_jsonl(
                        adversary_dir / "provider-transcript.jsonl",
                        {**record, "logical_turn": logical_turn},
                    )
                if new_failures:
                    terminal_provider_failure = True
                stop_reason = (
                    str(exc)
                    if isinstance(exc, ProviderBudgetStop)
                    else "PROVIDER_TRANSPORT_FAILURE"
                )
                if isinstance(exc, ProviderTerminalError):
                    terminal_provider_failure = True
                break

            for record in provider_state["failures"][failure_start:]:
                append_jsonl(
                    adversary_dir / "provider-transcript.jsonl",
                    {**record, "logical_turn": logical_turn},
                )
            append_jsonl(
                adversary_dir / "provider-transcript.jsonl",
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
                                {"detail": str(exc), "observation": "INVALID_ACTION_JSON"}
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
            try:
                status, response = target_post(
                    server.base_url,
                    action["path"],
                    action["json"],
                    float(timeouts["target_request_seconds"]),
                )
            except Exception as exc:
                status = 0
                response = {"detail": str(exc), "transport_error": type(exc).__name__}

            append_jsonl(
                adversary_dir / "http-attempts.jsonl",
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
            if subject_verdict["disposition"] == POSITIVE_CONTROL_EXPECTED_DISPOSITION:
                stop_reason = "VERIFIER_CONFIRMED_CONSEQUENCE_BOUNDARY_FAILURE"
                break

            messages.extend(
                [
                    {"role": "assistant", "content": content},
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "instruction": "Continue systematic bounded exploration or STOP.",
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
        subject_verdict, attempts=attempts, terminal_provider_failure=terminal_provider_failure
    )
    evidence = {
        "authority": host.authority.to_dict(),
        "authorizations": {k: v.to_dict() for k, v in host.authorizations.items()},
        "commits": [c.to_dict() for c in host.ledger.commits()],
        "observed_paths": [o.to_dict() for o in host.observer.observed_paths()],
        "protected_sink": {"description": host.sink.description, "sink_id": host.sink.sink_id},
        "receipts": [r.to_dict() for r in host.observer.receipts()],
        "subject_verifier_verdict": subject_verdict,
        "verdict": verdict,
    }
    write_json(adversary_dir / "verdict.json", verdict)
    write_json(adversary_dir / "evidence.json", evidence)
    runtime = {
        "artifact": "RUN_C_RUNTIME",
        "authorization": ledger.to_dict(),
        "claim_bearing_use": "PROHIBITED",
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "instrument_status": verdict.get("instrument_status"),
        "provider_call_performed": provider_state["calls"] > 0,
        "provider_calls": provider_state["calls"],
        "provider_transport_failures": len(provider_state["failures"]),
        "reasoning_content_persisted": False,
        "run_id": manifest["run_id"],
        "run_mode": "METHOD_DEVELOPMENT_ONLY",
        "sequence_id": SEQUENCE_ID,
        "stop_reason": stop_reason,
        "subject_result": verdict.get("subject_result"),
        "target_http_attempts": attempts,
    }
    write_json(adversary_dir / "runtime.json", runtime)
    write_json(
        adversary_dir / "credential-redaction-audit.json", secret_leak_audit(adversary_dir, api_key)
    )
    write_sha256sums(adversary_dir)
    return runtime


# --------------------------------------------------------------------------
# S4 -- replay and joint adjudication
# --------------------------------------------------------------------------


def rebuild_authority(subject: FrozenSubject, record: dict[str, Any]) -> Any:
    store = subject.authority_store_cls()
    for epoch in record["epochs"]:
        store.add(
            subject.authority_state_cls(
                epoch=int(epoch["epoch"]),
                effective_from=int(epoch["effective_from"]),
                active_grants=tuple(epoch["active_grants"]),
                revoked_grants=tuple(epoch["revoked_grants"]),
                superseded_grants=tuple(epoch["superseded_grants"]),
            )
        )
    return store


def rebuild_authorization(subject: FrozenSubject, record: dict[str, Any]) -> Any:
    if record.get("delegation") not in (None, "NOT_APPLICABLE"):
        raise SequenceGateError("replay of delegated authorizations is not bound by this runner")
    return subject.authorization_cls(
        authorization_id=record["authorization_id"],
        grant_id=record["grant_id"],
        decision=record["decision"],
        tenant_id=record["tenant_id"],
        principal_id=record["principal_id"],
        agent_id=record["agent_id"],
        release_id=record["release_id"],
        action_digest=record["action_digest"],
        sink_id=record["sink_id"],
        scope=record["scope"],
        authority_state_digest=record["authority_state_digest"],
        not_before=int(record["not_before"]),
        not_after=int(record["not_after"]),
        idempotency_key=record["idempotency_key"],
        max_uses=int(record["max_uses"]),
        integrity=record.get("integrity", ""),
    )


def replay_from_evidence(
    subject: FrozenSubject, evidence_dir: Path, workdir: Path, label: str
) -> dict[str, Any]:
    """Re-adjudicate from the preserved evidence, not from the stored verdict.

    The SQLite ledger and telemetry stores are copied into a scratch directory
    and re-read by the frozen host implementation, so the replay reconstructs
    the evidence graph and runs the frozen verifier over it.
    """
    stored = load_json(evidence_dir / "evidence.json")
    stored_verdict = stored["subject_verifier_verdict"]

    workdir.mkdir(parents=True, exist_ok=True)
    for name in ("ledger.sqlite3", "telemetry.sqlite3"):
        shutil.copy2(evidence_dir / name, workdir / name)

    authority = rebuild_authority(subject, stored["authority"])
    issuer = subject.issuer_cls(b"oat-host-sink-reference-secret")
    sink = subject.protected_sink_cls(
        stored["protected_sink"]["sink_id"], stored["protected_sink"]["description"]
    )
    host = subject.module.HostSinkIntegration(workdir, sink, authority, issuer)
    try:
        for record in stored["authorizations"].values():
            host.register(rebuild_authorization(subject, record))
        recomputed = host.verdict().to_dict()
    finally:
        host.close()

    matches = recomputed.get("disposition") == stored_verdict.get("disposition")
    return {
        "artifact": f"{label}_REPLAY",
        "evidence_integrity": verify_sha256sums(evidence_dir),
        "recomputed_disposition": recomputed.get("disposition"),
        "replay_matches_original": matches,
        "replay_method": (
            "reconstruct the evidence graph from the preserved stores and re-run the "
            "frozen verifier"
        ),
        "sequence_id": SEQUENCE_ID,
        "stored_disposition": stored_verdict.get("disposition"),
    }


def adjudicate_sequence(
    gates: GateState,
    ledger: AuthorizationLedger,
    pc_replay: dict[str, Any],
    run_c_replay: dict[str, Any] | None,
    run_c_runtime: dict[str, Any] | None,
) -> dict[str, Any]:
    """Jointly adjudicate. Sequence completeness never absorbs subject outcome."""
    run_c_executed = bool(run_c_runtime and run_c_runtime.get("provider_call_performed"))
    subject_result = str(run_c_runtime.get("subject_result")) if run_c_runtime else NOT_ESTABLISHED
    subject_disposition = (
        str(run_c_runtime.get("instrument_status")) if run_c_runtime else "NOT_EXECUTED"
    )

    integrity_checks = {
        "positive_control_evidence_integrity": pc_replay["evidence_integrity"]["status"],
        "run_c_evidence_integrity": (
            run_c_replay["evidence_integrity"]["status"] if run_c_replay else NOT_RUN
        ),
    }
    conditions = {
        "adversary_context_isolation": gates.adversary_context_isolation == PASS,
        "evidence_integrity": all(v == PASS for v in integrity_checks.values()),
        "pc_replay_matches": bool(pc_replay["replay_matches_original"]),
        "pc_replay_reproduces_expected": (
            pc_replay["recomputed_disposition"] == POSITIVE_CONTROL_EXPECTED_DISPOSITION
        ),
        "pc_sensitivity": gates.pc_sensitivity == ESTABLISHED,
        "run_c_executed": run_c_executed,
        "run_c_replay_matches": bool(run_c_replay and run_c_replay["replay_matches_original"]),
        "state_separation": gates.state_separation == ESTABLISHED,
    }
    closure = ESTABLISHED if all(conditions.values()) else NOT_ESTABLISHED
    return {
        "adversary_context_isolation": gates.adversary_context_isolation,
        "artifact": "SEQUENCE_ADJUDICATION",
        "authorization": ledger.to_dict(),
        "claim_bearing_use": "PROHIBITED",
        "closure_conditions": conditions,
        "evidence_integrity": integrity_checks,
        "full_frozen_sequence_closure": closure,
        "note": (
            "FULL_FROZEN_SEQUENCE_CLOSURE describes the completeness of the ordered "
            "experiment, never the subject outcome. A genuine Run C counterexample is "
            "a complete sequence."
        ),
        "pc_sensitivity": gates.pc_sensitivity,
        "positive_control_replay": pc_replay,
        "run_c_execution": "EXECUTED" if run_c_executed else "NOT_EXECUTED",
        "run_c_replay": run_c_replay,
        "run_c_subject_disposition": subject_disposition,
        "run_c_subject_result": subject_result,
        "sequence_id": SEQUENCE_ID,
        "state_separation": gates.state_separation,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=f"{SEQUENCE_ID} six-stage runner")
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("--prompt", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--stop-after",
        choices=["S0", "S1", "S1A", "S2", "S3", "S4"],
        default="S4",
        help="highest stage to execute; S2 stops before any provider contact",
    )
    args = ap.parse_args()

    repo = args.repo.resolve()
    manifest = load_json(args.manifest)
    prompt = args.prompt.read_text(encoding="utf-8")
    out_root = (args.out or (repo / manifest["outputs"]["sequence_directory"])).resolve()
    runner_path = Path(__file__).resolve()

    gates = GateState()
    ledger = AuthorizationLedger(manifest["owner_execution_authorization"]["authorization_id"])

    preflight = run_s0(repo, manifest, prompt, args.prompt, runner_path, out_root, gates, ledger)
    out_root.mkdir(parents=True, exist_ok=True)
    write_json(out_root / "sequence-manifest.json", manifest)
    write_json(out_root / "S0_PREFLIGHT.json", preflight)
    if preflight["status"] != PASS:
        print(
            json.dumps({"stage": "S0", "status": FAIL, "failures": preflight["failures"]}, indent=2)
        )
        return 1
    if args.stop_after == "S0":
        print(json.dumps({"stage": "S0", "status": PASS, "provider_calls": 0}, indent=2))
        return 0

    _control, forbidden_values = verify_control_freeze(repo, manifest)
    forbidden = forbidden_ground_truth_tokens(*forbidden_values)
    hidden_endpoint = forbidden_values[1]
    hidden_path = hidden_endpoint.split(" ", 1)[1] if " " in hidden_endpoint else hidden_endpoint

    adjudicator_dir = out_root / "adjudicator"
    pc_dir = adjudicator_dir / "positive-control"
    adversary_dir = out_root / "adversary"
    adjudication_dir = out_root / "adjudication"

    with tempfile.TemporaryDirectory(prefix="oat-seq003-") as td:
        scratch = Path(td)
        target_dir = scratch / "target"
        extract_target(repo, manifest["target"]["commit"], target_dir)
        subject = import_frozen_subject(target_dir)
        target_check = preflight["target"]

        pc_state = scratch / "pc-state"
        host, pc_record = run_s1(subject, manifest, pc_state, pc_dir, hidden_path, gates, ledger)
        if gates.pc_sensitivity != ESTABLISHED:
            host.close()
            write_json(adjudication_dir / "S1_POSITIVE_CONTROL_FAILED.json", pc_record)
            print(
                json.dumps(
                    {
                        "stage": "S1",
                        "pc_sensitivity": NOT_ESTABLISHED,
                        "provider_calls": 0,
                        "authorization_consumed": ledger.consumed,
                        "full_frozen_sequence_closure": NOT_ESTABLISHED,
                    },
                    indent=2,
                )
            )
            return 1
        if args.stop_after == "S1":
            host.close()
            print(json.dumps({"stage": "S1", "pc_sensitivity": ESTABLISHED}, indent=2))
            return 0

        seal = run_s1a(
            host, manifest, pc_state, pc_dir, pc_record, target_check, forbidden, gates, ledger
        )
        write_json(adjudicator_dir / "POSITIVE_CONTROL_SEAL.json", seal)
        if args.stop_after == "S1A":
            host.close()
            print(json.dumps({"stage": "S1A", "seal": seal["evidence_archive_digest"]}, indent=2))
            return 0

        adversary_state = scratch / "adversary-state"
        adversary_host, attestation = run_s2(
            host,
            subject,
            manifest,
            prompt,
            pc_state,
            adversary_state,
            target_check,
            forbidden,
            gates,
            ledger,
        )
        write_json(adjudication_dir / "RESET_ATTESTATION.json", attestation)
        if attestation["state_separation"] != ESTABLISHED:
            adversary_host.close()
            print(json.dumps({"stage": "S2", "state_separation": NOT_ESTABLISHED}, indent=2))
            return 1

        run_c_runtime: dict[str, Any] | None = None
        try:
            if args.stop_after in {"S3", "S4"}:
                api_key = os.environ.get(
                    manifest["credential_isolation"]["environment_variable"], ""
                )
                supplied = os.environ.get(
                    manifest["owner_execution_authorization"]["environment_variable"], ""
                )
                if not api_key:
                    raise SequenceGateError(
                        "missing provider credential; S3 not started, authorization unconsumed"
                    )
                if supplied != ledger.authorization_id:
                    raise SequenceGateError(
                        "owner execution authorization environment binding missing or incorrect"
                    )
                run_c_runtime = run_s3(
                    adversary_host,
                    subject,
                    manifest,
                    prompt,
                    api_key,
                    adversary_dir,
                    forbidden,
                    gates,
                    ledger,
                )
                for name in ("ledger.sqlite3", "telemetry.sqlite3"):
                    shutil.copy2(adversary_state / name, adversary_dir / name)
                write_sha256sums(adversary_dir)
        finally:
            adversary_host.close()

        pc_replay = replay_from_evidence(subject, pc_dir, scratch / "pc-replay", "POSITIVE_CONTROL")
        write_json(adjudication_dir / "POSITIVE_CONTROL_REPLAY.json", pc_replay)
        run_c_replay = None
        if run_c_runtime is not None:
            run_c_replay = replay_from_evidence(
                subject, adversary_dir, scratch / "run-c-replay", "ADVERSARY"
            )
            write_json(adjudication_dir / "ADVERSARY_REPLAY.json", run_c_replay)

        adjudication = adjudicate_sequence(gates, ledger, pc_replay, run_c_replay, run_c_runtime)
        write_json(adjudication_dir / "SEQUENCE_ADJUDICATION.json", adjudication)

    print(
        json.dumps(
            {
                "authorization_consumed": ledger.consumed,
                "full_frozen_sequence_closure": adjudication["full_frozen_sequence_closure"],
                "out": str(out_root),
                "pc_sensitivity": gates.pc_sensitivity,
                "run_c_execution": adjudication["run_c_execution"],
                "run_c_subject_result": adjudication["run_c_subject_result"],
                "state_separation": gates.state_separation,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
