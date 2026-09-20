#!/usr/bin/env python3
"""NVIDIA provider credential and transport preflight. NOT an OAT experiment.

Run C consumed a one-run owner authorization and immediately received HTTP 401.
The authorization was spent to learn that a credential was bad. This tool
exists so that failure mode is discovered *before* an authorization is at
stake.

It is deliberately outside the adversarial sequence. It does not touch the
frozen target, does not instantiate the host/sink, does not read adjudicator
ground truth, does not use the adversary prompt, does not take the owner
authorization environment binding, and does not write into a run evidence
directory. It sends one minimal non-adversarial request and reports whether
the credential, endpoint, model and streaming envelope work.

The credential is read from the environment, used only as a Bearer header,
and never printed, echoed, logged, or written to any artifact.

    python tools/oat_nvidia_provider_preflight.py --out /tmp/preflight.json

Exit status is 0 on PASS and 1 on FAIL.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TOOL_ID = "OAT-NVIDIA-PROVIDER-PREFLIGHT"
TOOL_VERSION = "1.0.0"

ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
CREDENTIAL_ENV = "NVIDIA_API_KEY"
PREFLIGHT_PROMPT = "Return exactly OK."
MAX_TOKENS = 16
TIMEOUT_SECONDS = 120

PASS = "PASS"
FAIL = "FAIL"

ALLOWED_PROVIDER_HEADERS = frozenset(
    {"content-type", "date", "nvcf-reqid", "nvcf-status", "x-request-id"}
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def allowed_headers(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    return {
        str(k).lower(): str(v)
        for k, v in headers.items()
        if str(k).lower() in ALLOWED_PROVIDER_HEADERS
    }


def data_payloads(raw: bytes) -> list[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []
    payloads: list[str] = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        lines = [line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")]
        if lines:
            payloads.append("\n".join(lines))
    return payloads


def read_stream(response: Any, raw: bytearray) -> bool:
    readline = getattr(response, "readline", None)
    if not callable(readline):
        raw.extend(response.read())
        return "[DONE]" in data_payloads(bytes(raw))
    event: list[bytes] = []
    while True:
        line = readline()
        if line == b"":
            return False
        raw.extend(line)
        normalized = line.rstrip(b"\r\n")
        if normalized:
            if normalized.startswith(b"data:"):
                event.append(normalized[5:].lstrip())
            continue
        if event and b"\n".join(event) == b"[DONE]":
            return True
        event = []


def returned_model(raw: bytes) -> str:
    model = ""
    for data in data_payloads(raw):
        if data == "[DONE]":
            continue
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("model"):
            model = str(payload["model"])
    return model


def provider_error(raw: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    else:
        if isinstance(value, dict) and isinstance(value.get("error"), dict):
            return {"type": value["error"].get("type"), "code": value["error"].get("code")}
    for data in data_payloads(raw):
        if data == "[DONE]":
            continue
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and isinstance(event.get("error"), dict):
            return {"type": event["error"].get("type"), "code": event["error"].get("code")}
    return None


def classify(status: int | None, *, done: bool, model_ok: bool) -> str:
    if status == 401 or status == 403:
        return "AUTHENTICATION_FAILURE"
    if status == 404:
        return "MODEL_OR_ENDPOINT_NOT_FOUND"
    if status == 429:
        return "RATE_LIMITED"
    if status is None:
        return "TRANSPORT_FAILURE"
    if status >= 500:
        return "PROVIDER_SERVER_ERROR"
    if status >= 400:
        return "PROVIDER_CLIENT_ERROR"
    if not done:
        return "STREAM_INCOMPLETE"
    if not model_ok:
        return "MODEL_MISMATCH"
    return "PROVIDER_TRANSPORT_OK"


def base_record(credential_present: bool) -> dict[str, Any]:
    return {
        "artifact": "PROVIDER_PREFLIGHT",
        "claim_bearing_use": "PROHIBITED",
        "consumes_owner_experiment_authorization": False,
        "credential_environment_variable": CREDENTIAL_ENV,
        "credential_present": credential_present,
        "credential_value_persisted": False,
        "endpoint": ENDPOINT,
        "frozen_target_touched": False,
        "is_oat_experiment": False,
        "model": MODEL,
        "provider": "NVIDIA NIM API",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool_id": TOOL_ID,
        "tool_version": TOOL_VERSION,
    }


def run_preflight() -> dict[str, Any]:
    api_key = os.environ.get(CREDENTIAL_ENV, "")
    record = base_record(bool(api_key))
    if not api_key:
        record.update(
            {
                "classification": "CREDENTIAL_ABSENT",
                "http_status": None,
                "preflight_status": FAIL,
                "reason": f"{CREDENTIAL_ENV} is not set in the environment",
                "stream_done_observed": False,
            }
        )
        return record

    body = {
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": PREFLIGHT_PROMPT}],
        "model": MODEL,
        "stream": True,
        "temperature": 0.0,
    }
    data = canonical_json(body)
    record["request_digest"] = sha256_bytes(data)
    started = time.monotonic()
    request = urllib.request.Request(
        ENDPOINT,
        data=data,
        method="POST",
        headers={
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    raw = bytearray()
    status: int | None = None
    headers: dict[str, str] = {}
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            status = int(response.status)
            headers = allowed_headers(response.headers)
            done = read_stream(response, raw)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        headers = allowed_headers(exc.headers)
        with contextlib.suppress(Exception):
            raw.extend(exc.read())
        done = False
    except TimeoutError:
        done = False
        record["reason"] = "provider call timed out"
    except OSError:
        done = False
        record["reason"] = "could not connect to the provider endpoint"

    payload = bytes(raw)
    seen_model = returned_model(payload)
    model_ok = seen_model == MODEL if seen_model else False
    classification = classify(status, done=done, model_ok=model_ok)
    ok = status == 200 and done and model_ok

    record.update(
        {
            "classification": classification,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "http_status": status,
            "preflight_status": PASS if ok else FAIL,
            "provider_error": provider_error(payload),
            "response_bytes": len(payload),
            "response_digest": sha256_bytes(payload),
            "response_headers": headers,
            "returned_model": seen_model,
            "returned_model_matches_bound_model": model_ok,
            "stream_done_observed": done,
        }
    )
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="NVIDIA provider credential/transport preflight")
    parser.add_argument("--out", type=Path, required=True, help="path for the PASS/FAIL artifact")
    args = parser.parse_args()

    record = run_preflight()

    # Defensive: the artifact is written to disk and read by the sequence
    # runner, so it must never carry the secret even if a future edit adds a
    # field that echoes a header or request.
    secret = os.environ.get(CREDENTIAL_ENV, "")
    serialized = json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False)
    if secret and secret in serialized:
        raise SystemExit("refusing to write preflight artifact: credential present in output")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(serialized + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "classification": record["classification"],
                "credential_present": record["credential_present"],
                "http_status": record.get("http_status"),
                "out": str(args.out),
                "preflight_status": record["preflight_status"],
                "returned_model_matches_bound_model": record.get(
                    "returned_model_matches_bound_model", False
                ),
                "stream_done_observed": record.get("stream_done_observed", False),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if record["preflight_status"] == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
