"""NVIDIA HTTPS/SSE transport with secret-free, replayable evidence."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Any

from oat.adversaries.provider import Transport, TransportError

ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
ALLOWED_HEADERS = frozenset({"content-type", "date", "nvcf-reqid", "nvcf-status", "x-request-id"})
RETRY_DELAYS_SECONDS = (1, 2)


class TransportClass(str, Enum):
    SUCCESSFUL_MODEL_RESPONSE = "SUCCESSFUL_MODEL_RESPONSE"
    HTTP_429_RETRYABLE = "HTTP_429_RETRYABLE"
    HTTP_4XX_FATAL_FOR_ANGLE = "HTTP_4XX_FATAL_FOR_ANGLE"
    HTTP_5XX_TRANSPORT_FAILURE = "HTTP_5XX_TRANSPORT_FAILURE"
    CONNECT_FAILURE = "CONNECT_FAILURE"
    TIMEOUT = "TIMEOUT"
    STREAM_INCOMPLETE = "STREAM_INCOMPLETE"
    MALFORMED_SSE = "MALFORMED_SSE"
    MODEL_RESPONSE_MALFORMED = "MODEL_RESPONSE_MALFORMED"


@dataclass(frozen=True)
class TransportEvidence:
    classification: TransportClass
    request_body: bytes
    request_sha256: str
    http_status: int
    response_headers: dict[str, str]
    raw_sse: bytes
    reconstructed_content: str
    returned_model: str
    done_seen: bool
    elapsed_ms: int
    response_sha256: str
    provider_run_occurred: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "canonical_request_body": self.request_body.decode(),
            "request_sha256": self.request_sha256,
            "http_status": self.http_status,
            "response_headers": self.response_headers,
            "raw_sse_utf8": self.raw_sse.decode("utf-8", "strict"),
            "reconstructed_assistant_content": self.reconstructed_content,
            "returned_model": self.returned_model,
            "done_seen": self.done_seen,
            "elapsed_ms": self.elapsed_ms,
            "response_sha256": self.response_sha256,
            "provider_run_occurred": self.provider_run_occurred,
        }


def canonical_request_body(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def reconstruct_sse(raw: bytes) -> tuple[str, str, bool]:
    content: list[str] = []
    model = ""
    done = False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransportError("MALFORMED_SSE") from exc
    for block in text.replace("\r\n", "\n").split("\n\n"):
        data_lines = [line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")]
        if not data_lines:
            continue
        data = "\n".join(data_lines)
        if data == "[DONE]":
            done = True
            continue
        try:
            event = json.loads(data)
            model = str(event.get("model", model))
            choices = event.get("choices")
            if not isinstance(choices, list):
                raise ValueError
            for choice in choices:
                delta = choice.get("delta", {})
                if isinstance(delta.get("content"), str):
                    content.append(delta["content"])
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise TransportError("MALFORMED_SSE") from exc
    return "".join(content), model, done


class NvidiaSSETransport(Transport):
    is_live = True
    name = "nvidia-https-sse"

    def __init__(self, *, api_key_env: str = "NVIDIA_API_KEY", timeout: int = 120) -> None:
        self.api_key_env = api_key_env
        self.timeout = timeout
        self.last_evidence: TransportEvidence | None = None

    @property
    def provider_run_occurred(self) -> bool:
        return bool(self.last_evidence and self.last_evidence.provider_run_occurred)

    def complete(self, prompt: str) -> str:
        return self.complete_body(
            {
                "model": "nvidia/nemotron-3-ultra-550b-a55b",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "top_p": 1.0,
                "max_tokens": 4096,
                "stream": True,
                "seed": 20260915,
            }
        ).reconstructed_content

    def complete_body(self, body: dict[str, Any]) -> TransportEvidence:
        key = os.environ.get(self.api_key_env)
        if not key:
            raise TransportError(
                f"missing runtime secret in environment variable {self.api_key_env}"
            )
        request_body = canonical_request_body(body)
        started = time.monotonic()
        request = urllib.request.Request(
            ENDPOINT,
            data=request_body,
            method="POST",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                status = int(response.status)
                headers = {
                    k.lower(): v
                    for k, v in response.headers.items()
                    if k.lower() in ALLOWED_HEADERS
                }
        except urllib.error.HTTPError as exc:
            cls = (
                TransportClass.HTTP_429_RETRYABLE
                if exc.code == 429
                else (
                    TransportClass.HTTP_4XX_FATAL_FOR_ANGLE
                    if 400 <= exc.code < 500
                    else TransportClass.HTTP_5XX_TRANSPORT_FAILURE
                )
            )
            raise TransportError(cls.value) from None
        except TimeoutError:
            raise TransportError(TransportClass.TIMEOUT.value) from None
        except OSError:
            raise TransportError(TransportClass.CONNECT_FAILURE.value) from None
        content, model, done = reconstruct_sse(raw)
        if not done:
            raise TransportError(TransportClass.STREAM_INCOMPLETE.value)
        evidence = TransportEvidence(
            TransportClass.SUCCESSFUL_MODEL_RESPONSE,
            request_body,
            hashlib.sha256(request_body).hexdigest(),
            status,
            headers,
            raw,
            content,
            model,
            done,
            int((time.monotonic() - started) * 1000),
            hashlib.sha256(raw).hexdigest(),
            True,
        )
        self.last_evidence = evidence
        return evidence

    def complete_with_retries(self, body: dict[str, Any]) -> TransportEvidence:
        """Use the frozen deterministic 1s/2s schedule for transport failures only."""
        retryable = {
            TransportClass.HTTP_429_RETRYABLE.value,
            TransportClass.HTTP_5XX_TRANSPORT_FAILURE.value,
            TransportClass.CONNECT_FAILURE.value,
            TransportClass.TIMEOUT.value,
            TransportClass.STREAM_INCOMPLETE.value,
        }
        for retry, delay in enumerate((*RETRY_DELAYS_SECONDS, 0)):
            try:
                return self.complete_body(body)
            except TransportError as exc:
                if str(exc) not in retryable or retry == len(RETRY_DELAYS_SECONDS):
                    raise
                time.sleep(delay)
        raise AssertionError("unreachable")
