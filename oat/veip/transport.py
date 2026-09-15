"""NVIDIA HTTPS/SSE transport with secret-free, replayable evidence."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from oat.adversaries.provider import Transport, TransportError

ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
ALLOWED_HEADERS = frozenset({"content-type", "date", "nvcf-reqid", "nvcf-status", "x-request-id"})
RETRY_DELAYS_SECONDS = (1, 2)
MAX_PROVIDER_CALLS_PER_LOGICAL_TRANSPORT = len(RETRY_DELAYS_SECONDS) + 1


class TransportClass(str, Enum):
    SUCCESSFUL_MODEL_RESPONSE = "SUCCESSFUL_MODEL_RESPONSE"
    HTTP_429_RETRYABLE = "HTTP_429_RETRYABLE"
    HTTP_4XX_FATAL_FOR_ANGLE = "HTTP_4XX_FATAL_FOR_ANGLE"
    HTTP_5XX_TRANSPORT_FAILURE = "HTTP_5XX_TRANSPORT_FAILURE"
    PROVIDER_SSE_RETRYABLE_ERROR = "PROVIDER_SSE_RETRYABLE_ERROR"
    PROVIDER_SSE_FATAL_ERROR = "PROVIDER_SSE_FATAL_ERROR"
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


@dataclass(frozen=True)
class TransportFailureEvidence:
    """Non-secret evidence for a transport failure, kept for later diagnosis.

    A failure is the one case where nothing is returned to the caller, so the
    only record of what the provider did is this. It carries no credential:
    the API key travels in a request header that is never captured, and
    response headers are filtered through :data:`ALLOWED_HEADERS`.
    """

    classification: TransportClass
    retryable: bool
    request_sha256: str
    http_status: int | None
    response_headers: dict[str, str]
    response_bytes: int
    response_sha256: str
    elapsed_ms: int
    provider_run_occurred: bool
    retry_ordinal: int | None = None
    provider_error_code: int | None = None
    provider_error_type: str | None = None
    #: Development-only. ``None`` unless raw capture was explicitly enabled.
    raw_response: bytes | None = None

    def to_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "classification": self.classification.value,
            "retryable": self.retryable,
            "request_sha256": self.request_sha256,
            "http_status": self.http_status,
            "response_headers": self.response_headers,
            "response_bytes": self.response_bytes,
            "response_sha256": self.response_sha256,
            "elapsed_ms": self.elapsed_ms,
            "provider_run_occurred": self.provider_run_occurred,
            "retry_ordinal": self.retry_ordinal,
        }
        if self.provider_error_code is not None:
            record["provider_error_code"] = self.provider_error_code
        if self.provider_error_type is not None:
            record["provider_error_type"] = self.provider_error_type
        if self.raw_response is not None:
            record["raw_response_development_only"] = self.raw_response.decode("utf-8", "replace")
        return record


#: Transport-level conditions the bounded retry schedule may repeat.
#:
#: ``MALFORMED_SSE`` remains retryable from v1.2.1. A syntactically valid
#: provider error carried inside an HTTP-200 SSE stream is classified
#: separately: embedded 429/5xx errors may retry, while all other embedded
#: provider errors fail closed without becoming model output.
RETRYABLE_TRANSPORT_CLASSES = frozenset(
    {
        TransportClass.HTTP_429_RETRYABLE.value,
        TransportClass.HTTP_5XX_TRANSPORT_FAILURE.value,
        TransportClass.CONNECT_FAILURE.value,
        TransportClass.TIMEOUT.value,
        TransportClass.STREAM_INCOMPLETE.value,
        TransportClass.MALFORMED_SSE.value,
    }
)

PROVIDER_SSE_RETRYABLE_CLASSES = frozenset({TransportClass.PROVIDER_SSE_RETRYABLE_ERROR.value})


def _is_retryable(classification: TransportClass) -> bool:
    return (
        classification.value in RETRYABLE_TRANSPORT_CLASSES
        or classification.value in PROVIDER_SSE_RETRYABLE_CLASSES
    )


@dataclass(frozen=True)
class _ProviderSSEError:
    code: int | None
    error_type: str | None

    @property
    def retryable(self) -> bool:
        return self.code == 429 or (self.code is not None and 500 <= self.code < 600)


def _allowed_headers(headers: Any) -> dict[str, str]:
    """Keep only the allow-listed response headers. Never any request header."""
    if headers is None:
        return {}
    return {k.lower(): v for k, v in headers.items() if k.lower() in ALLOWED_HEADERS}


def _read_error_body(exc: urllib.error.HTTPError) -> bytes:
    """Best-effort read of an error body; a body that cannot be read is empty."""
    try:
        return bytes(exc.read())
    except Exception:  # pragma: no cover - defensive; urllib may have closed it
        return b""


def canonical_request_body(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _data_payloads(raw: bytes) -> list[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransportError("MALFORMED_SSE") from exc
    payloads: list[str] = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        data_lines = [line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")]
        if data_lines:
            payloads.append("\n".join(data_lines))
    return payloads


def _provider_sse_error(raw: bytes) -> _ProviderSSEError | None:
    try:
        payloads = _data_payloads(raw)
    except TransportError:
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
        if not isinstance(error, dict):
            return _ProviderSSEError(None, None)
        code_value = error.get("code")
        code = (
            code_value if isinstance(code_value, int) and not isinstance(code_value, bool) else None
        )
        type_value = error.get("type")
        error_type = type_value if isinstance(type_value, str) else None
        return _ProviderSSEError(code, error_type)
    return None


def _read_sse_until_done(response: Any, raw: bytearray) -> bool:
    """Read exact SSE bytes through the protocol terminator, never waiting for HTTP EOF."""
    readline = getattr(response, "readline", None)
    if not callable(readline):
        # Compatibility for deterministic test doubles. Real urllib responses
        # expose ``readline`` and always take the incremental path below.
        raw.extend(response.read())
        try:
            return "[DONE]" in _data_payloads(bytes(raw))
        except TransportError:
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

    def __init__(
        self,
        *,
        api_key_env: str = "NVIDIA_API_KEY",
        timeout: int = 120,
        capture_raw_response: bool = False,
        before_provider_call: Callable[[], None] | None = None,
    ) -> None:
        self.api_key_env = api_key_env
        self.timeout = timeout
        #: Development-only raw-byte capture. Off by default, and raw provider
        #: bytes are never part of normal claim-bearing evidence.
        self.capture_raw_response = capture_raw_response
        self.before_provider_call = before_provider_call
        self.last_evidence: TransportEvidence | None = None
        self.transport_failures: list[TransportFailureEvidence] = []

    @property
    def provider_run_occurred(self) -> bool:
        return bool(self.last_evidence and self.last_evidence.provider_run_occurred)

    def _record_failure(
        self,
        classification: TransportClass,
        *,
        request_sha256: str,
        started: float,
        http_status: int | None = None,
        response_headers: dict[str, str] | None = None,
        raw: bytes = b"",
        provider_error_code: int | None = None,
        provider_error_type: str | None = None,
    ) -> TransportError:
        """Record non-secret failure evidence and return the error to raise.

        ``provider_run_occurred`` is derived here the same way it is for a
        success: from whether the provider actually answered. A status line or
        response bytes mean it did, even when the stream was unusable.
        """
        evidence = TransportFailureEvidence(
            classification=classification,
            retryable=_is_retryable(classification),
            request_sha256=request_sha256,
            http_status=http_status,
            response_headers=response_headers or {},
            response_bytes=len(raw),
            response_sha256=hashlib.sha256(raw).hexdigest(),
            elapsed_ms=int((time.monotonic() - started) * 1000),
            provider_run_occurred=http_status is not None or bool(raw),
            provider_error_code=provider_error_code,
            provider_error_type=provider_error_type,
            raw_response=raw if (self.capture_raw_response and raw) else None,
        )
        self.transport_failures.append(evidence)
        return TransportError(classification.value)

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
        request_sha256 = hashlib.sha256(request_body).hexdigest()
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
        if self.before_provider_call is not None:
            self.before_provider_call()

        status: int | None = None
        headers: dict[str, str] = {}
        raw_buffer = bytearray()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = int(response.status)
                headers = _allowed_headers(response.headers)
                done = _read_sse_until_done(response, raw_buffer)
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
            raise self._record_failure(
                cls,
                request_sha256=request_sha256,
                started=started,
                http_status=int(exc.code),
                response_headers=_allowed_headers(exc.headers),
                raw=_read_error_body(exc),
            ) from None
        except TimeoutError:
            raise self._record_failure(
                TransportClass.TIMEOUT,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=headers,
                raw=bytes(raw_buffer),
            ) from None
        except OSError:
            raise self._record_failure(
                TransportClass.CONNECT_FAILURE,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=headers,
                raw=bytes(raw_buffer),
            ) from None

        raw = bytes(raw_buffer)
        provider_error = _provider_sse_error(raw)
        if provider_error is not None:
            if not done:
                raise self._record_failure(
                    TransportClass.STREAM_INCOMPLETE,
                    request_sha256=request_sha256,
                    started=started,
                    http_status=status,
                    response_headers=headers,
                    raw=raw,
                )
            classification = (
                TransportClass.PROVIDER_SSE_RETRYABLE_ERROR
                if provider_error.retryable
                else TransportClass.PROVIDER_SSE_FATAL_ERROR
            )
            raise self._record_failure(
                classification,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=headers,
                raw=raw,
                provider_error_code=provider_error.code,
                provider_error_type=provider_error.error_type,
            ) from None

        try:
            content, model, reconstructed_done = reconstruct_sse(raw)
        except TransportError:
            # The parser still refuses malformed model-response frames. Provider
            # error frames are separated above and are never coerced into model output.
            raise self._record_failure(
                TransportClass.MALFORMED_SSE,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=headers,
                raw=raw,
            ) from None
        if not done or not reconstructed_done:
            raise self._record_failure(
                TransportClass.STREAM_INCOMPLETE,
                request_sha256=request_sha256,
                started=started,
                http_status=status,
                response_headers=headers,
                raw=raw,
            )
        if status is None:  # pragma: no cover - urlopen response always carries a status
            raise AssertionError("successful provider response missing HTTP status")
        evidence = TransportEvidence(
            TransportClass.SUCCESSFUL_MODEL_RESPONSE,
            request_body,
            request_sha256,
            status,
            headers,
            raw,
            content,
            model,
            reconstructed_done,
            int((time.monotonic() - started) * 1000),
            hashlib.sha256(raw).hexdigest(),
            True,
        )
        self.last_evidence = evidence
        return evidence

    def complete_with_retries(self, body: dict[str, Any]) -> TransportEvidence:
        """Use the frozen deterministic 1s/2s schedule for transport failures only.

        The schedule, delays and ceiling of three provider calls per logical
        transport operation are unchanged. Provider-side retryable SSE error
        frames now share that existing bounded retry budget; they do not become
        model output or consume adversarial attempts.
        """
        for retry, delay in enumerate((*RETRY_DELAYS_SECONDS, 0)):
            try:
                return self.complete_body(body)
            except TransportError as exc:
                self._stamp_retry_ordinal(retry)
                retryable = (
                    str(exc) in RETRYABLE_TRANSPORT_CLASSES
                    or str(exc) in PROVIDER_SSE_RETRYABLE_CLASSES
                )
                if not retryable or retry == len(RETRY_DELAYS_SECONDS):
                    raise
                time.sleep(delay)
        raise AssertionError("unreachable")

    def _stamp_retry_ordinal(self, retry: int) -> None:
        """Attach the attempt ordinal to the failure record just written."""
        if self.transport_failures and self.transport_failures[-1].retry_ordinal is None:
            self.transport_failures[-1] = replace(self.transport_failures[-1], retry_ordinal=retry)
