from __future__ import annotations

import hashlib
import json

import pytest

from oat.adversaries.provider import TransportError
from oat.veip.transport import (
    PROVIDER_SSE_RETRYABLE_CLASSES,
    RETRYABLE_TRANSPORT_CLASSES,
    NvidiaSSETransport,
    TransportClass,
    reconstruct_sse,
)


class _LineResponse:
    def __init__(
        self,
        raw: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        tail: bytes = b"",
    ) -> None:
        self._lines = (raw + tail).splitlines(keepends=True)
        self._index = 0
        self.status = status
        self.headers = headers or {"nvcf-status": "fulfilled"}
        self.read_called = False

    def readline(self) -> bytes:
        if self._index >= len(self._lines):
            return b""
        line = self._lines[self._index]
        self._index += 1
        return line

    def read(self) -> bytes:
        self.read_called = True
        raise AssertionError("incremental live path must not call response.read()")

    def __enter__(self) -> _LineResponse:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def _success_stream(content: str = "OAT_TRANSPORT_REACHABLE") -> bytes:
    event = {
        "model": "nvidia/nemotron-3-ultra-550b-a55b",
        "choices": [{"delta": {"content": content}}],
    }
    return (
        b"data: "
        + json.dumps(event, separators=(",", ":")).encode()
        + b"\n\n"
        + b"data: [DONE]\n\n"
    )


def _provider_error_stream(code: int, error_type: str, message: str) -> bytes:
    event = {"error": {"message": message, "type": error_type, "code": code}}
    return (
        b"data: "
        + json.dumps(event, separators=(",", ":")).encode()
        + b"\n\n"
        + b"data: [DONE]\n\n"
    )


def test_incremental_acquisition_stops_at_done_without_waiting_for_http_eof(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "unit-test-key-not-a-real-secret")
    raw = _success_stream()
    response = _LineResponse(raw, tail=b"SHOULD_NOT_BE_READ\n")
    monkeypatch.setattr("oat.veip.transport.urllib.request.urlopen", lambda *_a, **_k: response)

    evidence = NvidiaSSETransport().complete_body({"model": "m", "messages": []})

    assert evidence.classification is TransportClass.SUCCESSFUL_MODEL_RESPONSE
    assert evidence.reconstructed_content == "OAT_TRANSPORT_REACHABLE"
    assert evidence.done_seen is True
    assert evidence.raw_sse == raw
    assert b"SHOULD_NOT_BE_READ" not in evidence.raw_sse
    assert response.read_called is False


def test_http_200_sse_503_is_typed_provider_failure_not_malformed(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "unit-test-key-not-a-real-secret")
    raw = _provider_error_stream(503, "service_unavailable", "Service temporarily overloaded")
    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen",
        lambda *_a, **_k: _LineResponse(raw),
    )
    transport = NvidiaSSETransport()

    with pytest.raises(TransportError, match="PROVIDER_SSE_RETRYABLE_ERROR"):
        transport.complete_body({"model": "m", "messages": []})

    failure = transport.transport_failures[-1]
    assert failure.classification is TransportClass.PROVIDER_SSE_RETRYABLE_ERROR
    assert failure.retryable is True
    assert failure.http_status == 200
    assert failure.provider_error_code == 503
    assert failure.provider_error_type == "service_unavailable"
    assert failure.provider_run_occurred is True
    assert failure.response_sha256 == hashlib.sha256(raw).hexdigest()


def test_non_retryable_provider_sse_error_fails_closed(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "unit-test-key-not-a-real-secret")
    raw = _provider_error_stream(400, "bad_request", "bad request")
    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen",
        lambda *_a, **_k: _LineResponse(raw),
    )
    transport = NvidiaSSETransport()

    with pytest.raises(TransportError, match="PROVIDER_SSE_FATAL_ERROR"):
        transport.complete_body({"model": "m", "messages": []})

    failure = transport.transport_failures[-1]
    assert failure.classification is TransportClass.PROVIDER_SSE_FATAL_ERROR
    assert failure.retryable is False
    assert failure.provider_error_code == 400


def test_provider_sse_503_uses_existing_bounded_retry_schedule(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "unit-test-key-not-a-real-secret")
    outcomes = iter(
        [
            _LineResponse(_provider_error_stream(503, "service_unavailable", "overloaded")),
            _LineResponse(_success_stream("OK")),
        ]
    )
    sleeps: list[int] = []
    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen", lambda *_a, **_k: next(outcomes)
    )
    monkeypatch.setattr("oat.veip.transport.time.sleep", sleeps.append)
    transport = NvidiaSSETransport()

    evidence = transport.complete_with_retries({"model": "m", "messages": []})

    assert evidence.reconstructed_content == "OK"
    assert sleeps == [1]
    assert len(transport.transport_failures) == 1
    assert transport.transport_failures[0].retry_ordinal == 0


def test_provider_sse_retry_class_does_not_redefine_preexisting_retry_set():
    assert TransportClass.PROVIDER_SSE_RETRYABLE_ERROR.value not in RETRYABLE_TRANSPORT_CLASSES
    assert TransportClass.PROVIDER_SSE_RETRYABLE_ERROR.value in PROVIDER_SSE_RETRYABLE_CLASSES
    assert TransportClass.PROVIDER_SSE_FATAL_ERROR.value not in PROVIDER_SSE_RETRYABLE_CLASSES


def test_malformed_sse_remains_malformed_and_never_becomes_provider_error():
    with pytest.raises(TransportError, match="MALFORMED_SSE"):
        reconstruct_sse(b"data: nope\n\ndata: [DONE]\n\n")


def test_timeout_after_http_headers_preserves_partial_response_evidence(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "unit-test-key-not-a-real-secret")

    class _TimeoutResponse(_LineResponse):
        def readline(self) -> bytes:
            if self._index == 0:
                self._index += 1
                return b'data: {"choices":[]}\n'
            raise TimeoutError("timed out")

    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen",
        lambda *_a, **_k: _TimeoutResponse(b""),
    )
    transport = NvidiaSSETransport()

    with pytest.raises(TransportError, match="TIMEOUT"):
        transport.complete_body({"model": "m", "messages": []})

    failure = transport.transport_failures[-1]
    assert failure.http_status == 200
    assert failure.response_bytes > 0
    assert failure.provider_run_occurred is True
