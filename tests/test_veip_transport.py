from __future__ import annotations

import hashlib
import json

import pytest

from oat.adversaries.provider import ProviderAdversary, ScriptedTransport, TransportError
from oat.veip.transport import (
    NvidiaSSETransport,
    TransportClass,
    TransportEvidence,
    canonical_request_body,
    reconstruct_sse,
)


def _event(content: str) -> bytes:
    return (
        b"data: "
        + json.dumps(
            {
                "model": "nvidia/nemotron-3-ultra-550b-a55b",
                "choices": [{"delta": {"content": content}}],
            }
        ).encode()
        + b"\n\n"
    )


def test_split_token_sse_reconstructs_before_semantic_use():
    raw = _event("N") + _event("IM_REACHABLE") + b"data: [DONE]\n\n"
    assert reconstruct_sse(raw) == ("NIM_REACHABLE", "nvidia/nemotron-3-ultra-550b-a55b", True)


def test_request_digest_cannot_include_authorization():
    body = {"model": "m", "messages": [], "seed": 20260915}
    raw = canonical_request_body(body)
    assert b"Authorization" not in raw and b"secret" not in raw
    assert (
        hashlib.sha256(raw).hexdigest() == hashlib.sha256(canonical_request_body(body)).hexdigest()
    )


def test_live_transport_is_not_a_provider_run_before_evidence(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    transport = NvidiaSSETransport()
    assert transport.is_live is True
    assert transport.provider_run_occurred is False
    assert ProviderAdversary(transport=transport).provider_run_occurred is False
    with pytest.raises(TransportError, match="missing runtime secret"):
        transport.complete("never dispatched")
    assert transport.provider_run_occurred is False


def test_scripted_transport_never_claims_provider_run():
    assert ProviderAdversary(transport=ScriptedTransport(["x"])).provider_run_occurred is False


def test_incomplete_and_malformed_streams_fail_closed():
    assert reconstruct_sse(_event("x"))[2] is False
    with pytest.raises(TransportError, match="MALFORMED_SSE"):
        reconstruct_sse(b"data: nope\n\n")


def test_retry_schedule_applies_only_to_transport_failures(monkeypatch):
    transport = NvidiaSSETransport()
    calls = iter([TransportError("CONNECT_FAILURE"), TransportError("HTTP_429_RETRYABLE"), None])
    evidence = TransportEvidence(
        TransportClass.SUCCESSFUL_MODEL_RESPONSE,
        b"{}",
        "digest",
        200,
        {},
        b"data: [DONE]\\n\\n",
        "ok",
        "model",
        True,
        1,
        "digest",
        True,
    )

    def fake(_body):
        outcome = next(calls)
        if outcome:
            raise outcome
        return evidence

    sleeps = []
    monkeypatch.setattr(transport, "complete_body", fake)
    monkeypatch.setattr("oat.veip.transport.time.sleep", sleeps.append)
    assert transport.complete_with_retries({}) is evidence
    assert sleeps == [1, 2]

    monkeypatch.setattr(
        transport,
        "complete_body",
        lambda _body: (_ for _ in ()).throw(TransportError("HTTP_4XX_FATAL_FOR_ANGLE")),
    )
    with pytest.raises(TransportError, match="HTTP_4XX_FATAL_FOR_ANGLE"):
        transport.complete_with_retries({})
