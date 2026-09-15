from __future__ import annotations

import hashlib
import json

import pytest

from oat.adversaries.provider import ProviderAdversary, ScriptedTransport, TransportError
from oat.veip.transport import (
    MAX_PROVIDER_CALLS_PER_LOGICAL_TRANSPORT,
    RETRYABLE_TRANSPORT_CLASSES,
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


# --- v1.2.1 transport hardening: MALFORMED_SSE is a retryable transport failure ---
#
# The repair is deliberately narrow. reconstruct_sse() still refuses a
# malformed stream; only the retry layer's classification changed, so the whole
# provider call may be repeated under the schedule that already existed.


class _FakeResponse:
    def __init__(self, raw: bytes, status: int = 200, headers: dict[str, str] | None = None):
        self._raw = raw
        self.status = status
        self.headers = headers if headers is not None else {"nvcf-status": "fulfilled"}

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def _drive(monkeypatch, outcomes):
    """Run complete_with_retries over scripted per-call outcomes.

    Returns (result_or_error, provider_call_count, sleep_schedule).
    """
    transport = NvidiaSSETransport()
    remaining = list(outcomes)
    calls: list[int] = []
    sleeps: list[int] = []
    success = TransportEvidence(
        TransportClass.SUCCESSFUL_MODEL_RESPONSE,
        b"{}",
        "req-digest",
        200,
        {},
        b"data: [DONE]\n\n",
        "ok",
        "nvidia/nemotron-3-ultra-550b-a55b",
        True,
        1,
        "resp-digest",
        True,
    )

    def fake(_body):
        calls.append(1)
        outcome = remaining.pop(0)
        if outcome is None:
            return success
        raise TransportError(outcome)

    monkeypatch.setattr(transport, "complete_body", fake)
    monkeypatch.setattr("oat.veip.transport.time.sleep", sleeps.append)
    try:
        return transport.complete_with_retries({}), len(calls), sleeps
    except TransportError as exc:
        return exc, len(calls), sleeps


def test_a_malformed_sse_then_success_costs_one_retry(monkeypatch):
    result, provider_calls, sleeps = _drive(monkeypatch, ["MALFORMED_SSE", None])
    assert isinstance(result, TransportEvidence)
    assert result.classification is TransportClass.SUCCESSFUL_MODEL_RESPONSE
    assert provider_calls == 2
    assert sleeps == [1]


def test_b_two_malformed_sse_then_success_uses_full_schedule(monkeypatch):
    result, provider_calls, sleeps = _drive(monkeypatch, ["MALFORMED_SSE", "MALFORMED_SSE", None])
    assert isinstance(result, TransportEvidence)
    assert result.classification is TransportClass.SUCCESSFUL_MODEL_RESPONSE
    assert provider_calls == 3
    assert sleeps == [1, 2]


def test_c_three_malformed_sse_exhausts_the_bound_and_fails(monkeypatch):
    result, provider_calls, sleeps = _drive(
        monkeypatch, ["MALFORMED_SSE", "MALFORMED_SSE", "MALFORMED_SSE"]
    )
    assert isinstance(result, TransportError)
    assert str(result) == "MALFORMED_SSE"
    assert provider_calls == 3 == MAX_PROVIDER_CALLS_PER_LOGICAL_TRANSPORT
    assert sleeps == [1, 2]


def test_c_exhausted_malformed_sse_is_never_recast_as_a_result(monkeypatch):
    result, _calls, _sleeps = _drive(
        monkeypatch, ["MALFORMED_SSE", "MALFORMED_SSE", "MALFORMED_SSE"]
    )
    # It surfaces as a transport failure, not as success, empty content,
    # model output, negative evidence, or a consumed adversarial attempt.
    assert isinstance(result, TransportError)
    assert not isinstance(result, TransportEvidence)
    assert str(result) == TransportClass.MALFORMED_SSE.value


def test_d_http_4xx_remains_fatal_for_the_angle(monkeypatch):
    result, provider_calls, sleeps = _drive(monkeypatch, ["HTTP_4XX_FATAL_FOR_ANGLE"])
    assert isinstance(result, TransportError)
    assert str(result) == "HTTP_4XX_FATAL_FOR_ANGLE"
    assert provider_calls == 1
    assert sleeps == []
    assert TransportClass.HTTP_4XX_FATAL_FOR_ANGLE.value not in RETRYABLE_TRANSPORT_CLASSES


@pytest.mark.parametrize(
    "classification",
    [
        "HTTP_429_RETRYABLE",
        "HTTP_5XX_TRANSPORT_FAILURE",
        "CONNECT_FAILURE",
        "TIMEOUT",
        "STREAM_INCOMPLETE",
    ],
)
def test_e_preexisting_retryable_classes_keep_their_behavior(monkeypatch, classification):
    result, provider_calls, sleeps = _drive(monkeypatch, [classification, None])
    assert isinstance(result, TransportEvidence)
    assert provider_calls == 2
    assert sleeps == [1]

    exhausted, provider_calls, sleeps = _drive(monkeypatch, [classification] * 3)
    assert isinstance(exhausted, TransportError)
    assert str(exhausted) == classification
    assert provider_calls == 3
    assert sleeps == [1, 2]


def test_e_model_response_malformed_is_not_silently_made_retryable():
    # Section 9: out of scope for this repair. It must not join the set.
    assert TransportClass.MODEL_RESPONSE_MALFORMED.value not in RETRYABLE_TRANSPORT_CLASSES
    assert (
        frozenset(
            {
                "HTTP_429_RETRYABLE",
                "HTTP_5XX_TRANSPORT_FAILURE",
                "CONNECT_FAILURE",
                "TIMEOUT",
                "STREAM_INCOMPLETE",
                "MALFORMED_SSE",
            }
        )
        == RETRYABLE_TRANSPORT_CLASSES
    )


def test_f_parser_still_fails_closed_on_malformed_sse():
    # Retryability is a transport decision. The grammar is unchanged: none of
    # these become acceptable, and none is coerced into empty content.
    for raw in (
        b"data: nope\n\n",
        b"data: {not json}\n\n",
        b'data: {"choices": "not-a-list"}\n\n',
        b"data: \xff\xfe\n\n",
    ):
        with pytest.raises(TransportError, match="MALFORMED_SSE"):
            reconstruct_sse(raw)


def test_f_malformed_sse_from_a_real_response_is_classified_and_retryable(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "unit-test-key-not-a-real-secret")
    transport = NvidiaSSETransport()
    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen",
        lambda *_a, **_k: _FakeResponse(b"data: nope\n\n"),
    )
    with pytest.raises(TransportError, match="MALFORMED_SSE"):
        transport.complete_body({"model": "m", "messages": []})

    assert len(transport.transport_failures) == 1
    failure = transport.transport_failures[0]
    assert failure.classification is TransportClass.MALFORMED_SSE
    assert failure.retryable is True
    assert failure.http_status == 200
    assert failure.response_headers == {"nvcf-status": "fulfilled"}
    assert failure.response_bytes == len(b"data: nope\n\n")
    assert failure.response_sha256 == hashlib.sha256(b"data: nope\n\n").hexdigest()
    assert failure.raw_response is None  # development-only capture is off by default


def test_g_provider_run_occurred_is_derived_from_recorded_response_evidence(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "unit-test-key-not-a-real-secret")
    transport = NvidiaSSETransport()
    assert transport.provider_run_occurred is False

    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen",
        lambda *_a, **_k: _FakeResponse(b"data: nope\n\n"),
    )
    with pytest.raises(TransportError, match="MALFORMED_SSE"):
        transport.complete_body({"model": "m", "messages": []})
    # A response did arrive, so the failure record says the provider ran.
    assert transport.transport_failures[-1].provider_run_occurred is True
    # No successful model response was recorded, so the transport still does
    # not claim one. The flag is never declared, only derived.
    assert transport.provider_run_occurred is False

    def refuse(*_a, **_k):
        raise OSError("no route")

    monkeypatch.setattr("oat.veip.transport.urllib.request.urlopen", refuse)
    with pytest.raises(TransportError, match="CONNECT_FAILURE"):
        transport.complete_body({"model": "m", "messages": []})
    assert transport.transport_failures[-1].provider_run_occurred is False


def test_g_retry_ordinal_is_recorded_across_the_bounded_schedule(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "unit-test-key-not-a-real-secret")
    transport = NvidiaSSETransport()
    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen",
        lambda *_a, **_k: _FakeResponse(b"data: nope\n\n"),
    )
    monkeypatch.setattr("oat.veip.transport.time.sleep", lambda _d: None)
    with pytest.raises(TransportError, match="MALFORMED_SSE"):
        transport.complete_with_retries({"model": "m", "messages": []})
    assert [f.retry_ordinal for f in transport.transport_failures] == [0, 1, 2]
    assert len(transport.transport_failures) == MAX_PROVIDER_CALLS_PER_LOGICAL_TRANSPORT


def test_h_no_credential_material_appears_in_transport_evidence(monkeypatch):
    secret = "nvapi-UNIT-TEST-SENTINEL-0123456789"
    monkeypatch.setenv("NVIDIA_API_KEY", secret)
    transport = NvidiaSSETransport(capture_raw_response=True)
    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen",
        lambda *_a, **_k: _FakeResponse(
            b"data: nope\n\n",
            headers={"nvcf-status": "fulfilled", "authorization": f"Bearer {secret}"},
        ),
    )
    with pytest.raises(TransportError, match="MALFORMED_SSE"):
        transport.complete_body({"model": "m", "messages": []})

    serialized = json.dumps(transport.transport_failures[-1].to_dict())
    assert secret not in serialized
    assert "authorization" not in serialized.lower()
    assert "nvapi-" not in serialized
    # Raw capture is opt-in and development-only; when on it is clearly labelled.
    assert "raw_response_development_only" in serialized
