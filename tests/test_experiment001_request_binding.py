from __future__ import annotations

import io
import json
import urllib.error
from typing import Any

import pytest

from oat.adversaries.provider import TransportError
from oat.veip.execution_path import BudgetLedger
from oat.veip.experiment001 import (
    EXPERIMENT_SEED,
    MAX_TOKENS,
    NVIDIA_MODEL,
    feedback_for_round,
    make_budgeted_transport,
    render_provider_request,
)
from oat.veip.prompt import SYSTEM_PROMPT
from oat.veip.transport import ENDPOINT


def _angle(attack_id: str = "ATK-TEST") -> dict[str, Any]:
    return {
        "attack_id": attack_id,
        "family": "TEST_FAMILY",
        "falsifier_id": "FALS-VEIP-P-02",
        "target_components": ["veip-sdk"],
        "allowed_attacker_capabilities": ["candidate construction"],
        "prohibited_attacker_capabilities": ["falsifier mutation"],
    }


def _falsifier() -> dict[str, Any]:
    return {
        "property_id": "VEIP-P-02",
        "counterexample_condition": "frozen condition",
        "predicate": "frozen predicate",
        "required_observables": ["decision_sequence"],
    }


def test_frozen_request_body_is_exactly_bound() -> None:
    rendered = render_provider_request(
        _angle(),
        _falsifier(),
        round_number=1,
        attempt_number=1,
    )

    assert set(rendered.body) == {
        "model",
        "messages",
        "temperature",
        "top_p",
        "max_tokens",
        "stream",
        "seed",
    }

    assert rendered.body["model"] == NVIDIA_MODEL
    assert rendered.body["temperature"] == 0.0
    assert rendered.body["top_p"] == 1.0
    assert rendered.body["max_tokens"] == MAX_TOKENS
    assert rendered.body["stream"] is True
    assert rendered.body["seed"] == EXPERIMENT_SEED

    assert rendered.body["messages"][0] == {
        "role": "system",
        "content": SYSTEM_PROMPT,
    }
    assert rendered.body["messages"][1]["role"] == "user"

    reconstructed = (
        rendered.body["messages"][0]["content"] + "\n\n" + rendered.body["messages"][1]["content"]
    ).encode("utf-8")

    assert reconstructed == rendered.prompt_bytes

    assert rendered.request_sha256 == __import__("hashlib").sha256(rendered.body_bytes).hexdigest()


def test_round_one_is_blind_even_if_history_is_supplied() -> None:
    history = [
        {
            "attack_id": "ATK-TEST",
            "round": 1,
            "attempt": 1,
            "disposition": "UNEVALUABLE",
            "reason_category": "WITNESS_SCHEMA_INVALID",
            "reason": "DO NOT LEAK THIS RAW REASON",
        }
    ]

    rendered = render_provider_request(
        _angle(),
        _falsifier(),
        round_number=1,
        attempt_number=2,
        history=history,
    )

    user = rendered.body["messages"][1]["content"]

    assert rendered.feedback == ()
    assert "FEEDBACK ON YOUR PREVIOUS ROUND" not in user
    assert "DO NOT LEAK THIS RAW REASON" not in user
    assert "WITNESS_SCHEMA_INVALID" not in user


def test_round_two_feedback_is_same_angle_and_closed_projection() -> None:
    history = [
        {
            "attack_id": "ATK-TEST",
            "round": 1,
            "attempt": 2,
            "disposition": "NOT_A_COUNTEREXAMPLE",
            "reason": "never expose",
        },
        {
            "attack_id": "ATK-TEST",
            "round": 1,
            "attempt": 1,
            "disposition": "UNEVALUABLE",
            "reason_category": "WITNESS_SCHEMA_INVALID",
            "reason": "schema internals must not leak",
        },
        {
            "attack_id": "OTHER-ANGLE",
            "round": 1,
            "attempt": 1,
            "disposition": "COUNTEREXAMPLE_VALIDATED",
        },
    ]

    projected = feedback_for_round(
        history,
        attack_id="ATK-TEST",
        round_number=2,
    )

    assert projected == [
        {
            "attempt": "1",
            "disposition": "UNEVALUABLE",
            "reason_category": "WITNESS_SCHEMA_INVALID",
        },
        {
            "attempt": "2",
            "disposition": "NOT_A_COUNTEREXAMPLE",
        },
    ]

    rendered = render_provider_request(
        _angle(),
        _falsifier(),
        round_number=2,
        attempt_number=1,
        history=history,
    )

    user = rendered.body["messages"][1]["content"]

    assert "attempt 1: UNEVALUABLE, WITNESS_SCHEMA_INVALID" in user
    assert "attempt 2: NOT_A_COUNTEREXAMPLE" in user
    assert "schema internals must not leak" not in user
    assert "OTHER-ANGLE" not in user


def test_round_three_receives_immediately_prior_round_only() -> None:
    history = [
        {
            "attack_id": "ATK-TEST",
            "round": 1,
            "attempt": 1,
            "disposition": "UNEVALUABLE",
            "reason_category": "RESPONSE_MALFORMED",
        },
        {
            "attack_id": "ATK-TEST",
            "round": 2,
            "attempt": 7,
            "disposition": "UNEVALUABLE",
            "reason_category": "OBSERVABLE_MISSING",
        },
    ]

    rendered = render_provider_request(
        _angle(),
        _falsifier(),
        round_number=3,
        attempt_number=1,
        history=history,
    )

    user = rendered.body["messages"][1]["content"]

    assert "attempt 7: UNEVALUABLE, OBSERVABLE_MISSING" in user
    assert "RESPONSE_MALFORMED" not in user


def test_invalid_feedback_category_collapses_to_other() -> None:
    history = [
        {
            "attack_id": "ATK-TEST",
            "round": 1,
            "attempt": 1,
            "disposition": "UNEVALUABLE",
            "reason_category": "RAW_EXCEPTION_TEXT",
        }
    ]

    assert feedback_for_round(
        history,
        attack_id="ATK-TEST",
        round_number=2,
    ) == [
        {
            "attempt": "1",
            "disposition": "UNEVALUABLE",
            "reason_category": "OTHER",
        }
    ]


class _FakeResponse:
    def __init__(self, raw: bytes) -> None:
        self.status = 200
        self.headers = {
            "content-type": "text/event-stream",
            "nvcf-status": "fulfilled",
            "nvcf-reqid": "offline-test",
        }
        self._raw = raw

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _success_sse() -> bytes:
    event = {
        "model": NVIDIA_MODEL,
        "choices": [
            {
                "index": 0,
                "delta": {"content": '{"offline":true}'},
                "finish_reason": None,
            }
        ],
    }
    stop = {
        "model": NVIDIA_MODEL,
        "choices": [
            {
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }
        ],
    }
    return (f"data: {json.dumps(event)}\n\ndata: {json.dumps(stop)}\n\ndata: [DONE]\n\n").encode()


def _http_500() -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        ENDPOINT,
        500,
        "offline injected 500",
        {},
        io.BytesIO(b"offline failure"),
    )


def test_missing_local_secret_consumes_no_provider_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = BudgetLedger()
    transport = make_budgeted_transport(
        ledger,
        api_key_env="OAT_TEST_MISSING_KEY",
    )

    monkeypatch.delenv("OAT_TEST_MISSING_KEY", raising=False)

    with pytest.raises(TransportError, match="missing runtime secret"):
        transport.complete_with_retries(
            render_provider_request(
                _angle(),
                _falsifier(),
                round_number=1,
                attempt_number=1,
            ).body
        )

    assert ledger.physical_provider_calls == 0
    assert ledger.reserved_output_token_units == 0
    assert ledger.logical_adversarial_attempts == 0


def test_retry_path_counts_physical_calls_not_logical_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = BudgetLedger()
    transport = make_budgeted_transport(
        ledger,
        api_key_env="OAT_TEST_NVIDIA_KEY",
    )

    monkeypatch.setenv("OAT_TEST_NVIDIA_KEY", "offline-not-a-real-secret")
    monkeypatch.setattr("oat.veip.transport.time.sleep", lambda _: None)

    calls: list[object] = [
        _http_500(),
        _FakeResponse(_success_sse()),
    ]

    def fake_urlopen(*args: object, **kwargs: object) -> _FakeResponse:
        item = calls.pop(0)
        if isinstance(item, BaseException):
            raise item
        assert isinstance(item, _FakeResponse)
        return item

    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen",
        fake_urlopen,
    )

    rendered = render_provider_request(
        _angle(),
        _falsifier(),
        round_number=1,
        attempt_number=1,
    )

    evidence = transport.complete_with_retries(rendered.body)

    assert evidence.reconstructed_content == '{"offline":true}'
    assert ledger.physical_provider_calls == 2
    assert ledger.reserved_output_token_units == 8192
    assert ledger.logical_adversarial_attempts == 0

    ledger.consume_logical_attempt()

    assert ledger.logical_adversarial_attempts == 1
    assert len(transport.transport_failures) == 1
    assert transport.transport_failures[0].retry_ordinal == 0


def test_three_transport_failures_consume_three_physical_calls_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = BudgetLedger()
    transport = make_budgeted_transport(
        ledger,
        api_key_env="OAT_TEST_NVIDIA_KEY",
    )

    monkeypatch.setenv("OAT_TEST_NVIDIA_KEY", "offline-not-a-real-secret")
    monkeypatch.setattr("oat.veip.transport.time.sleep", lambda _: None)

    calls: list[object] = [
        _http_500(),
        _http_500(),
        _http_500(),
    ]

    def fake_urlopen(*args: object, **kwargs: object) -> _FakeResponse:
        item = calls.pop(0)
        if isinstance(item, BaseException):
            raise item
        assert isinstance(item, _FakeResponse)
        return item

    monkeypatch.setattr(
        "oat.veip.transport.urllib.request.urlopen",
        fake_urlopen,
    )

    rendered = render_provider_request(
        _angle(),
        _falsifier(),
        round_number=1,
        attempt_number=1,
    )

    with pytest.raises(
        TransportError,
        match="HTTP_5XX_TRANSPORT_FAILURE",
    ):
        transport.complete_with_retries(rendered.body)

    assert ledger.physical_provider_calls == 3
    assert ledger.reserved_output_token_units == 12_288
    assert ledger.logical_adversarial_attempts == 0
    assert [x.retry_ordinal for x in transport.transport_failures] == [
        0,
        1,
        2,
    ]


def test_canonical_request_never_contains_authorization_secret() -> None:
    rendered = render_provider_request(
        _angle(),
        _falsifier(),
        round_number=1,
        attempt_number=1,
    )

    text = rendered.body_bytes.decode("utf-8")

    assert "Authorization" not in text
    assert "Bearer " not in text
    assert "nvapi-" not in text
