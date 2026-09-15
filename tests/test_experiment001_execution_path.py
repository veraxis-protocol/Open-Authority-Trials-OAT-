from __future__ import annotations

import pytest

from oat.veip.execution_path import (
    LOGICAL_ADVERSARIAL_ATTEMPT_CEILING,
    OUTPUT_TOKEN_UNITS_PER_PROVIDER_CALL,
    PHYSICAL_PROVIDER_CALL_CEILING,
    RESERVED_OUTPUT_TOKEN_CEILING,
    UNEVALUABLE_REASON_CATEGORIES,
    BudgetExhausted,
    BudgetLedger,
    EvaluationStage,
    reason_category,
)


def test_reason_category_vocabulary_is_exact() -> None:
    assert UNEVALUABLE_REASON_CATEGORIES == (
        "PROTOCOL_VIOLATION",
        "RESPONSE_MALFORMED",
        "WITNESS_SCHEMA_INVALID",
        "OBSERVABLE_MISSING",
        "SUBJECT_INVOCATION_FAILED",
        "OTHER",
    )


@pytest.mark.parametrize(
    ("stage", "expected"),
    [
        (EvaluationStage.PROTOCOL_VALIDATION, "PROTOCOL_VIOLATION"),
        (EvaluationStage.RESPONSE_ENVELOPE, "RESPONSE_MALFORMED"),
        (EvaluationStage.WITNESS_ADMISSION, "WITNESS_SCHEMA_INVALID"),
        (
            EvaluationStage.SUBJECT_INVOCATION,
            "SUBJECT_INVOCATION_FAILED",
        ),
        (
            EvaluationStage.OBSERVABLE_COMPLETENESS,
            "OBSERVABLE_MISSING",
        ),
        (EvaluationStage.OTHER, "OTHER"),
    ],
)
def test_reason_category_is_stage_only(
    stage: EvaluationStage,
    expected: str,
) -> None:
    assert reason_category(stage) == expected


def test_unknown_reason_stage_is_other() -> None:
    assert reason_category("UNRECOGNIZED_STAGE") == "OTHER"


def test_retry_and_logical_attempt_counters_are_separate() -> None:
    ledger = BudgetLedger()

    ledger.reserve_provider_call()
    ledger.reserve_provider_call()
    ledger.consume_logical_attempt()

    assert ledger.logical_adversarial_attempts == 1
    assert ledger.physical_provider_calls == 2
    assert ledger.reserved_output_token_units == 8192


def test_transport_failure_need_not_consume_logical_attempt() -> None:
    ledger = BudgetLedger()

    ledger.reserve_provider_call()
    ledger.reserve_provider_call()
    ledger.reserve_provider_call()

    assert ledger.logical_adversarial_attempts == 0
    assert ledger.physical_provider_calls == 3
    assert ledger.reserved_output_token_units == 3 * 4096


def test_physical_budget_is_hard_1275_call_ceiling() -> None:
    ledger = BudgetLedger()

    for _ in range(PHYSICAL_PROVIDER_CALL_CEILING):
        ledger.reserve_provider_call()

    assert ledger.physical_provider_calls == 1275
    assert ledger.reserved_output_token_units == RESERVED_OUTPUT_TOKEN_CEILING
    assert ledger.provider_budget_exhausted is True

    with pytest.raises(
        BudgetExhausted,
        match="PHYSICAL_PROVIDER_BUDGET_EXHAUSTED",
    ):
        ledger.reserve_provider_call()

    assert ledger.physical_provider_calls == 1275
    assert ledger.reserved_output_token_units == 5_222_400


def test_every_physical_call_reserves_full_4096_units() -> None:
    ledger = BudgetLedger()

    for expected_calls in range(1, 5):
        ledger.reserve_provider_call()
        assert ledger.physical_provider_calls == expected_calls
        assert (
            ledger.reserved_output_token_units
            == expected_calls * OUTPUT_TOKEN_UNITS_PER_PROVIDER_CALL
        )


def test_logical_attempt_budget_is_separate_and_hard() -> None:
    ledger = BudgetLedger()

    for _ in range(LOGICAL_ADVERSARIAL_ATTEMPT_CEILING):
        ledger.consume_logical_attempt()

    assert ledger.logical_adversarial_attempts == 1275
    assert ledger.physical_provider_calls == 0
    assert ledger.reserved_output_token_units == 0

    with pytest.raises(
        BudgetExhausted,
        match="LOGICAL_ADVERSARIAL_ATTEMPT_BUDGET_EXHAUSTED",
    ):
        ledger.consume_logical_attempt()


def test_budget_ledger_serialization_preserves_three_counters() -> None:
    ledger = BudgetLedger()
    ledger.reserve_provider_call()
    ledger.consume_logical_attempt()

    assert ledger.to_dict() == {
        "logical_adversarial_attempts": 1,
        "physical_provider_calls": 1,
        "reserved_output_token_units": 4096,
    }
