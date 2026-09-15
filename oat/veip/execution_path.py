"""Experiment 001 execution-path controls fixed by owner disposition 001."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

PHYSICAL_PROVIDER_CALL_CEILING: Final = 1275
LOGICAL_ADVERSARIAL_ATTEMPT_CEILING: Final = 1275
OUTPUT_TOKEN_UNITS_PER_PROVIDER_CALL: Final = 4096
RESERVED_OUTPUT_TOKEN_CEILING: Final = 5_222_400

UNEVALUABLE_REASON_CATEGORIES: Final = (
    "PROTOCOL_VIOLATION",
    "RESPONSE_MALFORMED",
    "WITNESS_SCHEMA_INVALID",
    "OBSERVABLE_MISSING",
    "SUBJECT_INVOCATION_FAILED",
    "OTHER",
)


class EvaluationStage(str, Enum):
    """Stage reached before an attempt became UNEVALUABLE."""

    PROTOCOL_VALIDATION = "PROTOCOL_VALIDATION"
    RESPONSE_ENVELOPE = "RESPONSE_ENVELOPE"
    WITNESS_ADMISSION = "WITNESS_ADMISSION"
    SUBJECT_INVOCATION = "SUBJECT_INVOCATION"
    OBSERVABLE_COMPLETENESS = "OBSERVABLE_COMPLETENESS"
    OTHER = "OTHER"


_REASON_CATEGORY_BY_STAGE: Final[dict[EvaluationStage, str]] = {
    EvaluationStage.PROTOCOL_VALIDATION: "PROTOCOL_VIOLATION",
    EvaluationStage.RESPONSE_ENVELOPE: "RESPONSE_MALFORMED",
    EvaluationStage.WITNESS_ADMISSION: "WITNESS_SCHEMA_INVALID",
    EvaluationStage.SUBJECT_INVOCATION: "SUBJECT_INVOCATION_FAILED",
    EvaluationStage.OBSERVABLE_COMPLETENESS: "OBSERVABLE_MISSING",
    EvaluationStage.OTHER: "OTHER",
}


def reason_category(stage: EvaluationStage | str) -> str:
    """Return only the closed owner-authorized feedback token.

    Raw exception text is deliberately not an input to this function so it
    cannot accidentally become adversary feedback.
    """
    try:
        normalized = stage if isinstance(stage, EvaluationStage) else EvaluationStage(stage)
    except ValueError:
        return "OTHER"
    return _REASON_CATEGORY_BY_STAGE[normalized]


class BudgetExhausted(RuntimeError):
    """A frozen Experiment 001 budget cannot authorize the next operation."""


@dataclass
class BudgetLedger:
    """Keep logical attempts, physical calls and token reservations separate."""

    logical_adversarial_attempts: int = 0
    physical_provider_calls: int = 0
    reserved_output_token_units: int = 0

    @property
    def provider_budget_exhausted(self) -> bool:
        return (
            self.physical_provider_calls >= PHYSICAL_PROVIDER_CALL_CEILING
            or self.reserved_output_token_units + OUTPUT_TOKEN_UNITS_PER_PROVIDER_CALL
            > RESERVED_OUTPUT_TOKEN_CEILING
        )

    def reserve_provider_call(self) -> None:
        """Reserve one physical call immediately before outbound dispatch.

        Every authorized outbound provider request, including a retry,
        permanently reserves one physical-call unit and 4096 output-token
        units. Reservations are never refunded.
        """
        if self.provider_budget_exhausted:
            raise BudgetExhausted("PHYSICAL_PROVIDER_BUDGET_EXHAUSTED")

        self.physical_provider_calls += 1
        self.reserved_output_token_units += OUTPUT_TOKEN_UNITS_PER_PROVIDER_CALL

    def consume_logical_attempt(self) -> None:
        """Record one actual adversarial candidate attempt.

        Transport retries never call this method. A terminal transport failure
        without a model candidate therefore consumes physical-call/token
        budget but does not consume a logical adversarial attempt.
        """
        if self.logical_adversarial_attempts >= LOGICAL_ADVERSARIAL_ATTEMPT_CEILING:
            raise BudgetExhausted("LOGICAL_ADVERSARIAL_ATTEMPT_BUDGET_EXHAUSTED")

        self.logical_adversarial_attempts += 1

    def to_dict(self) -> dict[str, int]:
        return {
            "logical_adversarial_attempts": self.logical_adversarial_attempts,
            "physical_provider_calls": self.physical_provider_calls,
            "reserved_output_token_units": self.reserved_output_token_units,
        }
