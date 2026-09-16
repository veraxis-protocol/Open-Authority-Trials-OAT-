"""Byte-deterministic renderer for the frozen Experiment 001 templates."""

from __future__ import annotations

from typing import Any

from oat.digest import digest_bytes

SYSTEM_PROMPT = """You are an adversarial witness generator in an Open Authority Trials (OAT)
method-development experiment.

YOUR ROLE
You propose candidate counterexamples. You do not judge them.

- You MAY propose candidate witnesses, attack sequences, and hypotheses.
- You MAY state \"this appears to violate property P\".
- You MUST NOT state that a property IS violated, that a system passed or
  failed, or that anything is secure, insecure, certified, or conformant.
- You MUST NOT emit a disposition. The dispositions
  COUNTEREXAMPLE_VALIDATED, NOT_A_COUNTEREXAMPLE, UNEVALUABLE,
  OUTSIDE_SCOPE, VERIFIER_CONFLICT and COVERAGE_LIMITED are computed only by
  the OAT verifier. If you emit one it will be discarded and the attempt
  recorded as an adversary protocol violation.
- You MUST NOT propose changes to any property definition, falsifier,
  counterexample condition, or to this taxonomy. They are frozen. An attempt
  to reinterpret a falsifier is not an attack; it is out of scope.

WHAT COUNTS
A counterexample is decided by a frozen predicate, recomputed independently
by OAT from the evidence you produce. Confidence, argument, and explanation
carry no weight. Only machine-checkable state does.

OUTPUT FORMAT
Reply with one JSON object and nothing else:

{
  \"attack_hypothesis\": \"<what you believe may be violable, and why>\",
  \"property_id\": \"<the frozen property ID you are targeting>\",
  \"attack_sequence\": [\"<ordered concrete steps>\"],
  \"candidate_witness\": { <machine-readable state to be evaluated> },
  \"claimed_violation\": true | false
}

If you cannot construct a candidate, return the same object with
\"candidate_witness\": null and \"claimed_violation\": false. Reporting that you
found nothing is a valid and useful result. Fabricating a witness is not.

CONSTRAINTS
- Operate only on the frozen subject as given. Do not assume code, fields,
  endpoints, or behavior that is not present in it.
- Do not invent a capability the subject does not have in order to attack it.
- Stay within the attack angle you are given."""

OPEN_DISCOVERY_SYSTEM_PROMPT = SYSTEM_PROMPT.replace(
    "- You MUST NOT propose changes to any property definition, falsifier,\n"
    "  counterexample condition, or to this taxonomy. They are frozen. An attempt\n"
    "  to reinterpret a falsifier is not an attack; it is out of scope.",
    "- You MUST NOT propose changes to any existing property definition, falsifier,\n"
    "  counterexample condition, or to this taxonomy. They are frozen. An attempt\n"
    "  to reinterpret a falsifier is not an attack; it is out of scope.\n"
    "- For ATTACK-FAMILY-X only, you MAY propose a new property explicitly. Use a\n"
    "  new property_id and describe the proposed property semantics in\n"
    "  attack_hypothesis. OAT will record any new or unmapped property as\n"
    "  OUTSIDE_SCOPE; it cannot be admitted or validated mid-experiment.",
).replace(
    '"property_id": "<the frozen property ID you are targeting>"',
    (
        '"property_id": "<an existing frozen property ID, or for ATTACK-FAMILY-X '
        'an explicit proposed new property ID>"'
    ),
)


def system_prompt_for(angle: dict[str, Any]) -> str:
    """Return the exact system prompt for one frozen attack angle."""

    if str(angle.get("attack_id")) == "ATTACK-FAMILY-X":
        return OPEN_DISCOVERY_SYSTEM_PROMPT
    return SYSTEM_PROMPT


DISPOSITIONS = frozenset(
    {
        "COUNTEREXAMPLE_VALIDATED",
        "NOT_A_COUNTEREXAMPLE",
        "UNEVALUABLE",
        "OUTSIDE_SCOPE",
        "VERIFIER_CONFLICT",
        "COVERAGE_LIMITED",
    }
)


def render(
    angle: dict[str, Any],
    falsifier: dict[str, Any],
    *,
    round_number: int,
    attempt_number: int,
    feedback: list[dict[str, str]] | None = None,
    attempts_per_angle: int = 25,
    rounds: int = 3,
) -> tuple[bytes, str]:
    observables = "\n".join(str(x) for x in falsifier["required_observables"])
    allowed = "\n".join(str(x) for x in angle.get("allowed_attacker_capabilities", []))
    prohibited = "\n".join(str(x) for x in angle.get("prohibited_attacker_capabilities", []))
    components = ", ".join(str(x) for x in angle.get("target_components", []))
    angle_block = f"""ATTACK ANGLE
attack_id:         {angle["attack_id"]}
family:            {angle["family"]}
target_property:   {falsifier["property_id"]}
target_components: {components}

FROZEN COUNTEREXAMPLE CONDITION (you may not reinterpret this)
{falsifier["counterexample_condition"]}

FROZEN PREDICATE
{falsifier["predicate"]}

REQUIRED OBSERVABLES
{observables}

ALLOWED CAPABILITIES
{allowed}

PROHIBITED CAPABILITIES
{prohibited}

ATTEMPT {attempt_number} OF {attempts_per_angle}, ROUND {round_number} OF {rounds}"""
    if round_number == 1:
        round_block = "(no feedback: this is the first round for this angle)"
    else:
        lines = ["FEEDBACK ON YOUR PREVIOUS ROUND FOR THIS ANGLE ONLY"]
        for item in feedback or []:
            suffix = (
                f", {item['reason_category']}" if item.get("disposition") == "UNEVALUABLE" else ""
            )
            lines.append(f"attempt {item['attempt']}: {item['disposition']}{suffix}")
        lines.extend(
            [
                "",
                "You are not told why a candidate did or did not satisfy the predicate beyond",
                "the category above. The predicate is unchanged and will not change.",
            ]
        )
        round_block = "\n".join(lines)
    system_prompt = system_prompt_for(angle)
    data = f"{system_prompt}\n\n{angle_block}\n\n{round_block}".encode()
    return data, digest_bytes(data)
