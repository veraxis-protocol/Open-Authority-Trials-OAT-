from __future__ import annotations

from typing import Any

from oat.veip.experiment001 import render_provider_request
from oat.veip.launch_binding import (
    OPEN_DISCOVERY_ATTACK_ID,
    OPEN_DISCOVERY_SENTINEL,
    resolve_angle_binding,
)
from oat.veip.prompt import OPEN_DISCOVERY_SYSTEM_PROMPT, SYSTEM_PROMPT, render, system_prompt_for


def _ordinary_angle() -> dict[str, Any]:
    return {
        "attack_id": "ATK-F04",
        "family": "scope expansion",
        "target_components": ["veip"],
        "allowed_attacker_capabilities": ["propose witness"],
        "prohibited_attacker_capabilities": ["mutate subject"],
    }


def _ordinary_falsifier() -> dict[str, Any]:
    return {
        "property_id": "VEIP-P-09",
        "counterexample_condition": "condition",
        "predicate": "predicate",
        "required_observables": ["observable"],
    }


def _open_angle() -> dict[str, Any]:
    return {
        "attack_id": OPEN_DISCOVERY_ATTACK_ID,
        "family": "open discovery",
        "falsifiers": [OPEN_DISCOVERY_SENTINEL],
        "target_property_ids": ["ANY_IN_SCOPE", "OR_NEWLY_PROPOSED"],
        "target_components": ["any"],
        "allowed_attacker_capabilities": ["propose witness", "propose novel property"],
        "prohibited_attacker_capabilities": ["mutate subject", "admit property"],
    }


def test_ordinary_angles_keep_exact_original_system_prompt() -> None:
    angle = _ordinary_angle()
    assert system_prompt_for(angle) == SYSTEM_PROMPT
    assert system_prompt_for(angle) is SYSTEM_PROMPT

    prompt_bytes, _digest = render(
        angle,
        _ordinary_falsifier(),
        round_number=1,
        attempt_number=1,
    )
    assert prompt_bytes.startswith(f"{SYSTEM_PROMPT}\n\n".encode())
    assert b"explicit proposed new property ID" not in prompt_bytes


def test_open_discovery_system_prompt_explicitly_allows_new_property_proposal() -> None:
    prompt = system_prompt_for(_open_angle())

    assert prompt == OPEN_DISCOVERY_SYSTEM_PROMPT
    assert prompt != SYSTEM_PROMPT
    assert "For ATTACK-FAMILY-X only, you MAY propose a new property explicitly." in prompt
    assert "an explicit proposed new property ID" in prompt
    assert "describe the proposed property semantics in" in prompt
    assert "OUTSIDE_SCOPE" in prompt
    assert "cannot be admitted or validated mid-experiment" in prompt
    assert '"property_id": "<the frozen property ID you are targeting>"' not in prompt


def test_open_discovery_rendered_request_uses_variant_for_both_prompt_and_system_role() -> None:
    angle = _open_angle()
    binding = resolve_angle_binding(angle, {})

    rendered = render_provider_request(
        angle,
        binding.render_falsifier,
        round_number=1,
        attempt_number=1,
    )

    expected_system = system_prompt_for(angle)
    assert rendered.prompt_bytes.startswith(f"{expected_system}\n\n".encode())
    assert rendered.body["messages"][0] == {
        "role": "system",
        "content": expected_system,
    }
    assert "ANY_IN_SCOPE | OR_NEWLY_PROPOSED" in rendered.body["messages"][1]["content"]
    assert "A new, unmapped, or non-READY property" in rendered.body["messages"][1]["content"]


def test_ordinary_rendered_request_does_not_change_system_role() -> None:
    rendered = render_provider_request(
        _ordinary_angle(),
        _ordinary_falsifier(),
        round_number=1,
        attempt_number=1,
    )

    assert rendered.body["messages"][0] == {
        "role": "system",
        "content": SYSTEM_PROMPT,
    }
