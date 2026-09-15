"""Provider-backed adversary seam.

A frontier model is a *witness generator*. It proposes; it never adjudicates.
This module makes that structural rather than aspirational, and makes one
other thing structural too: whether a provider was actually called.

``provider_run_occurred`` is derived from the transport, not from
configuration or intent. A scripted transport reports ``False`` forever, so a
dry run cannot be written up as a live model run by accident or by editing a
label.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any

from oat.adversaries.base import Adversary
from oat.digest import digest_object
from oat.reference_boundaries.rb001 import Scenario, Variation
from oat.trial import AdversaryAssertion

#: Value recorded for any configuration field the provider does not expose.
NOT_EXPOSED: str = "NOT_EXPOSED_BY_PROVIDER"


class TransportError(RuntimeError):
    """Raised when a provider transport cannot serve a request."""


class Transport(ABC):
    """A request/response channel to a model provider."""

    #: True only for a transport that reaches a real provider endpoint.
    is_live: bool = False
    name: str = "abstract"

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Return the provider's response to ``prompt``."""


class UnconfiguredTransport(Transport):
    """The default. No endpoint, no credentials, and it refuses loudly."""

    is_live = False
    name = "unconfigured"

    def complete(self, prompt: str) -> str:
        raise TransportError(
            "No provider transport is configured: no endpoint and no credentials. "
            "An adversary run cannot be performed, and must not be reported as if "
            "it had been."
        )


class ScriptedTransport(Transport):
    """A deterministic, offline transport for plumbing dry runs.

    It replays fixed responses in order. It is not a model, it reaches no
    network, and it always reports ``is_live = False``.
    """

    is_live = False
    name = "scripted-offline"

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._index = 0

    def complete(self, prompt: str) -> str:
        if self._index >= len(self._responses):
            raise TransportError("scripted transport exhausted")
        response = self._responses[self._index]
        self._index += 1
        return response


class ProviderAdversary(Adversary):
    """Adversary that sources candidate hypotheses from a provider transport."""

    id = "OAT-ADVERSARY-PROVIDER"
    version = "0.2.0"

    def __init__(
        self,
        transport: Transport | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.transport = transport or UnconfiguredTransport()
        self.config = dict(config or {})

    @property
    def kind(self) -> str:
        return "provider"

    @property
    def provider_run_occurred(self) -> bool:
        """Whether a real provider endpoint was contacted. Derived, not declared."""
        return bool(self.transport.is_live)

    def identity(self) -> dict[str, Any]:
        identity = super().identity()
        identity.update(
            {
                "transport": self.transport.name,
                "provider_run_occurred": self.provider_run_occurred,
                "model": self.config.get("model", NOT_EXPOSED),
                "endpoint": self.config.get("endpoint", NOT_EXPOSED),
                "config_digest": digest_object(self.config),
            }
        )
        return identity

    def propose(self, scenario: Scenario) -> Iterator[Variation]:
        """Ask the transport for candidate variations.

        Responses are parsed into variations inside the scenario's declared
        search space. A response that cannot be parsed is discarded rather
        than guessed at.
        """
        raw = self.transport.complete(self._prompt(scenario))
        yield from self._parse(raw)

    def assert_finding(
        self, attack_id: str, property_id: str, claimed_violation: bool, hypothesis: str
    ) -> AdversaryAssertion:
        """Wrap a provider claim as an assertion — explicitly not a verdict."""
        return AdversaryAssertion(
            attack_id=attack_id,
            property_id=property_id,
            claimed_violation=claimed_violation,
            hypothesis=hypothesis,
            adversary_identity=self.identity(),
        )

    def _prompt(self, scenario: Scenario) -> str:
        return (
            f"scenario={scenario.scenario_id} "
            f"enforcement_path={scenario.enforcement_path} "
            f"search_space={sorted(scenario.search_space)}"
        )

    @staticmethod
    def _parse(raw: str) -> list[Variation]:
        """Parse ``check,revoke,commit[,delay[,retry[,duplicate]]]`` lines."""
        variations: list[Variation] = []
        for line in raw.splitlines():
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if len(parts) < 3:
                continue
            try:
                numbers = (
                    [int(p) for p in parts[:5]] if len(parts) >= 5 else [int(p) for p in parts[:3]]
                )
            except ValueError:
                continue
            variations.append(
                Variation(
                    check_tick=numbers[0],
                    revocation_tick=numbers[1],
                    commit_tick=numbers[2],
                    propagation_delay=numbers[3] if len(numbers) > 3 else 0,
                    retry_index=numbers[4] if len(numbers) > 4 else 0,
                    duplicate_request=parts[5].lower() == "true" if len(parts) > 5 else False,
                )
            )
        return variations
