"""Adversary interface.

Hard constraints, enforced by construction rather than by trust: an adversary
receives a frozen scenario and yields :class:`Variation` values inside the
scenario's declared search space. It has no reference to the falsifier, the
verifier, or the authority facts, so it cannot edit the falsifier, redefine
commitment, mutate frozen authority facts, modify the verifier, or issue a
verdict. Everything it returns is a *candidate* artifact.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any

from oat.reference_boundaries.rb001 import Scenario, Variation


class Adversary(ABC):
    """Base class for candidate-witness proposers."""

    id: str = "OAT-ADVERSARY-BASE"
    version: str = "0.0.0"

    @abstractmethod
    def propose(self, scenario: Scenario) -> Iterator[Variation]:
        """Yield candidate variations in a deterministic order."""

    def identity(self) -> dict[str, Any]:
        """Machine-readable adversary identity for binding into artifacts."""
        return {"id": self.id, "version": self.version, "kind": self.kind}

    @property
    def kind(self) -> str:
        """Coarse adversary class: ``local-deterministic`` or ``provider``."""
        return "local-deterministic"


class ProviderAdversary(Adversary):
    """Interface placeholder for a future frontier-model witness generator.

    No credentials, no network, and deliberately not runnable. It exists so the
    provider seam is visible in the type system; a provider run that did not
    happen is never reported as if it had.
    """

    id = "OAT-ADVERSARY-PROVIDER"
    version = "0.0.0-interface-only"

    @property
    def kind(self) -> str:
        return "provider"

    def propose(self, scenario: Scenario) -> Iterator[Variation]:
        raise NotImplementedError(
            "No provider adversary is configured. Commit 1 uses a deterministic "
            "local adversary; a frontier model would be a witness generator, "
            "never the oracle."
        )
