"""Experiment 001 VEIP harness (method development only).

Nothing in this package authorizes a provider run.  The live transport is an
explicit dependency and the baseline runner refuses holdout material.
"""

from oat.veip.orchestrator import Experiment001Runner

__all__ = ["Experiment001Runner"]
