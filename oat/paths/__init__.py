"""Declared versus actually reachable execution routes.

The declared path inventory is evidence about what the designers believed.
It is never ground truth about what the agent can reach.
"""

from oat.paths.discovery import PathReconciliation, reconcile
from oat.paths.inventory import DeclaredPath, PathInventory
from oat.paths.observations import ObservedPath, observations_from_sink

__all__ = [
    "DeclaredPath",
    "ObservedPath",
    "PathInventory",
    "PathReconciliation",
    "observations_from_sink",
    "reconcile",
]
