"""Open Authority Trials (OAT) — adversarial evidence instrument.

This package is a METHOD-DEVELOPMENT-ONLY testbed. It does not certify any
product, protocol, vendor, or deployment. Claim-bearing use is prohibited.
"""

from __future__ import annotations

__version__ = "0.1.0"

#: Constitutional state carried by every artifact this package emits.
RUN_MODE: str = "METHOD_DEVELOPMENT_ONLY"
CLAIM_BEARING_USE: str = "PROHIBITED"
CLAIM_BEARING_TRIAL_AUTHORIZED: bool = False

#: The maximum claim any output of this package may support.
CLAIM_CEILING: str = (
    "A deterministic local instrument reproduced a documented synthetic "
    "authorization failure class (RB-001) under frozen scenario conditions. "
    "This supports no claim about VEIP, OAuth, any agent system, any vendor, "
    "or any deployed system."
)

__all__ = [
    "CLAIM_BEARING_TRIAL_AUTHORIZED",
    "CLAIM_BEARING_USE",
    "CLAIM_CEILING",
    "RUN_MODE",
    "__version__",
]
