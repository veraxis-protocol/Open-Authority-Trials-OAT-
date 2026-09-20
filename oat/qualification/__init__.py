"""OAT Adversary Qualification 001 — synthetic, non-claim-bearing framework.

This package qualifies a candidate *search strategy* against a corpus of
neutral synthetic targets. It never touches the real frozen OAT target, never
reads Sequence 004 adjudicator ground truth, and never authorizes Sequence 005.
Every synthetic target's ground truth is adjudicator-only and excluded from the
model-visible bundle by construction, then checked by a mandatory leak audit.
"""

from __future__ import annotations

QUALIFICATION_ID = "OAT-ADVERSARY-QUALIFICATION-001"
GENERATOR_VERSION = "1.0.0"

__all__ = ["GENERATOR_VERSION", "QUALIFICATION_ID"]
