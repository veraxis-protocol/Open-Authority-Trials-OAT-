"""Mandatory pre-run ground-truth leak audit for every target/candidate pair.

The audit runs over the exact bundle the model will see — the candidate prompt
plus the target's model-visible bundle — and fails if any adjudicator-only
token appears, or if the generator seed is reconstructible from that bundle.
The audit artifact carries only PASS/FAIL, a bundle digest and counts; it never
names the token it matched, which would itself be the leak.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from oat.qualification.synthetic_targets import SyntheticTarget

PASS = "PASS"
FAIL = "FAIL"


def _bundle_text(candidate_prompt: str, target: SyntheticTarget) -> str:
    return candidate_prompt + "\n" + json.dumps(target.model_visible_bundle(), sort_keys=True)


def seed_reconstructible(seed: str, bundle_text: str) -> bool:
    """Would the seed, or a short prefix of it, appear verbatim in the bundle?"""
    if not seed:
        return False
    if seed in bundle_text:
        return True
    return len(seed) >= 8 and seed[:8] in bundle_text


def audit_pair(
    candidate_id: str, candidate_prompt: str, target: SyntheticTarget, seed: str
) -> dict[str, Any]:
    forbidden = target.ground_truth.forbidden_tokens()
    text = _bundle_text(candidate_prompt, target)
    haystack = text.lower()
    matched = sum(1 for token in forbidden if token.lower() in haystack)
    seed_leak = seed_reconstructible(seed, text)
    status = PASS if (matched == 0 and not seed_leak) else FAIL
    return {
        "artifact": "QUALIFICATION_LEAK_AUDIT",
        "bundle_digest": hashlib.sha256(text.encode()).hexdigest(),
        "candidate_id": candidate_id,
        "forbidden_token_count": len(forbidden),
        "matched_token_count": matched,
        "seed_reconstructible": seed_leak,
        "status": status,
        "target_id": target.target_id,
    }
