# FORMATION-0003 — Subject-specific executable readiness

Status: candidate closure under OAT-NIM-VEIP-005.

VEIP experiment readiness requires all three of the following at the bound,
immutable OAT identity:

1. executable subject-specific falsifiers whose predicates are unchanged;
2. a live transport and evidence contract validated entirely with offline SSE
   fixtures before VEIP is exposed; and
3. verifier identities in the candidate falsifier register that name the
   commit which actually implements them.

The v1.2.0 candidate adds hard gates for those properties. It does not
authorize the NIM attack, consume the holdout, mutate VEIP, or permit
claim-bearing use.
