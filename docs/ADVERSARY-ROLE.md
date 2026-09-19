# The adversary's role

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
NIM_PROVIDER_CALLS = NOT AUTHORIZED BY THE CURRENT REFACTOR
```

## The separation

```text
ADVERSARY        SEARCHES
VERIFIER         COMPUTES
SINK             RECORDS
AUTHORITY STATE  DEFINES
OAT              ADJUDICATES
```

A frontier model is a search procedure. It is good at finding routes and
argument mutations a human would not think of, and that is the entire reason
to point one at a boundary. It is not a source of truth about anything it
finds.

## What the adversary may produce

- candidate actions
- route hypotheses
- tool combinations
- retry strategies
- credential-use hypotheses
- delegation hypotheses
- argument mutations
- async and race strategies
- unknown-route discoveries

## What it may never produce

- authorization truth
- authority currentness
- sink commit truth
- counterexample truth
- institutional legitimacy
- standing

No model-generated claim becomes a counterexample without independent
verifier evidence. This is structural, not a policy: the verifier's evidence
object (`oat.verifier.consequence.ConsequenceEvidence`) has no field an
adversary can populate. Everything it reads comes from the sink's ledger, the
sink's independent observer, and the authority store.

`test_adversary_assertion_alone_establishes_nothing` asserts this against the
dataclass fields directly, so the property cannot quietly erode.

## Provider provenance

`oat/adversaries/provider.py` derives `provider_run_occurred` from the
transport rather than from configuration or intent. A scripted or offline
adversary reports `False` forever, so a dry run cannot be written up as a
live model run by relabelling it.

Consequence-boundary runs in this repository are entirely offline. Every run
package records `provider_run_occurred: false`, and no test performs a
network call.

## Why replay does not need the model

A validated counterexample is recomputed by the verifier from frozen
evidence. Model output is *search provenance* — it explains how a candidate
was found, not why it counts. Replay therefore requires no provider, and
`oat consequence replay` reproduces a disposition and evidence digest with no
credentials of any kind.
