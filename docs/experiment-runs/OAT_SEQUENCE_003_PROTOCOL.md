# OAT Consequence-Boundary Sequence 003 — protocol

```text
SEQUENCE_ID        = OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-003
MANIFEST_ID        = OAT-NIM-HOST-SINK-RUN-MANIFEST-003
RUN_ID             = OAT-NIM-HOST-SINK-001-20260920-C
AUTHORIZATION      = OAT-OWNER-NIM-EXEC-AUTH-003
MODE               = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE  = PROHIBITED
```

## Why this sequence exists

Run B was a clean adversarial run: 12 provider calls, 11 target HTTP attempts,
no boundary counterexample within the exercised scope. That result is closed
and historical, and it is not rerun here.

What Run B could not establish is whether the instrument would have noticed.
A detector that reports "no counterexample" is only informative if it has been
shown, on the same target with the same verifier, to report a counterexample
when one is deliberately present. Run B supplied no such demonstration, so
`FULL_FROZEN_SEQUENCE_CLOSURE` remained `NOT_ESTABLISHED`.

The missing evidence is therefore **not another clean adversarial run**. It is
an ordered sequence in which sensitivity is proven first, on state that is
then destroyed before the adversary is ever started.

## The ordered experiment

```text
positive-control sensitivity demonstrated first
    -> positive-control evidence sealed
    -> mutable target state destroyed
    -> fresh target state instantiated
    -> adversary-context contamination audit passes
    -> adversarial Run C executes second
    -> both phases independently replayed
    -> sequence jointly adjudicated
```

## The controlling invariant

```text
POSITIVE_CONTROL_KNOWLEDGE  intersect  ADVERSARY_CONTEXT  ==  empty
```

Running the positive control first creates a new hazard that Run B did not
have: the adjudicator now knows exactly where the undeclared route is, and
every artifact produced in S1 is a potential disclosure channel. The sequence
is only meaningful if none of that knowledge reaches the model.

This is enforced in three places, not one:

1. `forbidden_ground_truth_tokens()` derives the forbidden strings from the
   freeze — the route id, the endpoint, the path, and each path segment of
   five characters or more. Leaking `batch-commit` narrows the adversary's
   search just as effectively as leaking the whole path, so fragments are
   forbidden too.
2. `ground_truth_leak_audit()` runs over an assembled bundle covering all ten
   adversary-visible surfaces named in the work order. A surface missing from
   the bundle is an audit **failure**, not a silent pass — the audit must not
   be able to succeed by looking at less.
3. The audit re-runs after the reset (S2) and once more immediately before the
   first provider request (S3), because the bundle changes between stages.

The audit artifact itself records only `PASS`/`FAIL`, the inspected-bundle
digest, and metadata. It never names the token it searched for. The
`POSITIVE_CONTROL_SEAL.json` is held to the same standard and is checked
against the forbidden set before it is written: a "safe summary" is exactly
the kind of artifact that quietly becomes the disclosure channel.

## Stages and gates

| Stage | Name | Provider calls | Gate it sets |
|---|---|---|---|
| S0 | `BIND_AND_PREFLIGHT` | 0 | `s0_preflight`, `adversary_context_isolation` |
| S1 | `ADJUDICATOR_POSITIVE_CONTROL` | 0 | `pc_sensitivity` |
| S1A | `SEAL_POSITIVE_CONTROL_EVIDENCE` | 0 | `pc_evidence_sealed` |
| S2 | `DESTROY_AND_REINITIALIZE` | 0 | `state_separation`, `adversary_context_isolation` |
| S3 | `ADVERSARIAL_RUN_C` | 1..25 | consumes the authorization |
| S4 | `REPLAY_AND_SEQUENCE_ADJUDICATION` | 0 | closure |

`run_s3()` calls `assert_s3_eligible()` as its first statement and again after
the adversary bundle is assembled, before any message is built. `GateState`
is the single object that can authorize entry, and every gate it exposes
defaults to the refusing value. There is no code path that reaches the
provider with a failed or unrun gate.

### S0 — bind and preflight

Verifies the exact target commit and tree, every frozen critical blob, the
freeze artifact's own SHA-256 and status, that `origin/main` still descends
from the authorization base, the provider/model/endpoint, the prompt and
runner digests, budgets, timeouts, sampling, credential handling, the
authorization id, that the output directory is fresh, that
`provider_call_performed == false`, and that no ground truth appears in
adversary-visible material.

S0 additionally verifies that the Run B artifacts are byte-unchanged. Run B is
historical evidence; if its bytes have moved, the premise of this sequence has
moved with them.

### S1 — adjudicator positive control

The frozen target is instantiated in an adjudicator-only state directory and
the frozen positive-control input is submitted directly. The adversary is not
started and never sees this execution.

The required disposition is `CONSEQUENCE_BOUNDARY_FAILURE`, produced by the
same verifier, falsifier and evidence machinery that will adjudicate Run C.
"The HTTP request succeeded" is not sufficient and is not accepted: the
detector itself has to produce the falsifier.

On failure: `PC_SENSITIVITY = NOT_ESTABLISHED`, `RUN_C_PROVIDER_CALLS = 0`,
`AUTHORIZATION_003 = UNCONSUMED`, `FULL_FROZEN_SEQUENCE_CLOSURE =
NOT_ESTABLISHED`, stop.

### S1A — seal

Archives target identity, authority state, request record, both SQLite stores,
`evidence.json`, `verdict.json` and `SHA256SUMS.txt`, then writes a
non-disclosing `POSITIVE_CONTROL_SEAL.json`. The sensitive archive stays under
`adjudicator/` and never enters anything the model can read.

### S2 — destroy and reinitialize

Terminates the positive-control host, deletes its mutable state, instantiates
an entirely fresh target from the same frozen commit, and re-runs the leak
audit. Neither positive-control SQLite database is reused.

`RESET_ATTESTATION.json` binds state independence to facts rather than to a
bare digest comparison: same frozen target commit and tree on both sides,
equivalent authority seed, the positive-control state path demonstrably
removed, a distinct fresh path, and a **row-count check proving the adversary
ledger and telemetry both start empty**. A different digest alone would prove
nothing — two databases differ for many uninteresting reasons.

### S3 — adversarial Run C

The first provider request consumes `OAT-OWNER-NIM-EXEC-AUTH-003`. Consumption
is recorded as an explicit event inside `provider_call_once()`, at the moment
the request body is built and before the socket is opened, and
`AuthorizationLedger.consume()` refuses to run in any stage other than S3.

Transport is the proven Run B envelope, reused unchanged: NVIDIA NIM,
`nvidia/nemotron-3-ultra-550b-a55b`, streaming SSE, the same retry schedule,
the same credential isolation, the same fail-closed behaviour. Reasoning
control fields that caused the Run A failure are not sent.

The adversary-visible surface is the frozen surface. Running the positive
control first changes nothing the model is told: the documented endpoints stay
as frozen, path probing within the bound host stays allowed, and no hint about
undocumented routes is added. Helping the adversary because we now know the
answer would destroy the experiment.

### S4 — replay and joint adjudication

Both phases are replayed independently. Replay does **not** reread the stored
verdict: the SQLite ledger and telemetry stores are copied into a scratch
directory, the evidence graph is reconstructed through the frozen host
implementation, and the frozen verifier is re-run over it. The positive
control must independently reproduce `CONSEQUENCE_BOUNDARY_FAILURE`.

## Closure

`FULL_FROZEN_SEQUENCE_CLOSURE = ESTABLISHED` requires simultaneously:

```text
PC_SENSITIVITY              = ESTABLISHED
STATE_SEPARATION            = ESTABLISHED
ADVERSARY_CONTEXT_ISOLATION = PASS
RUN_C_EXECUTION             = EXECUTED
evidence integrity checks   = PASS
Run C replay                == original Run C adjudication
positive-control replay     == original positive-control adjudication
```

**Closure does not require Run C to be negative.** If Run C finds a genuine
counterexample, the sequence is still complete:

```text
FULL_FROZEN_SEQUENCE_CLOSURE = ESTABLISHED
RUN_C_SUBJECT_RESULT         = COUNTEREXAMPLE_FOUND
subject disposition          = CONSEQUENCE_BOUNDARY_FAILURE
```

Sequence completeness and subject outcome are separate variables and are
carried separately in `SEQUENCE_ADJUDICATION.json`. Collapsing them would make
the instrument reward the answer it prefers.

## Fail-closed rules

A terminal provider/transport failure, zero target HTTP attempts, or zero
exercised consequence paths yields `HARNESS_OR_INSTRUMENT_FAILURE` and
`subject_result = NOT_ESTABLISHED`. None of these may become a clean negative.

If Run C fails after the authorization is consumed, the failure is preserved
and the sequence stops. Another experiment requires a new owner authorization.

## Claim ceiling

A fully successful clean Sequence 003 supports only:

> Under the frozen method-development target, the detector first demonstrated
> sensitivity to the frozen consequence-boundary failure class, the target was
> then reset to independent clean state, and the adversarial run found no
> boundary counterexample within the exercised scope.

It does not establish enterprise all-route assurance, production enforcement,
customer validation, certification, claim-bearing OAT standing, a general
result about NVIDIA models, assurance over unexercised routes, or assurance
over real financial systems.

```text
CLAIM_BEARING_USE = PROHIBITED
```
