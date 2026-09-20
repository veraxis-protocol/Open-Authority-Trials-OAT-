# Erratum 001 — Sequence 003 adjudication was wrong

```text
ERRATUM_ID        = OAT-SEQUENCE-003-ADJUDICATION-ERRATUM-001
SEQUENCE_ID       = OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-003
RUN_ID            = OAT-NIM-HOST-SINK-001-20260920-C
AUTHORIZATION     = OAT-OWNER-NIM-EXEC-AUTH-003   (CONSUMED, permanently)
ISSUED            = 2026-09-20
STATUS            = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
```

Sequence 003 / Run C reported `FULL_FROZEN_SEQUENCE_CLOSURE = ESTABLISHED`.
**That output is invalid.** It was produced by two defects in
`tools/oat_consequence_sequence_runner_003.py`, each independently sufficient
to manufacture it. The corrected controlling state is below.

Nothing in the Run C evidence is altered, deleted, or relabelled by this
erratum. Runner 003 is preserved unmodified. What changes is the adjudication
of that evidence, and the runner used from Sequence 004 onward.

## What actually happened

As preserved in the Run C runtime evidence and provider transcript:

```text
AUTHORIZATION_003           = CONSUMED
PROVIDER_CALLS              = 1
PROVIDER_TRANSPORT_FAILURES = 1
TARGET_HTTP_ATTEMPTS        = 0

provider transcript, call 1:
  classification = HTTP_4XX_FATAL_FOR_RUN
  http_status    = 401
  retryable      = false
```

The first provider request consumed the one-run owner authorization and came
back unauthenticated. The run reached the target zero times. No route was
exercised, no commit was attempted, and no boundary question was put to the
subject at all.

## Corrected controlling state

```text
RUN_C_EXECUTION              = NOT_EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT
RUN_C_SUBJECT_RESULT         = NOT_ESTABLISHED
RUN_C_DISPOSITION            = HARNESS_OR_INSTRUMENT_FAILURE
FULL_FROZEN_SEQUENCE_CLOSURE = NOT_ESTABLISHED
SEQUENCE_003_RUNNER_OUTPUT   = INVALIDATED_BY_ADJUDICATION_DEFECT
AUTHORIZATION_003            = CONSUMED; reuse and rerun PROHIBITED
```

The pre-adversary half of Sequence 003 stands and is unaffected by either
defect, because neither touches the positive control's own execution:

```text
PC_SENSITIVITY              = ESTABLISHED   (CONSEQUENCE_BOUNDARY_FAILURE)
STATE_SEPARATION            = ESTABLISHED
ADVERSARY_CONTEXT_ISOLATION = PASS
```

## Defect A — execution was inferred from provider contact

`adjudicate_sequence()` in runner 003 computed:

```python
run_c_executed = bool(run_c_runtime and run_c_runtime.get("provider_call_performed"))
```

A provider request occurring is evidence that the authorization was consumed.
It is not evidence that the experimental boundary was exercised to an
admissible result. Run C sent one request, was rejected at authentication, and
made zero target attempts — yet satisfied `run_c_executed`.

The fail-closed wrapper had already reached the right answer downstream:
`instrument_status = NOT_EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT` and
`subject_result = NOT_ESTABLISHED` are both present in the preserved Run C
verdict. The closure computation simply did not consult them.

Corrected in runner 004:

```python
run_executed = (
    runtime.get("instrument_status") == "EXECUTED"
    and int(runtime.get("target_http_attempts", 0)) > 0
)
```

## Defect B — replay compared the wrong verdict

`replay_from_evidence()` in runner 003 reconstructed the subject verifier
result from the preserved stores and compared it to
`evidence["subject_verifier_verdict"]` — the *raw* subject verdict.

On Run C the ledger was empty, so the frozen verifier correctly returned
`NO_BOUNDARY_COUNTEREXAMPLE`, which equalled the stored raw subject verdict.
Replay reported success. But the stored **final** disposition was
`HARNESS_OR_INSTRUMENT_FAILURE`, and that is what replay was supposed to
reproduce. The check was comparing a value to itself and skipping the
adjudication entirely.

Corrected in runner 004, replay runs in two layers:

- **Layer A** — the frozen verifier reconstructs the subject verdict from the
  preserved SQLite stores.
- **Layer B** — the same fail-closed wrapper is re-applied using preserved
  execution facts, and the recomputed **final** verdict must match the stored
  final verdict on `disposition`, `subject_result` and `instrument_status`.

This required runtime evidence to preserve enough to recompute the final
adjudication deterministically. Runner 004 records `terminal_provider_failure`
explicitly alongside `target_http_attempts`, `provider_call_performed`,
`provider_transport_failures` and `stop_reason`.

## Why both defects mattered

Either one alone produces the false closure. Defect A scores a 401 as an
execution; Defect B lets an empty ledger replay cleanly against itself. With
both present, a run that never reached the target reported a complete
scientific sequence.

The instrument's own fail-closed rule was correct and did fire — the Run C
verdict says `HARNESS_OR_INSTRUMENT_FAILURE` in plain text. The failure was in
the layer that read that verdict, which is the layer nothing else was checking.

## Provenance

`tools/oat_consequence_sequence_runner_003.py` is **not** modified. It remains
the historical executable that produced the Run C evidence, and its SHA-256 is
pinned in the Sequence 004 manifest's immutability set so a test fails if it
moves. The corrected logic lives in
`tools/oat_consequence_sequence_runner_004.py` under a new runner id and
version.

## Consequences for Sequence 004

1. Authorization 003 is consumed. Run C will not be rerun. Sequence 004 / Run D
   is a new sequence under a new authorization.
2. A non-experiment provider credential preflight
   (`tools/oat_nvidia_provider_preflight.py`) must PASS before Run D may enter
   S3. Run C spent an owner authorization to discover a bad credential; that is
   now discoverable for free.
3. Ten regression tests cover both defects directly, including the exact
   observed Run C shape (provider call = 1, attempts = 0, 401) and the
   empty-ledger replay case.

## Claim ceiling

Unchanged. Sequence 003 established detector sensitivity and clean state
separation under the frozen method-development target. It established nothing
about the subject, because the subject was never reached.

```text
CLAIM_BEARING_USE = PROHIBITED
```
