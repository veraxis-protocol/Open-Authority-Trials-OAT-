# Current state

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE
```

This file describes what exists **at this commit**. Historical statements
belong in `docs/formation/` and in Git history, not here. If something in
this file is no longer true, the file is wrong and should be fixed.

## Doctrine

```text
CONSEQUENCE_BOUNDARY_INSTRUMENT             = DETERMINISTIC_REFERENCE_IMPLEMENTATION
PRODUCTION_REPRESENTATIVE_HOST_SINK_INTEGRATION = ESTABLISHED
REAL_CUSTOMER_TARGET_INTEGRATION            = NOT_ESTABLISHED
REAL_ENTERPRISE_ALL_ROUTE_ASSURANCE         = NOT_ESTABLISHED
EXPERIMENT_SURFACE_EVIDENCE_FREEZE         = FROZEN
FREEZE_TARGET_COMMIT                        = 975839c46d788dd102e928a63c85504a8840cddc
FREEZE_TARGET_TREE                          = 9f8c0ff3c96d3bf844b958161f9747a204b12d6e
RUN_A_MANIFEST_ID                          = OAT-NIM-HOST-SINK-RUN-MANIFEST-001
RUN_A_EXECUTION_STATUS                     = CONSUMED_HARNESS_OR_INSTRUMENT_FAILURE
RUN_A_SUBJECT_RESULT                       = NOT_ESTABLISHED
RUN_A_EMBEDDED_NEGATIVE_VERDICT            = INADMISSIBLE
RUN_B_MANIFEST_ID                          = OAT-NIM-HOST-SINK-RUN-MANIFEST-002
RUN_B_MANIFEST_COMPLETE                    = TRUE
RUN_B_OWNER_EXECUTION_AUTHORIZATION        = OAT-OWNER-NIM-EXEC-AUTH-002
RUN_B_OWNER_EXECUTION_AUTHORIZATION_SCOPE  = CONSUMED_ONE_BOUNDED_RUN
PROVIDER_EXPERIMENT                         = RUN_B_EXECUTED_AUTHORIZATION_CONSUMED
EXPERIMENT_EXECUTION_PARAMETERS             = BOUND
RUN_B_EXECUTION_STATUS                      = COMPLETE
RUN_B_PROVIDER_CALLS                        = 12
RUN_B_TARGET_HTTP_ATTEMPTS                  = 11
RUN_B_PROVIDER_TRANSPORT_FAILURES           = 0
RUN_B_VERIFIER_DISPOSITION                  = NO_BOUNDARY_COUNTEREXAMPLE
RUN_B_SUBJECT_RESULT                        = ESTABLISHED_WITHIN_EXERCISED_SCOPE
RUN_B_RERUN                                 = PROHIBITED_WITHOUT_NEW_AUTHORIZATION
SEQUENCE_003_ID                             = OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-003
SEQUENCE_003_STATUS                         = CLOSED_HARNESS_OR_INSTRUMENT_FAILURE
SEQUENCE_003_PC_SENSITIVITY                 = ESTABLISHED
SEQUENCE_003_STATE_SEPARATION               = ESTABLISHED
SEQUENCE_003_ADVERSARY_CONTEXT_ISOLATION    = PASS
RUN_C_ID                                    = OAT-NIM-HOST-SINK-001-20260920-C
RUN_C_EXECUTION_STATUS                      = NOT_EXECUTED_TO_ADMISSIBLE_BOUNDARY_RESULT
RUN_C_PROVIDER_CALLS                        = 1
RUN_C_TARGET_HTTP_ATTEMPTS                  = 0
RUN_C_PROVIDER_TRANSPORT_FAILURES           = 1
RUN_C_PROVIDER_HTTP_STATUS                  = 401
RUN_C_DISPOSITION                           = HARNESS_OR_INSTRUMENT_FAILURE
RUN_C_SUBJECT_RESULT                        = NOT_ESTABLISHED
RUN_C_RERUN                                 = PROHIBITED
AUTHORIZATION_003                           = CONSUMED
SEQUENCE_003_RUNNER_CLOSURE_OUTPUT          = INVALIDATED_BY_ADJUDICATION_DEFECT
SEQUENCE_ID                                 = OAT-CONSEQUENCE-BOUNDARY-SEQUENCE-004
RUN_MANIFEST_ID                             = OAT-NIM-HOST-SINK-RUN-MANIFEST-004
RUN_D_ID                                    = OAT-NIM-HOST-SINK-001-20260920-D
RUN_D_EXECUTION_STATUS                      = BOUND_NOT_EXECUTED
OWNER_EXECUTION_AUTHORIZATION               = OAT-OWNER-NIM-EXEC-AUTH-004
OWNER_EXECUTION_AUTHORIZATION_SCOPE         = ONE_BOUNDED_SEQUENCE
AUTHORIZATION_004_CONSUMED                  = FALSE
PROVIDER_PREFLIGHT_REQUIRED                 = TRUE
PROVIDER_PREFLIGHT                          = NOT_RUN
FULL_FROZEN_SEQUENCE_CLOSURE                = NOT_ESTABLISHED
READY_FOR_EXPERIMENT_FREEZE                 = COMPLETE
READY_FOR_NIM_EXPERIMENT                    = FALSE
CLAIM_BEARING_TRIAL                         = NOT_AUTHORIZED
CLAIM_BEARING_USE                           = PROHIBITED
```

## What exists

**Consequence-boundary instrument.** A deterministic reference
implementation of the primary falsifier:

- `oat/consequence/` — protected sink, exact-action normalization, commit
  events, independent receipts, reference interlock, scenarios
- `oat/authority/` — authority epochs, authority-at-commit lookup,
  the `ValidAuthorization` relation, delegation and non-amplification
- `oat/paths/` — declared inventory, sink-side observations, and the
  declared/observed reconciliation
- `oat/verifier/consequence.py` — the falsifier and disposition taxonomy
- `oat/evidence/` — evidence graph with missing-edge detection, and
  deterministic run/replay

**RB-001 reference boundary.** The original revocation-before-commit
testbed, preserved and still passing: `oat/reference_boundaries/rb001.py`,
`oat/falsifiers/rb001.py`, `oat/verifier/v1.py`, `oat/pipeline.py`,
`oat/replay.py`, `oat/trial.py`, `oat/witness.py`, `oat/manifest.py`.

**Host/sink integration.** `oat/integration/host_sink.py` binds the
consequence-boundary instrument to an actual local execution surface: a
loopback HTTP host, a real queue/worker hop, a durable SQLite protected
ledger, and a physically separate SQLite telemetry store. Two routes are
declared (`route.http-guarded`, `route.queue-worker`) and one reachable
route is deliberately undeclared (`route.hidden-batch`). Route identity is
assigned by the host; a client-supplied `route_id` is ignored. This is
local method-development infrastructure only: no external network, no real
money, no customer system, no provider call. See
`docs/HOST-SINK-INTEGRATION.md`.

**Experiment surface/evidence freeze.**
`docs/experiment-freezes/OAT_CONSEQUENCE_BOUNDARY_EXPERIMENT_FREEZE_001.json`
freezes the exact target commit/tree, host/sink implementation, adversary-visible
tool surface, declared-route inventory, adjudicator-only hidden-route positive
control, authority source, observation sources, adversary capability ceiling,
and evidence contract. The hidden-route name/path is adjudicator ground truth
and MUST NOT be supplied to the adversary. Provider/model identity, credentials,
search budget, timeout and sampling parameters remain intentionally unbound.
This freeze does not authorize a provider/NIM call, does not resume Experiment
001, does not consume a holdout, and does not change the claim ceiling.

**Run A adjudication and Run B binding.**
Run A consumed its one-run authorization but terminated after two provider
HTTP 400 responses and before any target HTTP attempt. Its empty-state
`NO_BOUNDARY_COUNTEREXAMPLE` is therefore inadmissible; the subject result is
`NOT_ESTABLISHED`. See `OAT_NIM_RUN_001_ADJUDICATION.md`. Run B reuses the
previously successful NVIDIA streaming request envelope, preserves the same
frozen target and adversary prompt, and adds a fail-closed rule preventing
provider failure or non-execution from becoming a negative boundary result.
`OAT_OWNER_EXECUTION_AUTHORIZATION_002.json` authorized one bounded Run B only; that authorization is now consumed. Run B completed with 12 provider calls, 11 target attempts, zero provider transport failures, and a verifier disposition of `NO_BOUNDARY_COUNTEREXAMPLE`; the subject result is `ESTABLISHED_WITHIN_EXERCISED_SCOPE`. The result remains method-development only and claim-bearing use is prohibited. See `OAT_NIM_RUN_002_ADJUDICATION.md` and `OAT_RUN_B_CLOSURE_001.md`.

**Frozen Sequence 003 (bound, not executed).** Run B was a clean adversarial
run, but nothing in it showed that the instrument would have noticed a
counterexample if one had been present. That is the gap Sequence 003 closes,
and the missing evidence is not another clean run: it is an ordered
experiment in which detector sensitivity is demonstrated *first*, on state
that is then destroyed before the adversary starts.

`docs/experiment-runs/OAT_SEQUENCE_003_PROTOCOL.md` defines the six stages;
`OAT_NIM_RUN_MANIFEST_003.json` binds them; `OAT_OWNER_EXECUTION_AUTHORIZATION_003.json`
records one bounded sequence authorization; and
`tools/oat_consequence_sequence_runner_003.py` implements them behind hard
gates. The controlling invariant is
`POSITIVE_CONTROL_KNOWLEDGE intersect ADVERSARY_CONTEXT == empty`: running the
positive control first is what makes the sequence informative, and also what
creates the contamination hazard the leak audits exist to refuse.

S0, S1, S1A and S2 make no provider call and cannot consume the
authorization. Only the first provider request in S3 consumes it, and
`run_s3()` refuses to build that request unless every preceding gate passed.
Sequence completeness and subject outcome stay separate variables: a genuine
Run C counterexample would be a *complete* sequence, not a failed one.

At this commit nothing has been executed. `RUN_C_EXECUTION_STATUS =
BOUND_NOT_EXECUTED`, `FULL_FROZEN_SEQUENCE_CLOSURE = NOT_ESTABLISHED`,
`READY_FOR_NIM_EXPERIMENT = FALSE`, and no provider request has been made.

**Sequence 003 is closed as a harness failure, and its closure output was
wrong.** Run C consumed Authorization 003 on its first provider request, got
HTTP 401, and reached the target zero times. Runner 003 nevertheless reported
`FULL_FROZEN_SEQUENCE_CLOSURE = ESTABLISHED`. Two defects produced that, each
sufficient alone: execution was inferred from `provider_call_performed`, and
replay compared the raw subject verdict (`NO_BOUNDARY_COUNTEREXAMPLE` on an
empty ledger, matching itself) instead of the final fail-closed adjudication
(`HARNESS_OR_INSTRUMENT_FAILURE`). See
`docs/experiment-runs/OAT_SEQUENCE_003_ADJUDICATION_ERRATUM_001.md`.

The pre-adversary half of Sequence 003 is unaffected and stands:
`PC_SENSITIVITY = ESTABLISHED`, `STATE_SEPARATION = ESTABLISHED`,
`ADVERSARY_CONTEXT_ISOLATION = PASS`. The subject was never reached, so
nothing about the subject was established.

`tools/oat_consequence_sequence_runner_003.py` is preserved unmodified as the
historical executable that produced the Run C evidence; its SHA-256 is pinned
in the Sequence 004 manifest so a test fails if it moves.

**Sequence 004 (bound, not executed).**
`tools/oat_consequence_sequence_runner_004.py` carries the corrected logic:
execution is derived from `instrument_status == EXECUTED` **and**
`target_http_attempts > 0`, never from provider contact; replay runs in two
layers and must reproduce the FINAL adjudication on `disposition`,
`subject_result` and `instrument_status`; and runtime evidence now preserves
`terminal_provider_failure` so that recomputation is deterministic.

`tools/oat_nvidia_provider_preflight.py` is a non-experiment credential and
transport check that must PASS before Run D may enter S3. It never touches the
frozen target, never reads adjudicator ground truth, and never consumes the
experiment authorization. Run C spent an owner authorization to discover a bad
credential; that is now discoverable for free.

At this commit nothing has been executed against the provider under
Authorization 004, and no Run D provider request has been made.

**Shared machinery.** Canonicalization (`oat/canonical.py`), digests
(`oat/digest.py`), manifest binding, the claim quarantine, licensing
enforcement, and the CLI.

**CLI.** `run`, `verify`, `replay`, `inspect`, `demo`, `dryrun` (RB-001) plus
`consequence run|verify|replay` and `paths inspect`.

**Remote.** The GitHub remote exists at
`veraxis-protocol/Open-Authority-Trials-OAT-`, `main` is public, and GitHub
Actions runs on push across Python 3.10, 3.11 and 3.12. The pre-refactor
generation is preserved at tag `oat-method-development-v0.1`.

**Provider seam.** `oat/adversaries/provider.py` is a real adapter, not a
stub that only raises. It derives `provider_run_occurred` from the transport
so an offline run cannot be relabelled as a live one. `UnconfiguredTransport`
refuses loudly; `ScriptedTransport` replays fixed responses offline.

## What does not exist

- Any claim-bearing frontier-model consequence-boundary result. Run B completed as a method-development execution and established a scoped negative result only for exercised routes; it does not establish all-route, production, customer, or enterprise assurance.
- Any real customer target integration. The host/sink integration is a
  local, production-representative execution surface, not a deployment: the
  sink, authorization artifact, authority store and routes remain
  representative deterministic primitives. It is not customer validation and
  not real enterprise assurance.
- Any all-route assurance claim about any real system.
- Any claim-bearing result, standing, or certification of anything.
- Any claim-bearing Experiment 001 result. Run A was an unsuccessful
  method-development execution attempt; Run B remains claim-bearing prohibited.

## Honest limits of a clean run

A `NO_BOUNDARY_COUNTEREXAMPLE` verdict is scoped to the routes actually
exercised, and every run reports its `unexercised_declared_paths`. Absence of
a counterexample on declared routes is not evidence that all reachable routes
are controlled — see `docs/REACHABILITY-AND-UNKNOWN-PATHS.md`.
