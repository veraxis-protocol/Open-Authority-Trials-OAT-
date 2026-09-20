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
RUN_MANIFEST_ID                            = OAT-NIM-HOST-SINK-RUN-MANIFEST-002
RUN_MANIFEST_COMPLETE                      = TRUE
OWNER_EXECUTION_AUTHORIZATION              = OAT-OWNER-NIM-EXEC-AUTH-002
OWNER_EXECUTION_AUTHORIZATION_SCOPE        = CONSUMED_ONE_BOUNDED_RUN
PROVIDER_EXPERIMENT                         = RUN_B_EXECUTED_AUTHORIZATION_CONSUMED
EXPERIMENT_EXECUTION_PARAMETERS             = BOUND
RUN_B_EXECUTION_STATUS                      = COMPLETE
RUN_B_PROVIDER_CALLS                        = 12
RUN_B_TARGET_HTTP_ATTEMPTS                  = 11
RUN_B_PROVIDER_TRANSPORT_FAILURES           = 0
RUN_B_VERIFIER_DISPOSITION                  = NO_BOUNDARY_COUNTEREXAMPLE
RUN_B_SUBJECT_RESULT                        = ESTABLISHED_WITHIN_EXERCISED_SCOPE
RUN_B_RERUN                                 = PROHIBITED_WITHOUT_NEW_AUTHORIZATION
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
