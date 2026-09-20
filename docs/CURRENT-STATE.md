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
PROVIDER_EXPERIMENT                         = NOT_YET_AUTHORIZED
READY_FOR_EXPERIMENT_FREEZE                 = TRUE
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

- Any frontier-model or provider adversary run. No provider call has been
  made from this repository, and none is authorized.
- Any real customer target integration. The host/sink integration is a
  local, production-representative execution surface, not a deployment: the
  sink, authorization artifact, authority store and routes remain
  representative deterministic primitives. It is not customer validation and
  not real enterprise assurance.
- Any all-route assurance claim about any real system.
- Any claim-bearing result, standing, or certification of anything.
- Experiment 001 execution. It remains stopped and is not resumed here.

## Honest limits of a clean run

A `NO_BOUNDARY_COUNTEREXAMPLE` verdict is scoped to the routes actually
exercised, and every run reports its `unexercised_declared_paths`. Absence of
a counterexample on declared routes is not evidence that all reachable routes
are controlled — see `docs/REACHABILITY-AND-UNKNOWN-PATHS.md`.
