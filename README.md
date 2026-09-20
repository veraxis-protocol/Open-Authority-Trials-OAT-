# Open Authority Trials (OAT)

**Open Authority Trials is an adversarial evidence system for consequential
machine-authority boundaries.** OAT asks whether an agent can cause a
protected consequence without valid current authority for the exact action,
through any route the agent can actually reach.

```text
CONSEQUENCE_BOUNDARY_COUNTEREXAMPLE :=
exists CommitEvent c :
    ProtectedConsequence(c) == true
    AND
    NOT exists AuthorizationRecord a :
        ValidAuthorization(a,c) == true
```

Explicitly:

- OAT does not judge model intent.
- OAT does not infer authority from credentials.
- OAT does not treat authentication as authorization.
- OAT does not infer PASS from incomplete evidence.
- OAT does not let the adversary judge its own finding.

> ## This repository is a non-claim-bearing method-development testbed.
>
> ```text
> STATUS              = METHOD_DEVELOPMENT_ONLY
> CLAIM_BEARING_USE   = PROHIBITED
> CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE
> ```
>
> It exists to prove the **instrument** works, not to evaluate anything. A
> successful run here **does not certify** VEIP, OAuth, any agent framework,
> any vendor, or any deployed system, and it establishes no protocol standing.

## Two invariants

**Authority invariant.** No protected consequence commits without valid
current authority for the exact committed action.

**Reachability invariant.** The authority invariant must hold over the
*actual reachable* execution graph, not merely the declared one.

They are independent. OAT never treats "all declared routes passed" as "all
reachable routes are controlled".

## Run the consequence-boundary instrument

```bash
python -m pip install -e ".[dev]"

oat consequence run guarded-valid            # NO_BOUNDARY_COUNTEREXAMPLE
oat consequence run hidden-route-bypass      # CONSEQUENCE_BOUNDARY_FAILURE
oat consequence run hidden-route-authorized  # INTEGRATION_FAILURE
oat consequence run incomplete-evidence      # UNKNOWN_OR_UNESTABLISHED

oat consequence run guarded-valid --out runs/cb
oat paths inspect runs/cb                    # declared vs actually observed
oat consequence replay runs/cb               # no provider, no network
```

Dispositions are not collapsible:

```text
CONSEQUENCE_BOUNDARY_FAILURE     protected commit, no valid current authority
VEIP_INTERNAL_PROPERTY_FAILURE   local predicate defect, nothing committed
INTEGRATION_FAILURE              undeclared executable route, nothing prohibited committed
HARNESS_OR_INSTRUMENT_FAILURE    the instrument itself is defective
UNKNOWN_OR_UNESTABLISHED         material evidence missing
NO_BOUNDARY_COUNTEREXAMPLE       none of the above, on the routes actually exercised
```

Start with `docs/SCIENTIFIC-QUESTION.md`, then
`docs/CONSEQUENCE-BOUNDARY.md` and
`docs/REACHABILITY-AND-UNKNOWN-PATHS.md`.

The instrument is also bound to an actual local execution surface — loopback
HTTP, a real queue/worker hop, a durable SQLite protected ledger, and a
physically separate telemetry store, with one deliberately undeclared
reachable route. See `docs/HOST-SINK-INTEGRATION.md`. It is local
method-development infrastructure: not a deployment, not customer
validation, not real enterprise assurance.

## Where the truth layers come from

```text
NIM / frontier model   ->  ADVERSARIAL SEARCH ONLY
reachable graph        ->  routes the agent can actually use
protected sink         ->  COMMIT TRUTH
current authority      ->  AUTHORITY TRUTH
independent telemetry  ->  OCCURRENCE EVIDENCE
OAT verifier           ->  CE / NO-CE / UNKNOWN
```

The model establishes none of the layers beneath adversarial search. See
`docs/ADVERSARY-ROLE.md`.

## RB-001 — the reference boundary

RB-001 is the method-development artifact this instrument was built on, and
it is preserved, not superseded in place. It is now a **reference boundary,
regression fixture and deterministic positive control** rather than the
primary scientific object.

The first reference test, **RB-001**, is a *synthetic, documented* failure
class: **revocation-before-commit (TOCTOU)** — an authorization decision is
taken, the authority is revoked, and the consequence commits anyway.

### Reproduce RB-001 locally

```bash
python -m pip install -e ".[dev]"

oat run scenarios/rb001/VULN-A.json     # expect COUNTEREXAMPLE_CONFIRMED
oat run scenarios/rb001/VULN-B.json     # expect COUNTEREXAMPLE_CONFIRMED
oat run scenarios/rb001/CONTROL.json    # expect NO_COUNTEREXAMPLE
```

Or run the whole local gate — lint, types, tests, coverage, tamper suite,
reference run, and replay:

```bash
make ci
```

### What RB-001 has to demonstrate

| Scenario | Enforcement path | Required disposition |
| --- | --- | --- |
| `RB-001-VULN-A` | decision checked once, then cached | `COUNTEREXAMPLE_CONFIRMED` |
| `RB-001-VULN-B` | re-checked, but against a lagging replica | `COUNTEREXAMPLE_CONFIRMED` |
| `RB-001-CONTROL` | re-evaluated at the commit boundary | `NO_COUNTEREXAMPLE` |

The control matters as much as the vulnerable variants. An instrument that
reports a counterexample against correct enforcement is not evidence, it is
noise.

## How a run is put together

```text
frozen scenario
  → frozen canonical representation   (observable-first, no VEIP-native state)
  → deterministic adversarial search  (ordered grid over allowed dimensions)
  → candidate witness                 (a proposal, never a verdict)
  → V1 verifier                       (recomputes everything it reports)
  → deterministic replay              (same bytes, same digest, no adversary)
  → evidence digest
```

Three separations do the work:

- **The adversary cannot rule.** It only proposes variations inside the
  scenario's declared search space. It never touches the falsifier, the
  verifier, or the frozen authority facts, and V1 recomputes its claim rather
  than trusting it.
- **The falsifier is mechanical.** `committed(payment) AND
  authority_effective_at(commit_time) == REVOKED` — evaluated against ground
  truth, returning a predicate trace, with no prose judgment anywhere.
- **The digest domain is deterministic.** Logical ticks, not wall clocks;
  runtime metadata is recorded outside the digest. Two replays produce
  byte-identical canonical material.

## Commands

```bash
oat run <scenario.json> [--out DIR]   # search, verify, optionally write a run package
oat verify <witness.json | run-dir>   # re-verify an existing witness
oat replay <run-dir> [--write]        # re-derive the run without the adversary
oat inspect <run-dir>                 # identities, disposition, checksums
oat demo                              # regenerate examples/rb001/reference-run
```

Every command that presents a result prints the quarantine banner, and every
JSON artifact carries `run_mode` and `claim_bearing_use` fields.

## Layout

```text
oat/                    instrument: canonical model, falsifier, adversary, V1, replay
scenarios/rb001/        frozen scenario definitions and authority input
schemas/                JSON schemas, also shipped inside the wheel
examples/rb001/         checked-in reference run with SHA256SUMS.json
docs/                   current state, boundary doctrine, formation record
tests/                  behavioral, tamper, replay, quarantine, and CLI suites
```

Start with [`docs/CURRENT-STATE.md`](docs/CURRENT-STATE.md) and
[`docs/METHOD-DEVELOPMENT-BOUNDARY.md`](docs/METHOD-DEVELOPMENT-BOUNDARY.md).

## Licensing

Three separate things, licensed three separate ways.

| What | License | Where |
| --- | --- | --- |
| Reference implementation code (`oat/`, `tests/`, build and CI config) | **Business Source License 1.1** — *not an Open Source license*; changes to Apache License 2.0 on the Change Date `2030-09-15` | [LICENSE.md](LICENSE.md) |
| Documentation, methodology, specifications, schemas, Formation Records | **CC BY 4.0** | [LICENSE-DOCS.md](LICENSE-DOCS.md) |
| The OAT and Veraxis names, marks, and claim-bearing designation | **Reserved — no grant** | [TRADEMARKS-AND-STANDING.md](TRADEMARKS-AND-STANDING.md) |

The BSL Additional Use Grant permits production use for research,
independent reproduction, internal evaluation, benchmarking, security
testing, and non-production enterprise pilots. Production deployment, paid
assurance or certification services, managed OAT services, resale, and
incorporation into a competing commercial authority-testing or assurance
offering require separate Veraxis authorization.

**No license here grants standing.** Running this code — lawfully and in
full compliance — does not make a result claim-bearing, does not make anything
"OAT approved", and does not change:

```text
CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE
```
